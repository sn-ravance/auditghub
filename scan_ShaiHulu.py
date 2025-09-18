#!/usr/bin/env python3
"""
Specialized detector for the "Shai-Hulud" campaign with GraphQL API integration.

This scanner inspects GitHub repositories for:
- package-lock.json references containing packages from a provided IoC list (shaihulupkg.txt)
- suspicious security/audit logs committed to repos
- data.json files containing double-encoded base64 payloads
- suspicious workflow or script indicators (processor.sh, migrate-repos.sh, webhook.site)
- malicious JS file hash matches

It uses the new GitHub client with both GraphQL and REST API support, including
built-in rate limiting, retries, and caching.
"""

import argparse
import base64
import concurrent.futures
import datetime
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple, Union, cast, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from dotenv import load_dotenv

# Add src to path for local imports
sys.path.append(str(Path(__file__).parent.absolute()))

# Import from our GitHub client
from src.github import GitHubClient, GraphQLClient
from src.github.models import Repository, RepositoryPrivacy, User, Organization
from src.github.utils import (
    make_rate_limited_session,
    parse_github_url,
    format_duration,
    normalize_repo_name
)

# Load environment variables from .env file
load_dotenv(override=True)

# Constants
IOC_MALICIOUS_JS_SHA256 = "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"
IOC_WEBHOOK_DOMAIN = "webhook.site"
IOC_SCRIPT_PATHS = ["/tmp/processor.sh", "/tmp/migrate-repos.sh"]

# Configure logging
def setup_logging(verbosity: int = 1) -> None:
    """Configure logging with the specified verbosity level.
    
    Args:
        verbosity: 0=WARNING, 1=INFO, 2=DEBUG
    """
    log_level = logging.INFO
    if verbosity >= 2:
        log_level = logging.DEBUG
    elif verbosity == 0:
        log_level = logging.WARNING
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(Path('logs/shaihulu_scan.log').resolve())
        ]
    )
    
    # Set log level for external libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('github').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)

# Initialize logger
logger = logging.getLogger(__name__)

@dataclass
class ShaiHuluConfig:
    """Configuration for the Shai-Hulud scanner.
    
    This class manages all configuration settings for the scanner, including:
    - GitHub API credentials and client
    - File system paths for reports and clones
    - Scanning behavior and thresholds
    """
    
    # Required configuration
    GITHUB_TOKEN: str = field(init=False)
    ORG_NAME: str = field(init=False)
    
    # GitHub client configuration
    github: GitHubClient = field(init=False)
    graphql_client: GraphQLClient = field(init=False)
    
    # File system paths
    REPORT_DIR: Path = field(init=False)
    CLONE_DIR: Path = field(init=False)
    CACHE_DIR: Path = field(init=False)
    
    # Scanning configuration
    MAX_REPOS: int = 1000  # Maximum number of repos to process
    MAX_THREADS: int = 5    # Maximum concurrent operations
    REQUEST_TIMEOUT: int = 30  # Seconds to wait for API responses
    
    # Rate limiting
    REQUESTS_PER_HOUR: int = 5000  # GitHub API limit for authenticated requests
    
    def __post_init__(self):
        """Initialize configuration from environment variables."""
        # Load required configuration
        self.GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
        self.ORG_NAME = os.getenv("GITHUB_ORG", "")
        
        if not self.GITHUB_TOKEN:
            raise ValueError("GITHUB_TOKEN environment variable is required")
        if not self.ORG_NAME:
            raise ValueError("GITHUB_ORG environment variable is required")
        
        # Initialize GitHub clients
        self.github = GitHubClient(
            token=self.GITHUB_TOKEN,
            cache_ttl=3600,  # 1 hour cache
            user_agent="auditgh-shaihulu",
            timeout=self.REQUEST_TIMEOUT
        )
        
        # Initialize GraphQL client
        self.graphql_client = GraphQLClient(
            token=self.GITHUB_TOKEN,
            cache_ttl=3600
        )
        
        # Set up file system paths
        self.REPORT_DIR = Path(os.getenv("REPORT_DIR", "shaihulud_reports")).resolve()
        self.CLONE_DIR = Path(os.getenv("CLONE_DIR", "repos")).resolve()
        self.CACHE_DIR = Path(".cache").resolve()
        
        # Create necessary directories
        for directory in [self.REPORT_DIR, self.CLONE_DIR, self.CACHE_DIR]:
            directory.mkdir(parents=True, exist_ok=True)
    
    @property
    def headers(self) -> Dict[str, str]:
        """Get default HTTP headers for GitHub API requests."""
        return {
            "Authorization": f"token {self.GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json,application/vnd.github.audit-log-preview+json",
            "User-Agent": "auditgh-shaihulu"
        }

# Global config
config: Optional[ShaiHuluConfig] = None


def get_all_repos(include_forks: bool = False, include_archived: bool = False) -> List[Dict[str, Any]]:
    """Fetch all repositories from the organization with filtering."""
    if not config:
        return []
        
    try:
        # Use the new GitHub client to get all repositories
        repos = config.github.list_all_organization_repositories(
            config.ORG_NAME,
            include_forks=include_forks,
            include_archived=include_archived
        )
        return [repo.to_dict() for repo in repos]
    except Exception as e:
        logger.error(f"Error fetching repositories: {e}")
        return []


def get_single_repo(owner: str, repo_name: str) -> Optional[Dict[str, Any]]:
    """Get a single repository by owner and name."""
    if not config:
        return None
        
    try:
        repo = config.github.get_repository(owner, repo_name)
        return repo.to_dict() if repo else None
    except Exception as e:
        logger.error(f"Error fetching repository {owner}/{repo_name}: {e}")
        return None


def org_audit_log_search(phrase: str, action: Optional[str] = None, limit: int = 200) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Attempt to query the org audit log. 
    
    Note: This still uses the REST API as audit logs aren't available in GraphQL.
    """
    if not config:
        return False, []
        
    url = f"{config.github.base_url}/orgs/{config.ORG_NAME}/audit-log"
    params = {"phrase": phrase, "per_page": min(100, limit), "page": 1}
    if action:
        params["phrase"] = f"{params['phrase']} action:{action}"
    
    try:
        # Use the session from the GitHub client
        session = config.github._session
        resp = session.get(url, params=params, timeout=30)
        resp.raise_for_status()
        return True, resp.json()
    except Exception as e:
        if hasattr(e, 'response') and hasattr(e.response, 'status_code'):
            if e.response.status_code == 403:
                logger.warning("Insufficient permissions to access org audit log (requires admin:org scope)")
            else:
                logger.error(f"Error accessing audit log: {e}")
        else:
            logger.error(f"Unexpected error accessing audit log: {e}")
        return False, []


def search_repositories(query: str, max_items: int = 200) -> List[Dict[str, Any]]:
    """Search for repositories using the GitHub API."""
    if not config:
        return []
        
    try:
        # First try GraphQL API
        result = config.github.repositories.search_repositories(
            query=query,
            first=min(100, max_items)  # Limit page size to 100
        )
        
        nodes = result.get('nodes', [])
        return [node for node in nodes if isinstance(node, dict)]
        
    except Exception as e:
        logger.warning(f"GraphQL search failed, falling back to REST API: {e}")
        try:
            # Fall back to REST API
            result = config.github.search_repositories(
                query=query,
                per_page=min(100, max_items)
            )
            return result.get('items', [])
        except Exception as e2:
            logger.error(f"REST search also failed: {e2}")
            return []


def search_code(query: str, max_items: int = 100) -> List[Dict[str, Any]]:
    """Search code with the GitHub API."""
    if not config:
        return []
        
    try:
        result = config.github.search_code(
            query=query,
            per_page=min(100, max_items)
        )
        return result.get('items', [])
    except Exception as e:
        logger.error(f"Error searching code: {e}")
        return []


def list_org_members(max_items: int = 500) -> List[Dict[str, Any]]:
    """List organization members."""
    if not config:
        return []
        
    try:
        # Use the REST API for members as it's not in GraphQL
        url = f"{config.github.base_url}/orgs/{config.ORG_NAME}/members"
        params = {"per_page": min(100, max_items)}
        
        # Use the session from the GitHub client
        session = config.github._session
        resp = session.get(url, params=params, timeout=30)
        
        # Handle 404 if user doesn't have permission
        if resp.status_code == 404:
            logger.warning("Organization not found or insufficient permissions to list members")
            return []
            
        resp.raise_for_status()
        return resp.json()
        
    except Exception as e:
        logger.error(f"Error listing organization members: {e}")
        return []


# -----------------
# Local repo scanning
# -----------------

def clone_repo(repo: Dict[str, Any]) -> Optional[str]:
    """Clone a repository locally for scanning.
    
    Args:
        repo: Repository dictionary containing at least 'name' and 'clone_url'
        
    Returns:
        Path to the cloned repository or None if cloning failed
    """
    if not config or not config.CLONE_DIR:
        config.CLONE_DIR = tempfile.mkdtemp(prefix="repo_scan_")
        
    repo_name = repo.get('name', 'unknown')
    clone_dir = os.path.join(config.CLONE_DIR, repo_name)
    
    try:
        # If directory exists, update the repo
        if os.path.exists(clone_dir):
            try:
                # Check if it's a git repo and update if needed
                if os.path.exists(os.path.join(clone_dir, '.git')):
                    subprocess.run(
                        ['git', 'remote', 'update'],
                        cwd=clone_dir,
                        check=True,
                        capture_output=True,
                        text=True
                    )
                    return clone_dir
                # Not a git repo, remove and reclone
                shutil.rmtree(clone_dir)
            except Exception as e:
                logger.warning("Error updating repo %s: %s", repo_name, str(e))
                shutil.rmtree(clone_dir, ignore_errors=True)
        
        # Create parent directory if it doesn't exist
        os.makedirs(os.path.dirname(clone_dir), exist_ok=True)
        
        # Clone the repository using the GitHub client's authenticated URL
        clone_url = repo.get('clone_url', '')
        if not clone_url:
            logger.error("No clone URL provided for repository")
            return None
            
        # Use the authenticated URL from the GitHub client if available
        if hasattr(config, 'github') and hasattr(config.github, 'get_authenticated_url'):
            clone_url = config.github.get_authenticated_url(clone_url)
        
        # Clone with a shallow clone to save time and space
        result = subprocess.run(
            ['git', 'clone', '--depth', '1', clone_url, clone_dir],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            logger.error(
                "Failed to clone %s: %s",
                repo_name,
                result.stderr.strip() if result.stderr else 'Unknown error'
            )
            return None
            
        return clone_dir
        
    except Exception as e:
        logger.exception("Unexpected error cloning repository %s", repo_name)
        return None


def load_ioc_packages(packages_file: str) -> Set[str]:
    pkgs: Set[str] = set()
    try:
        with open(packages_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Example: "teselagen-interval-tree (1.1.2)"
                name = line.split('(')[0].strip()
                if name:
                    pkgs.add(name.lower())
    except Exception as e:
        logging.warning(f"Could not read packages file '{packages_file}': {e}")
    return pkgs


def collect_npm_packages_from_lock(lock_path: Path) -> Set[str]:
    names: Set[str] = set()
    try:
        with open(lock_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        def walk_deps(obj: Any):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k == 'dependencies' and isinstance(v, dict):
                        for dep_name in v.keys():
                            names.add(dep_name.lower())
                        walk_deps(v)
                    else:
                        walk_deps(v)
            elif isinstance(obj, list):
                for it in obj:
                    walk_deps(it)
        walk_deps(data)
    except Exception as e:
        logging.debug(f"Failed to parse {lock_path}: {e}")
    return names


def detect_double_base64(s: str) -> Tuple[bool, Optional[str]]:
    try:
        b1 = base64.b64decode(s, validate=True)
        b2 = base64.b64decode(b1, validate=True)
        try:
            decoded = b2.decode('utf-8', errors='ignore')
        except Exception:
            decoded = b2.decode('latin1', errors='ignore')
        return True, decoded
    except Exception:
        return False, None


SUSPICIOUS_STRINGS = [
    'AKIA', 'ASIA', '-----BEGIN', 'SECRET_KEY', 'PRIVATE KEY', 'xoxb-',
    'password=', 'token=', IOC_WEBHOOK_DOMAIN, 'child_process.exec', 'bash -c', 'curl ', 'wget '
]


def scan_repo_local(repo_path: str, repo: Dict[str, Any], ioc_packages: Set[str]) -> Dict[str, Any]:
    """Scan a local repository for indicators of compromise.
    
    Args:
        repo_path: Path to the local repository
        repo: Repository metadata dictionary
        ioc_packages: Set of package names to check for in package-lock.json
        
    Returns:
        Dictionary containing findings in different categories
    """
    if not config:
        return {}
        
    repo_name = repo.get('full_name') or repo.get('name', 'unknown')
    logger.info("Scanning repository: %s", repo_name)
    
    findings: Dict[str, Any] = {
        'repo': repo_name,
        'package_lock_matches': [],
        'security_logs': [],
        'data_json_findings': [],
        'suspicious_strings': [],
        'workflow_findings': [],
        'ioc_scripts_refs': [],
        'malicious_js_hash_matches': [],
    }
    
    try:
        # Skip if the repo path doesn't exist
        if not os.path.exists(repo_path):
            logger.warning("Repository path does not exist: %s", repo_path)
            return findings
            
        # 1. Scan package-lock.json files for IoC packages
        for lock_path in Path(repo_path).rglob('package-lock.json'):
            try:
                pkgs = collect_npm_packages_from_lock(lock_path)
                matches = sorted(list(pkgs.intersection(ioc_packages)))
                if matches:
                    finding = {
                        'path': str(lock_path.relative_to(repo_path)),
                        'matches': matches
                    }
                    findings['package_lock_matches'].append(finding)
                    logger.debug("Found IoC packages in %s: %s", finding['path'], matches)
            except Exception as e:
                logger.warning("Error processing %s: %s", lock_path, str(e))

        # 2. Search for security/audit log files
        try:
            for p in Path(repo_path).rglob('*'):
                if p.is_file():
                    name = p.name.lower()
                    if ('security' in name or 'audit' in name) and name.endswith('.log'):
                        log_path = str(p.relative_to(repo_path))
                        findings['security_logs'].append(log_path)
                        logger.debug("Found security log: %s", log_path)
        except Exception as e:
            logger.warning("Error searching for security logs: %s", str(e))

        # 3. Check data.json files for double base64 encoded content
        for dp in Path(repo_path).rglob('data.json'):
            try:
                with open(dp, 'r', encoding='utf-8', errors='ignore') as f:
                    txt = f.read()
                
                decoded = None
                try:
                    j = json.loads(txt)
                    # Common keys that could hold payloads
                    candidates = []
                    if isinstance(j, dict):
                        for k in ['data', 'payload', 'content', 'blob']:
                            v = j.get(k)
                            if isinstance(v, str):
                                candidates.append(v)
                    if not candidates and isinstance(j, str):
                        candidates = [j]
                        
                    for c in candidates:
                        ok, out = detect_double_base64(c)
                        if ok:
                            decoded = out
                            break
                except json.JSONDecodeError:
                    ok, out = detect_double_base64(txt)
                    if ok:
                        decoded = out
                
                if decoded:
                    # Heuristic to detect potential secrets
                    suspicious = any(x in decoded.upper() for x in 
                                   ['AKIA', 'BEGIN', 'SECRET', 'PASSWORD', 'TOKEN', 'KEY', 'CREDENTIAL'])
                    
                    finding = {
                        'path': str(dp.relative_to(repo_path)),
                        'decoded_preview': decoded[:200],
                        'suspicious': suspicious
                    }
                    findings['data_json_findings'].append(finding)
                    
                    log_level = logging.WARNING if suspicious else logging.INFO
                    logger.log(log_level, "Found base64 encoded data in %s (suspicious: %s)", 
                             finding['path'], suspicious)
                    
            except Exception as e:
                logger.debug("Error processing data.json %s: %s", dp, str(e))

        # 4. Scan for suspicious strings and IoC script references
        try:
            for p in Path(repo_path).rglob('*'):
                if not p.is_file():
                    continue
                    
                rel_path = str(p.relative_to(repo_path))
                
                # Skip large files and binary files
                try:
                    if p.stat().st_size > 2 * 1024 * 1024:  # 2MB
                        continue
                        
                    # Skip binary files
                    if p.suffix in ['.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip', '.tar.gz', '.jar', '.war', '.class']:
                        continue
                        
                    # Read file content
                    try:
                        text = p.read_text(encoding='utf-8', errors='ignore')
                    except (UnicodeDecodeError, PermissionError):
                        continue
                        
                    # Check for suspicious strings
                    for s in SUSPICIOUS_STRINGS:
                        if s in text:
                            finding = {'path': rel_path, 'indicator': s}
                            findings['suspicious_strings'].append(finding)
                            logger.debug("Found suspicious string in %s: %s", rel_path, s)
                    
                    # Check for IoC script references
                    for sp in IOC_SCRIPT_PATHS:
                        if sp in text:
                            finding = {'path': rel_path, 'script': sp}
                            findings['ioc_scripts_refs'].append(finding)
                            logger.warning("Found reference to IoC script in %s: %s", rel_path, sp)
                            
                except Exception as e:
                    logger.debug("Error scanning file %s: %s", rel_path, str(e))
                    
        except Exception as e:
            logger.error("Error during file scanning: %s", str(e))

        # 5. Check for malicious JS files by hash
        for js in Path(repo_path).rglob('*.js'):
            try:
                if js.stat().st_size > 1 * 1024 * 1024:  # 1MB
                    continue
                    
                file_hash = hashlib.sha256(js.read_bytes()).hexdigest()
                if file_hash == IOC_MALICIOUS_JS_SHA256:
                    js_path = str(js.relative_to(repo_path))
                    findings['malicious_js_hash_matches'].append(js_path)
                    logger.warning("Found malicious JS file by hash: %s", js_path)
                    
            except Exception as e:
                logger.debug("Error checking JS file %s: %s", js, str(e))

        # 6. Scan workflow files for IoCs
        for wf_ext in ['*.yml', '*.yaml']:
            for wf in Path(repo_path).rglob(f'.github/workflows/{wf_ext}'):
                try:
                    text = wf.read_text(encoding='utf-8', errors='ignore')
                    wf_path = str(wf.relative_to(repo_path))
                    
                    # Check for webhook.site domains
                    if IOC_WEBHOOK_DOMAIN in text:
                        finding = {'path': wf_path, 'indicator': IOC_WEBHOOK_DOMAIN}
                        findings['workflow_findings'].append(finding)
                        logger.warning("Found webhook.site reference in workflow: %s", wf_path)
                    
                    # Check for other suspicious patterns
                    for s in SUSPICIOUS_STRINGS:
                        if s in text and s != IOC_WEBHOOK_DOMAIN:  # Already checked
                            finding = {'path': wf_path, 'indicator': s}
                            findings['workflow_findings'].append(finding)
                            logger.debug("Found suspicious string in workflow %s: %s", wf_path, s)
                            
                except Exception as e:
                    logger.debug("Error reading workflow file %s: %s", wf, str(e))
                    
    except Exception as e:
        logger.exception("Unexpected error during repository scan: %s", str(e))
    
    logger.info("Completed scanning repository: %s", repo_name)
    return findings


# High-level queries
# -----------------

def run_high_level_queries() -> Dict[str, Any]:
    """Run high-level queries using the GitHub API with caching.
    
    This function performs several searches to identify potential Shai-Hulud campaign indicators:
    1. Public repositories named 'Shai-Hulud' in the organization
    2. Public repositories with 'Shai-Hulud Migration' in description and 'mitigation' in name
    3. Private migration repositories
    4. Developer accounts with repositories named 'Shai-Hulud'
    5. Audit log entries related to Shai-Hulud
    
    Returns:
        Dictionary containing query results organized by category
    """
    if not config:
        logger.error("Configuration not initialized")
        return {}
        
    results: Dict[str, Any] = {
        'first_wave': [],
        'second_wave': [],
        'audit_repo_create': [],
        'private_migration_repos': [],
        'dev_accounts_shai_hulud': []
    }

    try:
        logger.info("Starting high-level queries for organization: %s", config.ORG_NAME)
        
        # First wave: public repos named Shai-Hulud within org
        try:
            q1 = f"org:{config.ORG_NAME} in:name \"Shai-Hulud\" is:public"
            logger.debug("Running first wave query: %s", q1)
            results['first_wave'] = search_repositories(q1)
            logger.info("First wave query found %d results", len(results['first_wave']))
        except Exception as e:
            logger.error("Error in first wave query: %s", str(e))
            results['first_wave_error'] = str(e)
        
        # Second wave: public repos with description "Shai-Hulud Migration" and name containing 'mitigation'
        try:
            q2 = f"org:{config.ORG_NAME} in:description \"Shai-Hulud Migration\" in:name mitigation is:public"
            logger.debug("Running second wave query: %s", q2)
            results['second_wave'] = search_repositories(q2)
            logger.info("Second wave query found %d results", len(results['second_wave']))
        except Exception as e:
            logger.error("Error in second wave query: %s", str(e))
            results['second_wave_error'] = str(e)
        
        # Get all organization repositories using the GitHub client
        try:
            logger.info("Fetching all organization repositories")
            all_repos = config.github.list_all_organization_repositories(
                org=config.ORG_NAME,
                include_forks=True,
                include_archived=True
            )
            logger.info("Found %d total repositories in organization", len(all_repos))
            
            # Process private migration repos
            private_migration_count = 0
            for repo in all_repos:
                try:
                    repo_dict = repo.to_dict()
                    name = (repo_dict.get('name') or '').lower()
                    desc = (repo_dict.get('description') or '')
                    
                    # Look for private migration repos with Shai-Hulud indicators
                    is_private = repo_dict.get('private', False)
                    is_migration = name.endswith('-migration')
                    has_shaihulud_desc = 'Shai-Hulud Migration' in desc
                    
                    if is_private and is_migration and has_shaihulud_desc:
                        results['private_migration_repos'].append(repo_dict)
                        private_migration_count += 1
                        
                except Exception as e:
                    logger.debug("Error processing repo %s: %s", 
                               getattr(repo, 'full_name', 'unknown'), 
                               str(e))
                    continue
                    
            logger.info("Found %d private migration repositories", private_migration_count)
            
        except Exception as e:
            logger.error("Error fetching organization repositories: %s", str(e))
            results['repo_fetch_error'] = str(e)
        
        # Get organization members (limited to avoid rate limits)
        try:
            logger.info("Fetching organization members")
            members = list_org_members(max_items=10)
            logger.info("Found %d organization members", len(members))
            
            # Search for Shai-Hulud in developer accounts (with rate limiting)
            dev_account_results = []
            for i, member in enumerate(members, 1):
                try:
                    login = member.get('login')
                    if not login:
                        continue
                        
                    logger.debug("Searching user %d/%d: %s", i, len(members), login)
                    
                    # Search for repositories with name containing 'Shai-Hulud'
                    qd = f"user:{login} in:name \"Shai-Hulud\""
                    hits = search_repositories(qd, max_items=5)  # Limit to 5 per user
                    
                    if hits:
                        dev_account_results.extend(hits)
                        logger.info("Found %d Shai-Hulud repos for user %s", 
                                  len(hits), login)
                    
                    # Add a small delay between user searches to avoid rate limits
                    if i < len(members):  # No need to delay after the last one
                        time.sleep(1)
                        
                except Exception as e:
                    logger.error("Error searching user %s: %s", login, str(e))
                    continue
            
            results['dev_accounts_shai_hulud'] = dev_account_results
            logger.info("Found %d total Shai-Hulud repositories in developer accounts", 
                      len(dev_account_results))
            
        except Exception as e:
            logger.error("Error processing organization members: %s", str(e))
            results['member_search_error'] = str(e)
        
        # Audit logs: look for repo create/publication actions mentioning Shai-Hulud
        try:
            logger.info("Searching audit logs for Shai-Hulud references")
            ok, events = org_audit_log_search(phrase="Shai-Hulud", action=None, limit=200)
            if ok:
                results['audit_repo_create'] = events
                logger.info("Found %d relevant audit log events", len(events))
            else:
                logger.warning("Audit log search failed or returned no results")
                results['audit_log_error'] = "Search failed or no results"
                
        except Exception as e:
            logger.error("Error searching audit logs: %s", str(e))
            results['audit_log_error'] = str(e)
            
    except Exception as e:
        logger.exception("Unexpected error in high-level queries: %s", str(e))
        results['error'] = str(e)
    
    logger.info("Completed high-level queries")
    return results


def _fallback_high_level_queries() -> Dict[str, Any]:
    """Fallback implementation using REST API if primary queries fail.
    
    This is a simplified version of run_high_level_queries that uses direct REST API calls
    instead of the GitHub client. It's used as a fallback when the primary method fails.
    
    Returns:
        Dictionary containing query results organized by category
    """
    if not config:
        logger.error("Configuration not initialized in fallback")
        return {}
        
    results: Dict[str, Any] = {
        'first_wave': [],
        'second_wave': [],
        'audit_repo_create': [],
        'private_migration_repos': [],
        'dev_accounts_shai_hulud': [],
        'warnings': ['Using fallback query method']
    }

    try:
        logger.warning("Using fallback high-level queries for organization: %s", config.ORG_NAME)
        
        # First wave: public repos named Shai-Hulud within org
        try:
            q1 = f"org:{config.ORG_NAME} in:name \"Shai-Hulud\" is:public"
            logger.debug("Running fallback first wave query: %s", q1)
            results['first_wave'] = search_repositories(q1)
            logger.info("Fallback first wave query found %d results", len(results['first_wave']))
        except Exception as e:
            logger.error("Error in fallback first wave query: %s", str(e))
            results['first_wave_error'] = str(e)
        
        # Second wave: public repos with description "Shai-Hulud Migration" and name containing 'mitigation'
        try:
            q2 = f"org:{config.ORG_NAME} in:description \"Shai-Hulud Migration\" in:name mitigation is:public"
            logger.debug("Running fallback second wave query: %s", q2)
            results['second_wave'] = search_repositories(q2)
            logger.info("Fallback second wave query found %d results", len(results['second_wave']))
        except Exception as e:
            logger.error("Error in fallback second wave query: %s", str(e))
            results['second_wave_error'] = str(e)
        
        # Get all organization repositories using direct REST API
        try:
            logger.info("Fetching all organization repositories (fallback)")
            org_repos = get_all_repos(include_forks=True, include_archived=True)
            logger.info("Found %d total repositories in organization (fallback)", len(org_repos))
            
            # Process private migration repos
            private_migration_count = 0
            for repo in org_repos:
                try:
                    name = (repo.get('name') or '').lower()
                    desc = (repo.get('description') or '')
                    
                    # Look for private migration repos with Shai-Hulud indicators
                    is_private = repo.get('private', False)
                    is_migration = name.endswith('-migration')
                    has_shaihulud_desc = 'Shai-Hulud Migration' in desc
                    
                    if is_private and is_migration and has_shaihulud_desc:
                        results['private_migration_repos'].append(repo)
                        private_migration_count += 1
                        
                except Exception as e:
                    logger.debug("Error processing repo in fallback: %s", str(e))
                    continue
                    
            logger.info("Found %d private migration repositories (fallback)", private_migration_count)
            
        except Exception as e:
            logger.error("Error fetching organization repositories in fallback: %s", str(e))
            results['repo_fetch_error'] = str(e)
        
        # Get organization members (limited to avoid rate limits)
        try:
            logger.info("Fetching organization members (fallback)")
            members = list_org_members(max_items=5)  # Limit to 5 members in fallback
            logger.info("Found %d organization members (fallback)", len(members))
            
            # Search for Shai-Hulud in developer accounts (with rate limiting)
            dev_account_results = []
            for i, member in enumerate(members, 1):
                try:
                    login = member.get('login')
                    if not login:
                        continue
                        
                    logger.debug("Searching user %d/%d: %s (fallback)", i, len(members), login)
                    
                    # Search for repositories with name containing 'Shai-Hulud'
                    qd = f"user:{login} in:name \"Shai-Hulud\""
                    hits = search_repositories(qd, max_items=3)  # Limit to 3 per user in fallback
                    
                    if hits:
                        dev_account_results.extend(hits)
                        logger.info("Found %d Shai-Hulud repos for user %s (fallback)", 
                                  len(hits), login)
                    
                    # Add a larger delay between user searches in fallback mode
                    if i < len(members):  # No need to delay after the last one
                        time.sleep(2)  # Longer delay in fallback mode
                        
                except Exception as e:
                    logger.error("Error searching user %s in fallback: %s", login, str(e))
                    continue
            
            results['dev_accounts_shai_hulud'] = dev_account_results
            logger.info("Found %d total Shai-Hulud repositories in developer accounts (fallback)", 
                      len(dev_account_results))
            
        except Exception as e:
            logger.error("Error processing organization members in fallback: %s", str(e))
            results['member_search_error'] = str(e)
        
        # Audit logs: look for repo create/publication actions mentioning Shai-Hulud
        try:
            logger.info("Searching audit logs for Shai-Hulud references (fallback)")
            ok, events = org_audit_log_search(phrase="Shai-Hulud", action=None, limit=100)  # Lower limit in fallback
            if ok:
                results['audit_repo_create'] = events
                logger.info("Found %d relevant audit log events (fallback)", len(events))
            else:
                logger.warning("Audit log search failed or returned no results (fallback)")
                results['audit_log_error'] = "Search failed or no results"
                
        except Exception as e:
            logger.error("Error searching audit logs in fallback: %s", str(e))
            results['audit_log_error'] = str(e)
            
    except Exception as e:
        logger.exception("Unexpected error in fallback high-level queries: %s", str(e))
        results['error'] = str(e)
    
    logger.warning("Completed fallback high-level queries")
    return results


def main() -> int:
    """Main entry point for the Shai-Hulud scanner.
    
    This function orchestrates the entire scanning process, including:
    1. Parsing command line arguments
    2. Setting up logging and configuration
    3. Determining which repositories to scan
    4. Running high-level queries
    5. Cloning and scanning repositories
    6. Generating reports
    
    Returns:
        int: Exit code (0 for success, non-zero for errors)
    """
    global config
    start_time = time.time()
    
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description='Scan for Shai-Hulud campaign indicators in GitHub repositories',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--repo', type=str, 
                      help='Specific repo to scan (format: owner/repo or just repo name)')
    parser.add_argument('--all', action='store_true', 
                      help='Scan all repositories in the organization')
    parser.add_argument('--skip-clone', action='store_true', 
                      help='Skip cloning repositories (use with --all or --repo)')
    parser.add_argument('--skip-scan', action='store_true', 
                      help='Skip local scanning (just collect metadata)')
    parser.add_argument('--output', type=str, default='shaihulud_reports',
                      help='Output directory for reports')
    parser.add_argument('--threads', type=int, default=5,
                      help='Number of concurrent threads for cloning/scanning')
    parser.add_argument('--ioc-file', type=str, default='shaihulupkg.txt',
                      help='Path to file containing IoC packages')
    parser.add_argument('--verbose', '-v', action='count', default=0, 
                      help='Increase verbosity (can be specified multiple times)')
    
    args = parser.parse_args()
    
    # Configure logging
    setup_logging(args.verbose)
    logger.info("Starting Shai-Hulud scanner")
    logger.debug("Command line arguments: %s", args)
    
    try:
        # Load configuration
        logger.info("Initializing configuration...")
        config = ShaiHuluConfig()
        config.REPORT_DIR = os.path.abspath(args.output)
        
        # Ensure output directory exists
        os.makedirs(config.REPORT_DIR, exist_ok=True)
        logger.debug("Using report directory: %s", config.REPORT_DIR)
        
        # Load IoC packages
        logger.info("Loading IoC packages from %s...", args.ioc_file)
        try:
            ioc_packages = load_ioc_packages(args.ioc_file)
            logger.info("Loaded %d IoC packages", len(ioc_packages))
        except Exception as e:
            logger.error("Failed to load IoC packages: %s", str(e))
            return 1
        
        # Initialize results
        scan_start = datetime.datetime.utcnow()
        results = {
            'metadata': {
                'start_time': scan_start.isoformat(),
                'command': ' '.join(sys.argv),
                'version': '1.0.0'
            },
            'scanned_repos': [],
            'findings': {
                'package_lock_matches': [],
                'security_logs': [],
                'data_json_findings': [],
                'suspicious_strings': [],
                'workflow_findings': [],
                'ioc_scripts_refs': [],
                'malicious_js_hash_matches': []
            },
            'summary': {
                'total_repos': 0,
                'scanned_repos': 0,
                'findings_count': 0,
                'start_time': scan_start.isoformat(),
                'end_time': None,
                'duration_seconds': None
            },
            'config': {
                'org': config.ORG_NAME,
                'report_dir': config.REPORT_DIR,
                'ioc_packages_count': len(ioc_packages),
                'threads': args.threads,
                'skip_clone': args.skip_clone,
                'skip_scan': args.skip_scan
            }
        }
        
        # Determine which repos to scan
        repos_to_scan = []
        
        if args.repo:
            # Single repo scan
            owner, _, repo_name = args.repo.partition('/')
            if not repo_name:  # If no owner specified, use org
                owner = config.ORG_NAME
                repo_name = args.repo
                
            repo = get_single_repo(owner, repo_name)
            if repo:
                repos_to_scan.append(repo)
            else:
                logger.error(f"Could not find repository: {args.repo}")
                return 1
                
        elif args.all:
            # Scan all repos in the organization
            logger.info(f"Fetching all repositories in organization {config.ORG_NAME}...")
            repos_to_scan = get_all_repos(include_forks=True, include_archived=True)
            logger.info(f"Found {len(repos_to_scan)} repositories to scan")
            
            # Sort by size to process smaller repos first
            repos_to_scan.sort(key=lambda r: r.get('size', 0))
        else:
            # Default: run high-level queries only
            logger.info("Running high-level queries...")
            try:
                query_results = run_high_level_queries()
                
                # Save query results
                query_results_file = os.path.join(config.REPORT_DIR, 'shaihulu_queries.json')
                with open(query_results_file, 'w', encoding='utf-8') as f:
                    json.dump(query_results, f, indent=2, ensure_ascii=False, default=str)
                    
                logger.info(f"Saved query results to {query_results_file}")
                
                # Print summary
                print("\n=== Shai-Hulud Scan Results ===")
                print(f"First wave (public repos named Shai-Hulud): {len(query_results.get('first_wave', []))}")
                print(f"Second wave (mitigation repos): {len(query_results.get('second_wave', []))}")
                print(f"Private migration repos: {len(query_results.get('private_migration_repos', []))}")
                print(f"Dev accounts with Shai-Hulud repos: {len(query_results.get('dev_accounts_shai_hulud', []))}")
                print(f"Audit log events: {len(query_results.get('audit_repo_create', []))}")
                print("\nRun with --all to scan all repositories locally")
                summary_file = os.path.join(config.REPORT_DIR, 'summary.json')
                with open(summary_file, 'w', encoding='utf-8') as f:
                    json.dump({
                        'timestamp': datetime.datetime.utcnow().isoformat(),
                        'results': summary,
                        'details_file': os.path.basename(query_results_file)
                    }, f, indent=2)
                    
                return 0
                
            except Exception as e:
                logger.exception("Error during high-level queries: %s", str(e))
                return 1
        
        # Update total repos count
        results['summary']['total_repos'] = len(repos_to_scan)
        
        # Scan the selected repositories if not skipped
        if not args.skip_scan and not args.skip_clone and repos_to_scan:
            logger.info("Starting scan of %d repositories with %d threads...", 
                      len(repos_to_scan), args.threads)
            
            # Create a thread pool for parallel processing
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
                # Submit all clone and scan tasks
                future_to_repo = {}
                for repo in repos_to_scan:
                    repo_name = repo.get('full_name', repo.get('name', 'unknown'))
                    future = executor.submit(process_repository, repo, ioc_packages, args.skip_clone, args.skip_scan)
                    future_to_repo[future] = repo_name
                
                # Process completed tasks
                for future in concurrent.futures.as_completed(future_to_repo):
                    repo_name = future_to_repo[future]
                    try:
                        repo_result = future.result()
                        results['scanned_repos'].append(repo_result)
                        
                        # Update findings
                        if 'findings' in repo_result:
                            for key in results['findings'].keys():
                                if key in repo_result['findings'] and repo_result['findings'][key]:
                                    results['findings'][key].extend(repo_result['findings'][key])
                        
                        # Update summary
                        results['summary']['scanned_repos'] += 1
                        results['summary']['findings_count'] += sum(
                            len(v) for v in repo_result.get('findings', {}).values()
                        )
                        
                        # Log progress
                        progress = (len(results['scanned_repos']) / len(repos_to_scan)) * 100
                        logger.info("Progress: %.1f%% - Scanned %d/%d repositories (%d findings)",
                                  progress, len(results['scanned_repos']), len(repos_to_scan),
                                  results['summary']['findings_count'])
                        
                    except Exception as e:
                        logger.error("Error processing repository %s: %s", repo_name, str(e))
                        results['scanned_repos'].append({
                            'repo': repo_name,
                            'error': str(e),
                            'success': False,
                            'timestamp': datetime.datetime.utcnow().isoformat()
                        })
                        repo_path = future.result()
                        if repo_path:
                            logger.debug("Cloned %s to %s", repo.get('full_name', 'unknown'), repo_path)
                        else:
                            logger.warning("Failed to clone %s", repo.get('full_name', 'unknown'))
                    except Exception as e:
                        logger.exception("Error cloning repository")
        
        # Scan each repository
        scan_results = {}
        for repo in repos_to_scan:
            repo_name = repo.get('full_name', 'unknown')
            logger.info("Scanning %s...", repo_name)
            
            repo_results = {
                'metadata': repo,
                'findings': {}
            }
            
            # Local scan if not skipped
            if not args.skip_scan:
                repo_path = os.path.join(config.CLONE_DIR or '', repo_name.split('/')[-1])
                if os.path.exists(repo_path):
                    findings = scan_repo_local(repo_path, repo, ioc_packages)
                    repo_results['findings'] = findings
                    
                    # Write individual report
                    write_repo_report(config.REPORT_DIR, repo_name, findings)
                    
                    # Add to results if there are findings
                    if any(findings.values()):
                        scan_results[repo_name] = findings
            
            results['scanned_repos'].append(repo_name)
            results['findings'][repo_name] = repo_results
        
        # Write summary report
        summary_file = os.path.join(config.REPORT_DIR, 'shaihulu_summary.json')
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        logger.info("Scan complete. Results saved to %s", config.REPORT_DIR)
        
        # Print summary
        print("\n=== Scan Summary ===")
        print(f"Repositories scanned: {len(results['scanned_repos'])}")
        print(f"Repositories with findings: {len(scan_results)}")
        print(f"\nDetailed reports available in: {os.path.abspath(config.REPORT_DIR)}")
        
        return 0
        
    except Exception as e:
        logger.exception("An error occurred during scanning")
        return 1


# -----------------
# Reporting
# -----------------

def write_repo_report(report_dir: str, repo_name: str, findings: Dict[str, Any]):
    os.makedirs(report_dir, exist_ok=True)
    md = os.path.join(report_dir, f"{repo_name}_shaihulu.md")
    with open(md, 'w', encoding='utf-8') as f:
        f.write(f"# Shai-Hulud Scan Report\n\n")
        f.write(f"**Repository:** {repo_name}\n\n")
        for key in ['package_lock_matches','security_logs','data_json_findings','suspicious_strings','workflow_findings','ioc_scripts_refs','malicious_js_hash_matches']:
            items = findings.get(key) or []
            f.write(f"## {key}\n\n")
            if not items:
                f.write("- None\n\n")
            else:
                for it in items:
                    f.write(f"- {json.dumps(it, ensure_ascii=False)}\n")
                f.write("\n")


def write_summary(report_root: str, repos_scanned: int, summary: Dict[str, Any]):
    os.makedirs(report_root, exist_ok=True)
    md_path = os.path.join(report_root, "shaihulu_summary.md")
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write("# Shai-Hulud Summary\n\n")
        f.write(f"**Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**Repos scanned:** {repos_scanned}\n\n")
        for sec in ['first_wave','second_wave','audit_repo_create','private_migration_repos','dev_accounts_shai_hulud']:
            f.write(f"## {sec}\n\n")
            items = summary.get(sec) or []
            if not items:
                f.write("- None\n\n")
            else:
                for it in items:
                    try:
                        f.write(f"- {json.dumps(it, ensure_ascii=False)}\n")
                    except Exception:
                        f.write(f"- {str(it)}\n")
                f.write("\n")


# -----------------
# Main
# -----------------

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if logger.getEffectiveLevel() <= logging.DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)
