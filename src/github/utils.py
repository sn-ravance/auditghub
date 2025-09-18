"""Utility functions for GitHub API interactions."""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar, cast, overload

import requests
from requests import Response, Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .models import RateLimit, Repository

T = TypeVar('T')
F = TypeVar('F', bound=Callable[..., Any])

# Default retry strategy
DEFAULT_RETRY_STRATEGY = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"]
)

def make_rate_limited_session(
    token: Optional[str] = None,
    user_agent: str = "auditgh",
    retry_strategy: Optional[Retry] = None
) -> Session:
    """Create a requests Session with rate limiting and retry logic.
    
    Args:
        token: GitHub personal access token
        user_agent: User agent string
        retry_strategy: Custom retry strategy. If None, uses DEFAULT_RETRY_STRATEGY.
        
    Returns:
        Configured requests.Session instance
    """
    session = requests.Session()
    
    # Set up headers
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': user_agent
    }
    
    if token:
        headers['Authorization'] = f'token {token}'
    
    session.headers.update(headers)
    
    # Set up retry strategy
    adapter = HTTPAdapter(
        max_retries=retry_strategy if retry_strategy is not None else DEFAULT_RETRY_STRATEGY
    )
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    
    return session

def handle_rate_limits(func: F) -> F:
    """Decorator to handle GitHub API rate limits with exponential backoff."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        max_retries = 3
        base_delay = 5  # seconds
        
        for attempt in range(max_retries):
            try:
                return func(*args, **kwargs)
            except requests.exceptions.HTTPError as e:
                if e.response.status_code != 403:
                    raise
                
                # Check if rate limited
                rate_limit_remaining = e.response.headers.get('X-RateLimit-Remaining')
                rate_limit_reset = e.response.headers.get('X-RateLimit-Reset')
                
                if not (rate_limit_remaining == '0' and rate_limit_reset):
                    raise
                
                # Calculate sleep time with jitter
                reset_time = int(rate_limit_reset)
                now = int(time.time())
                sleep_time = max(reset_time - now, 0) + 1  # Add 1 second buffer
                
                if attempt == max_retries - 1:
                    logging.error(f"Rate limit exceeded. Max retries ({max_retries}) reached.")
                    raise
                
                logging.warning(
                    f"Rate limit exceeded. Waiting {sleep_time} seconds before retry "
                    f"(attempt {attempt + 1}/{max_retries})"
                )
                time.sleep(sleep_time)
    
    return cast(F, wrapper)

def paginate(
    session: Session,
    url: str,
    params: Optional[Dict[str, Any]] = None,
    max_pages: Optional[int] = None,
    per_page: int = 100,
    timeout: int = 30
) -> List[Dict[str, Any]]:
    """Paginate through GitHub API responses.
    
    Args:
        session: requests.Session instance
        url: API endpoint URL
        params: Query parameters
        max_pages: Maximum number of pages to fetch (None for all)
        per_page: Number of items per page (max 100)
        timeout: Request timeout in seconds
        
    Returns:
        List of items from all pages
    """
    if params is None:
        params = {}
    
    params = params.copy()
    params['per_page'] = min(per_page, 100)  # GitHub max per_page is 100
    
    items: List[Dict[str, Any]] = []
    page = 1
    
    while True:
        if max_pages is not None and page > max_pages:
            break
            
        params['page'] = page
        response = session.get(url, params=params, timeout=timeout)
        response.raise_for_status()
        
        page_items = response.json()
        if not page_items:
            break
            
        items.extend(page_items)
        
        # Check if we've reached the last page
        link_header = response.headers.get('Link', '')
        if 'rel="next"' not in link_header:
            break
            
        page += 1
    
    return items

def parse_rate_limit_headers(response: Response) -> RateLimit:
    """Parse rate limit headers from a GitHub API response.
    
    Args:
        response: requests.Response object
        
    Returns:
        RateLimit object with rate limit information
    """
    return {
        'limit': int(response.headers.get('X-RateLimit-Limit', 0)),
        'remaining': int(response.headers.get('X-RateLimit-Remaining', 0)),
        'reset': int(response.headers.get('X-RateLimit-Reset', 0)),
        'used': int(response.headers.get('X-RateLimit-Used', 0)),
    }

def get_rate_limit_reset_time(rate_limit: RateLimit) -> datetime:
    """Get the datetime when rate limits reset.
    
    Args:
        rate_limit: RateLimit dictionary
        
    Returns:
        datetime when rate limits reset
    """
    return datetime.fromtimestamp(rate_limit['reset'], timezone.utc)

def is_rate_limited(rate_limit: RateLimit) -> bool:
    """Check if rate limited based on rate limit info.
    
    Args:
        rate_limit: RateLimit dictionary
        
    Returns:
        True if rate limited, False otherwise
    """
    return rate_limit['remaining'] <= 0

def wait_for_rate_limit_reset(rate_limit: RateLimit) -> None:
    """Sleep until rate limits reset.
    
    Args:
        rate_limit: RateLimit dictionary
    """
    reset_time = get_rate_limit_reset_time(rate_limit)
    now = datetime.now(timezone.utc)
    sleep_seconds = max(0, (reset_time - now).total_seconds() + 1)  # Add 1 second buffer
    
    if sleep_seconds > 0:
        logging.warning(f"Rate limited. Waiting {sleep_seconds:.1f} seconds until {reset_time.isoformat()}")
        time.sleep(sleep_seconds)

def filter_repositories(
    repos: List[Dict[str, Any]],
    include_archived: bool = False,
    include_forks: bool = False,
    include_private: bool = True,
    include_public: bool = True
) -> List[Dict[str, Any]]:
    """Filter repositories based on criteria.
    
    Args:
        repos: List of repository dictionaries
        include_archived: Whether to include archived repositories
        include_forks: Whether to include forked repositories
        include_private: Whether to include private repositories
        include_public: Whether to include public repositories
        
    Returns:
        Filtered list of repositories
    """
    filtered = []
    
    for repo in repos:
        # Skip archived repositories unless included
        if not include_archived and repo.get('archived'):
            continue
            
        # Skip forks unless included
        if not include_forks and repo.get('fork'):
            continue
            
        # Filter by visibility
        is_private = repo.get('private', False)
        if is_private and not include_private:
            continue
        if not is_private and not include_public:
            continue
            
        filtered.append(repo)
    
    return filtered
