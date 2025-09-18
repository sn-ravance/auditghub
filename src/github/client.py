"""GitHub API client with GraphQL and REST support and caching."""
from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, TypeVar, Generic, Type, Union, cast
from urllib.parse import urljoin

import requests
from cachetools import TTLCache
from cachetools.keys import hashkey

from .graphql_utils import GraphQLClient
from .repository_queries import RepositoryQueries

T = TypeVar('T')

# Default cache TTL in seconds (1 hour)
DEFAULT_CACHE_TTL = 3600
# Default cache max size (1000 items)
DEFAULT_CACHE_SIZE = 1000

class BaseGitHubClient(ABC):
    """Base class for GitHub API clients with common functionality."""
    
    def __init__(
        self,
        token: Optional[str] = None,
        base_url: str = "https://api.github.com",
        cache_ttl: int = DEFAULT_CACHE_TTL,
        cache_size: int = DEFAULT_CACHE_SIZE,
        user_agent: str = "auditgh"
    ) -> None:
        """Initialize the GitHub client.
        
        Args:
            token: GitHub personal access token for authentication
            base_url: Base URL for the GitHub API
            cache_ttl: Cache TTL in seconds
            cache_size: Maximum number of items to cache
            user_agent: User agent string for API requests
        """
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.base_url = base_url.rstrip('/')
        self.user_agent = user_agent
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Initialize cache
        self._cache = TTLCache(
            maxsize=cache_size,
            ttl=cache_ttl,
            getsizeof=lambda x: 1  # Simple size function for TTLCache
        )
        
        # Initialize session
        self._session = self._create_session()
        
        # Initialize GraphQL client if needed
        self._graphql_client: Optional[GraphQLClient] = None
        self._repository_queries: Optional[RepositoryQueries] = None
    
    def _create_session(self) -> requests.Session:
        """Create and configure a requests session."""
        session = requests.Session()
        
        # Set up headers
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': self.user_agent
        }
        
        # Add auth token if provided
        if self.token:
            headers['Authorization'] = f'token {self.token}'
        
        session.headers.update(headers)
        return session
    
    @property
    def graphql(self) -> GraphQLClient:
        """Get the GraphQL client, initializing it if needed."""
        if self._graphql_client is None:
            graphql_url = self.base_url.replace('api.', 'api.' if 'api.' in self.base_url else '') + '/graphql'
            self._graphql_client = GraphQLClient(
                endpoint=graphql_url,
                token=self.token,
                user_agent=self.user_agent
            )
        return self._graphql_client
    
    @property
    def repositories(self) -> RepositoryQueries:
        """Get the repository queries client."""
        if self._repository_queries is None:
            self._repository_queries = RepositoryQueries(self.graphql, self)
        return self._repository_queries
    
    def _make_cache_key(self, method: str, url: str, **kwargs) -> str:
        """Generate a cache key for a request."""
        # Sort kwargs for consistent keys
        sorted_kwargs = tuple(sorted((k, v) for k, v in kwargs.items()))
        return str(hashkey(method, url, sorted_kwargs))
    
    def _cached_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make a request with caching."""
        cache_key = self._make_cache_key(method, url, **kwargs)
        
        # Check cache first
        if cache_key in self._cache:
            self.logger.debug(f"Cache hit for {method} {url}")
            return self._cache[cache_key]
        
        # Make the request
        self.logger.debug(f"Cache miss for {method} {url}")
        response = self._session.request(method, url, **kwargs)
        
        # Cache successful responses
        if response.status_code == 200:
            self._cache[cache_key] = response
        
        return response
    
    def get(self, path: str, **kwargs) -> requests.Response:
        """Make a GET request to the GitHub API."""
        url = urljoin(f"{self.base_url}/", path.lstrip('/'))
        return self._cached_request('GET', url, **kwargs)
    
    def post(self, path: str, **kwargs) -> requests.Response:
        """Make a POST request to the GitHub API."""
        url = urljoin(f"{self.base_url}/", path.lstrip('/'))
        return self._session.post(url, **kwargs)
    
    def put(self, path: str, **kwargs) -> requests.Response:
        """Make a PUT request to the GitHub API."""
        url = urljoin(f"{self.base_url}/", path.lstrip('/'))
        return self._session.put(url, **kwargs)
    
    def delete(self, path: str, **kwargs) -> requests.Response:
        """Make a DELETE request to the GitHub API."""
        url = urljoin(f"{self.base_url}/", path.lstrip('/'))
        return self._session.delete(url, **kwargs)
    
    def close(self) -> None:
        """Close the underlying session."""
        self._session.close()
    
    def __enter__(self) -> 'BaseGitHubClient':
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - close the session."""
        self.close()


class GitHubClient(BaseGitHubClient):
    """Main GitHub API client with high-level methods."""
    
    def get_repository(self, owner: str, repo: str) -> Dict[str, Any]:
        """Get a single repository."""
        path = f"repos/{owner}/{repo}"
        response = self.get(path)
        response.raise_for_status()
        return response.json()
    
    def list_organization_repositories(
        self,
        org: str,
        repo_type: str = "all",
        sort: str = "full_name",
        direction: str = "asc",
        per_page: int = 100,
        page: int = 1
    ) -> List[Dict[str, Any]]:
        """List organization repositories with pagination."""
        path = f"orgs/{org}/repos"
        params = {
            'type': repo_type,
            'sort': sort,
            'direction': direction,
            'per_page': min(per_page, 100),  # GitHub max per_page is 100
            'page': page
        }
        
        response = self.get(path, params=params)
        response.raise_for_status()
        return response.json()
    
    def list_all_organization_repositories(
        self,
        org: str,
        include_forks: bool = True,
        include_archived: bool = True
    ) -> List[Dict[str, Any]]:
        """List all repositories in an organization with optional filtering."""
        all_repos: List[Dict[str, Any]] = []
        page = 1
        per_page = 100
        
        while True:
            try:
                repos = self.list_organization_repositories(
                    org=org,
                    repo_type='all',
                    per_page=per_page,
                    page=page
                )
                
                if not repos:
                    break
                
                # Apply filters
                for repo in repos:
                    if not include_forks and repo.get('fork'):
                        continue
                    if not include_archived and repo.get('archived'):
                        continue
                    all_repos.append(repo)
                
                # If we got fewer results than requested, we've reached the end
                if len(repos) < per_page:
                    break
                    
                page += 1
                
            except requests.exceptions.HTTPError as e:
                self.logger.error(f"Error fetching repositories: {e}")
                break
        
        return all_repos
    
    def search_repositories(
        self,
        query: str,
        sort: Optional[str] = None,
        order: str = "desc",
        per_page: int = 30,
        page: int = 1
    ) -> Dict[str, Any]:
        """Search repositories with the GitHub API."""
        path = "search/repositories"
        params = {
            'q': query,
            'order': order,
            'per_page': min(per_page, 100),  # GitHub max per_page is 100
            'page': page
        }
        
        if sort:
            params['sort'] = sort
        
        response = self.get(path, params=params)
        response.raise_for_status()
        return response.json()
    
    def get_rate_limit(self) -> Dict[str, Any]:
        """Get GitHub API rate limit information."""
        response = self.get("rate_limit")
        response.raise_for_status()
        return response.json()
