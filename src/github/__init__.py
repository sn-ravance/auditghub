"""GitHub API client with GraphQL and REST support.

This package provides a high-level interface to the GitHub API with support for both
GraphQL and REST endpoints, including built-in rate limiting, retries, and caching.

Example usage:
    ```python
    from github import GitHubClient
    
    # Create a client with default settings
    client = GitHubClient(token="your_github_token")
    
    # Get a repository
    repo = client.get_repository("owner", "repo")
    
    # List all repositories in an organization
    repos = client.list_all_organization_repositories("org-name")
    ```
"""
import warnings
from typing import Any, Dict, List, Optional

# Import new components
from .client import GitHubClient, BaseGitHubClient
from .graphql_utils import GraphQLClient
from .repository_queries import RepositoryQueries
from .models import (
    Repository,
    Contributor,
    LanguageStats,
    RepositoryPrivacy,
    RepositoryOrderField,
    OrderDirection,
    RateLimit,
)
from .utils import (
    make_rate_limited_session,
    handle_rate_limits,
    paginate,
    parse_rate_limit_headers,
    get_rate_limit_reset_time,
    is_rate_limited,
    wait_for_rate_limit_reset,
    filter_repositories,
)

# Backward compatibility imports
from .api import GitHubAPI as LegacyGitHubAPI

# Warn about deprecated imports
warnings.warn(
    "The direct import of GitHubAPI is deprecated. "
    "Please use GitHubClient instead.",
    DeprecationWarning,
    stacklevel=2
)

# Alias for backward compatibility
GitHubAPI = LegacyGitHubAPI

__all__ = [
    # New components
    'GitHubClient',
    'BaseGitHubClient',
    'GraphQLClient',
    'RepositoryQueries',
    'Repository',
    'Contributor',
    'LanguageStats',
    'RepositoryPrivacy',
    'RepositoryOrderField',
    'OrderDirection',
    'RateLimit',
    'make_rate_limited_session',
    'handle_rate_limits',
    'paginate',
    'parse_rate_limit_headers',
    'get_rate_limit_reset_time',
    'is_rate_limited',
    'wait_for_rate_limit_reset',
    'filter_repositories',
    # Legacy components (deprecated)
    'GitHubAPI',
]

__version__ = '0.1.0'
