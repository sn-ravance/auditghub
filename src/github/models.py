"""
Data models for GitHub API responses.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Literal, TypedDict, Generic, TypeVar

# Type variables for generic responses
T = TypeVar('T')

class RepositoryPrivacy(str, Enum):
    """Repository privacy settings."""
    PUBLIC = 'PUBLIC'
    PRIVATE = 'PRIVATE'
    INTERNAL = 'INTERNAL'

class RepositoryOrderField(str, Enum):
    """Fields available for repository ordering."""
    CREATED_AT = 'CREATED_AT'
    UPDATED_AT = 'UPDATED_AT'
    PUSHED_AT = 'PUSHED_AT'
    NAME = 'NAME'
    STARGAZERS = 'STARGAZERS'

class OrderDirection(str, Enum):
    """Sort direction for queries."""
    ASC = 'ASC'
    DESC = 'DESC'


class RepositoryOwner(TypedDict):
    """Repository owner information."""
    login: str
    id: str
    avatar_url: str
    html_url: str
    type: Literal['User', 'Organization']

class LicenseInfo(TypedDict):
    """License information."""
    key: str
    name: str
    spdx_id: str
    url: str
    node_id: str

@dataclass
class Repository:
    """Repository information from GitHub API."""
    # Core fields
    name: str
    full_name: str
    html_url: str
    description: Optional[str] = None
    homepage: Optional[str] = None
    language: Optional[str] = None
    license_info: Optional[LicenseInfo] = None
    owner: Optional[RepositoryOwner] = None
    
    # Timestamps
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    pushed_at: Optional[str] = None
    
    # Counts
    size: int = 0
    stargazers_count: int = 0
    watchers_count: int = 0
    forks_count: int = 0
    open_issues_count: int = 0
    network_count: int = 0
    subscribers_count: int = 0
    
    # Flags
    is_fork: bool = False
    is_archived: bool = False
    is_disabled: bool = False
    is_template: bool = False
    has_issues: bool = True
    has_projects: bool = True
    has_wiki: bool = True
    has_downloads: bool = True
    has_discussions: bool = False
    
    # References
    default_branch: str = "main"
    topics: List[str] = field(default_factory=list)
    
    # GraphQL specific
    id: Optional[str] = None
    database_id: Optional[int] = None
    url: Optional[str] = None
    
    def __post_init__(self) -> None:
        # Convert dict to LicenseInfo if needed
        if isinstance(self.license_info, dict):
            self.license_info = LicenseInfo(**self.license_info)
        # Convert dict to RepositoryOwner if needed
        if isinstance(self.owner, dict):
            self.owner = RepositoryOwner(**self.owner)
    
    @property
    def last_updated(self) -> Optional[datetime]:
        """Get the last update time as a datetime object."""
        if self.pushed_at:
            return datetime.fromisoformat(self.pushed_at.replace('Z', '+00:00'))
        return None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Repository':
        """Create a Repository instance from a dictionary."""
        # Map GitHub API response to our model
        mapped = {
            'name': data.get('name'),
            'full_name': data.get('full_name'),
            'html_url': data.get('html_url'),
            'description': data.get('description'),
            'homepage': data.get('homepage'),
            'language': data.get('language'),
            'license_info': data.get('license'),
            'owner': data.get('owner'),
            'created_at': data.get('created_at'),
            'updated_at': data.get('updated_at'),
            'pushed_at': data.get('pushed_at'),
            'size': data.get('size', 0),
            'stargazers_count': data.get('stargazers_count', 0),
            'watchers_count': data.get('watchers_count', 0),
            'forks_count': data.get('forks_count', 0),
            'open_issues_count': data.get('open_issues_count', 0),
            'network_count': data.get('network_count', 0),
            'subscribers_count': data.get('subscribers_count', 0),
            'is_fork': data.get('fork', False),
            'is_archived': data.get('archived', False),
            'is_disabled': data.get('disabled', False),
            'is_template': data.get('is_template', False),
            'has_issues': data.get('has_issues', True),
            'has_projects': data.get('has_projects', True),
            'has_wiki': data.get('has_wiki', True),
            'has_downloads': data.get('has_downloads', True),
            'has_discussions': data.get('has_discussions', False),
            'default_branch': data.get('default_branch', 'main'),
            'topics': data.get('topics', []),
            'id': data.get('node_id'),
            'database_id': data.get('id'),
            'url': data.get('url')
        }
        return cls(**{k: v for k, v in mapped.items() if v is not None})
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the repository to a dictionary."""
        result = asdict(self)
        # Convert nested objects to dict
        if self.license_info:
            result['license_info'] = dict(self.license_info)
        if self.owner:
            result['owner'] = dict(self.owner)
        return result


@dataclass
class Contributor:
    """Repository contributor information."""
    login: str
    contributions: int
    avatar_url: Optional[str] = None
    html_url: Optional[str] = None
    type: str = "User"
    site_admin: bool = False
    id: Optional[str] = None
    name: Optional[str] = None
    email: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Contributor':
        """Create a Contributor instance from a dictionary."""
        return cls(
            login=data.get('login', ''),
            contributions=data.get('contributions', 0),
            avatar_url=data.get('avatar_url'),
            html_url=data.get('html_url'),
            type=data.get('type', 'User'),
            site_admin=data.get('site_admin', False),
            id=data.get('id'),
            name=data.get('name'),
            email=data.get('email')
        )


@dataclass
class LanguageStats:
    """Repository language statistics."""
    languages: Dict[str, int] = field(default_factory=dict)
    total_bytes: int = 0

    def add_language(self, language: str, bytes_count: int) -> None:
        """Add language data to the stats."""
        self.languages[language] = bytes_count
        self.total_bytes += bytes_count

    def get_percentage(self, language: str) -> float:
        """Get the percentage of code in a specific language."""
        if not self.total_bytes or language not in self.languages:
            return 0.0
        return (self.languages[language] / self.total_bytes) * 100
    
    @classmethod
    def from_dict(cls, data: Dict[str, int]) -> 'LanguageStats':
        """Create LanguageStats from a dictionary of language stats."""
        stats = cls()
        for lang, bytes_count in data.items():
            stats.add_language(lang, bytes_count)
        return stats


class PageInfo(TypedDict):
    """Pagination information for GraphQL queries."""
    hasNextPage: bool
    endCursor: Optional[str]


class GraphQLResponse(TypedDict, Generic[T]):
    """Generic GraphQL response type."""
    data: Optional[Dict[str, T]]
    errors: Optional[List[Dict[str, Any]]]


class RepositoryConnection(TypedDict):
    """Repository connection type for GraphQL pagination."""
    totalCount: int
    pageInfo: PageInfo
    nodes: List[Dict[str, Any]]


class SearchResultItemConnection(TypedDict):
    """Search result connection type for GraphQL."""
    repositoryCount: int
    pageInfo: PageInfo
    nodes: List[Dict[str, Any]]


class RateLimit(TypedDict):
    """GitHub API rate limit information."""
    limit: int
    cost: int
    remaining: int
    resetAt: str
    used: int


class RateLimitInfo(TypedDict):
    """Rate limit information from GraphQL API."""
    limit: int
    cost: int
    remaining: int
    resetAt: str
    nodeCount: int


class GraphQLRateLimit(TypedDict):
    """Rate limit information from GraphQL API."""
    limit: int
    cost: int
    remaining: int
    resetAt: str
    nodeCount: int


class GraphQLRateLimitInfo(TypedDict):
    """GraphQL rate limit information."""
    rateLimit: GraphQLRateLimit
