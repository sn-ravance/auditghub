# Migration Guide: GitHub API Client

This guide helps you migrate from the legacy `GitHubAPI` class to the new `GitHubClient` with GraphQL support.

## Key Changes

1. **Unified Client**: The new `GitHubClient` combines both REST and GraphQL functionality
2. **Improved Caching**: Built-in response caching with TTL
3. **Better Rate Limiting**: Automatic rate limit handling with retries
4. **Type Hints**: Full type annotations for better IDE support
5. **Consistent API**: More consistent method naming and parameter handling

## Migration Steps

### 1. Update Imports

**Before:**
```python
from github import GitHubAPI
```

**After:**
```python
from github import GitHubClient
```

### 2. Initialize the Client

**Before:**
```python
github = GitHubAPI(token="your_token")
```

**After:**
```python
# Basic usage
github = GitHubClient(token="your_token")

# With custom settings
github = GitHubClient(
    token="your_token",
    base_url="https://api.github.com",  # or your GHES URL
    cache_ttl=3600,  # 1 hour cache TTL
    cache_size=1000,  # Max 1000 items in cache
    user_agent="your-app/1.0.0"
)
```

### 3. Common Operations

#### Get a Repository

**Before:**
```python
repo = github.get_repo("owner/repo")
```

**After:**
```python
# Using REST API
repo = github.get_repository("owner", "repo")

# Using GraphQL (more efficient for complex queries)
repo = github.repositories.get_repository(owner="owner", name="repo")
```

#### List Organization Repositories

**Before:**
```python
repos = github.get_org_repos("org-name")
```

**After:**
```python
# Using REST API (pagination handled automatically)
repos = github.list_all_organization_repositories("org-name")

# With filters
repos = github.list_all_organization_repositories(
    "org-name",
    include_forks=False,
    include_archived=False
)

# Using GraphQL (more efficient for large organizations)
repos = github.repositories.list_organization_repositories(
    org="org-name",
    first=100,  # Number of items per page
    privacy="PUBLIC"  # Optional: PUBLIC, PRIVATE, or None for all
)
```

#### Search Repositories

**Before:**
```python
repos = github.search_repos("org:org-name language:python")
```

**After:**
```python
# Using REST API
result = github.search_repositories("org:org-name language:python")
repos = result.get('items', [])

# Using GraphQL (more efficient for complex queries)
result = github.repositories.search_repositories(
    query="org:org-name language:python",
    first=100  # Number of items per page
)
repos = result['nodes']
```

### 4. Rate Limiting

The new client handles rate limiting automatically, but you can still access rate limit information:

```python
# Get current rate limit status
rate_limit = github.get_rate_limit()
print(f"Remaining: {rate_limit['remaining']}/{rate_limit['limit']}")
print(f"Resets at: {rate_limit['resetAt']}")
```

### 5. Caching

Responses are cached automatically. You can control caching behavior:

```python
# Disable caching for a specific request
repo = github.get_repository("owner", "repo", use_cache=False)

# Clear the cache
github.clear_cache()
```

### 6. Error Handling

Error handling is more consistent. All API errors raise `requests.exceptions.HTTPError`:

```python
try:
    repo = github.get_repository("owner", "nonexistent-repo")
except requests.exceptions.HTTPError as e:
    if e.response.status_code == 404:
        print("Repository not found")
    else:
        raise
```

## Advanced Usage

### Custom GraphQL Queries

```python
query = """
query GetRepo($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    name
    description
    stargazerCount
    forkCount
    # Add more fields as needed
  }
}
"""

result = github.graphql.execute(query, variables={"owner": "owner", "name": "repo"})
print(result['data']['repository'])
```

### Batch Operations

```python
# Get multiple repositories in a single request
repos = github.repositories.get_repositories([
    ("owner1", "repo1"),
    ("owner2", "repo2"),
    # ...
])
```

## Backward Compatibility

The legacy `GitHubAPI` class is still available but deprecated. It's recommended to migrate to the new `GitHubClient` for new code.

## Performance Tips

1. Use GraphQL for complex queries to reduce the number of API calls
2. Take advantage of the built-in caching for frequently accessed resources
3. Use batch operations when possible to reduce the number of requests
4. Set appropriate cache TTL based on your use case

## Troubleshooting

### Enable Debug Logging

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Check Rate Limits

```python
rate_limit = github.get_rate_limit()
print(f"Remaining: {rate_limit['remaining']}/{rate_limit['limit']}")
```

### Clear Cache

```python
github.clear_cache()
```
## Example: Converting a Scan Script

Here's an example of converting a scan script from the old to the new API:

**Before:**
```python
from github import GitHubAPI

def scan_repos(org_name):
    github = GitHubAPI()
    repos = github.get_org_repos(org_name)
    
    for repo in repos:
        print(f"Scanning {repo['full_name']}")
        # ... scan logic ...
```

**After:**
```python
from github import GitHubClient

def scan_repos(org_name):
    # Initialize with caching and rate limiting
    github = GitHubClient(cache_ttl=3600)
    
    # Get all repositories (automatically handles pagination)
    repos = github.list_all_organization_repositories(
        org_name,
        include_forks=False,
        include_archived=False
    )
    
    for repo in repos:
        print(f"Scanning {repo['full_name']}")
        # ... scan logic ...
```

## Next Steps

1. Update your code to use the new `GitHubClient`
2. Test thoroughly in a development environment
3. Monitor API usage and adjust caching as needed
4. Report any issues to the project maintainers
