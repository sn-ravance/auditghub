"""
GraphQL queries for repository-related operations.
"""
from typing import Any, Dict, List, Optional
from .graphql_utils import GraphQLClient

class RepositoryQueries:
    def __init__(self, client: GraphQLClient):
        self.client = client

    def search_repositories(
        self,
        query: str,
        first: int = 100,
        after: Optional[str] = None,
        include_forks: bool = False,
        include_archived: bool = False
    ) -> Dict[str, Any]:
        """
        Search for repositories using GraphQL API with pagination.
        
        Args:
            query: Search query string
            first: Number of results per page
            after: Cursor for pagination
            include_forks: Whether to include forked repositories
            include_archived: Whether to include archived repositories
            
        Returns:
            Dict containing search results and page info
        """
        search_query = f"{query} "
        if not include_forks:
            search_query += "fork:false "
        if not include_archived:
            search_query += "archived:false "
            
        variables = {
            "query": search_query.strip(),
            "first": first,
        }
        
        if after:
            variables["after"] = after
            
        query = """
        query SearchRepositories($query: String!, $first: Int, $after: String) {
          search(query: $query, type: REPOSITORY, first: $first, after: $after) {
            repositoryCount
            pageInfo {
              hasNextPage
              endCursor
              startCursor
            }
            edges {
              node {
                ... on Repository {
                  id
                  name
                  nameWithOwner
                  description
                  url
                  isPrivate
                  isArchived
                  isFork
                  createdAt
                  updatedAt
                  pushedAt
                  primaryLanguage {
                    name
                  }
                  owner {
                    login
                    ... on User {
                      email
                    }
                    ... on Organization {
                      email
                    }
                  }
                }
              }
            }
          }
          rateLimit {
            limit
            cost
            remaining
            resetAt
          }
        }
        """
        
        return self.client.execute_query(query, variables)

    def get_organization_repositories(
        self,
        org: str,
        first: int = 100,
        after: Optional[str] = None,
        include_forks: bool = False,
        include_archived: bool = False
    ) -> Dict[str, Any]:
        """
        Get repositories for an organization with pagination.
        """
        variables = {
            "org": org,
            "first": first,
            "includeForks": include_forks,
            "includeArchived": include_archived,
        }
        
        if after:
            variables["after"] = after
            
        query = """
        query GetOrgRepositories(
            $org: String!,
            $first: Int,
            $after: String,
            $includeForks: Boolean!,
            $includeArchived: Boolean!
        ) {
          organization(login: $org) {
            repositories(
              first: $first,
              after: $after,
              isFork: $includeForks,
              isArchived: $includeArchived,
              orderBy: {field: UPDATED_AT, direction: DESC}
            ) {
              totalCount
              pageInfo {
                hasNextPage
                endCursor
                startCursor
              }
              nodes {
                id
                name
                nameWithOwner
                description
                url
                isPrivate
                isArchived
                isFork
                createdAt
                updatedAt
                pushedAt
                primaryLanguage {
                  name
                }
                owner {
                  login
                }
              }
            }
          }
          rateLimit {
            limit
            cost
            remaining
            resetAt
          }
        }
        """
        
        return self.client.execute_query(query, variables)

    def get_repository_details(self, owner: str, name: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a repository.
        """
        query = """
        query GetRepository($owner: String!, $name: String!) {
          repository(owner: $owner, name: $name) {
            id
            name
            nameWithOwner
            description
            url
            isPrivate
            isArchived
            isFork
            createdAt
            updatedAt
            pushedAt
            primaryLanguage {
              name
            }
            owner {
              login
              ... on User {
                email
              }
              ... on Organization {
                email
              }
            }
            defaultBranchRef {
              name
              target {
                ... on Commit {
                  history(first: 1) {
                    edges {
                      node {
                        ... on Commit {
                          committedDate
                          message
                          author {
                            name
                            email
                            user {
                              login
                              name
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
            stargazers {
              totalCount
            }
            watchers {
              totalCount
            }
            forks {
              totalCount
            }
            issues(states: [OPEN]) {
              totalCount
            }
            pullRequests(states: [OPEN]) {
              totalCount
            }
          }
        }
        """
        
        try:
            result = self.client.execute_query(query, {"owner": owner, "name": name})
            return result.get("data", {}).get("repository")
        except Exception as e:
            logging.error(f"Error getting repository details: {e}")
            return None
