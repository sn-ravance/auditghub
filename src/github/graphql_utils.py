"""
GraphQL utilities for GitHub API with rate limiting and caching.
"""
import json
import logging
import os
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Any, Dict, List, Optional, Union

import requests
from cachetools import TTLCache
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Cache with 1-hour TTL
GRAPHQL_CACHE = TTLCache(maxsize=100, ttl=3600)

class GraphQLClient:
    def __init__(self, token: str, api_url: str = "https://api.github.com/graphql"):
        self.api_url = api_url
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create a session with retry logic."""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["POST", "GET"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        return session

    @lru_cache(maxsize=100)
    def execute_query(
        self,
        query: str,
        variables: Optional[Dict[str, Any]] = None,
        operation_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute a GraphQL query with caching.
        
        Args:
            query: The GraphQL query string
            variables: Dictionary of variables for the query
            operation_name: Optional operation name for the query
            
        Returns:
            Dict containing the query result
        """
        cache_key = self._generate_cache_key(query, variables, operation_name)
        
        # Check cache first
        if cache_key in GRAPHQL_CACHE:
            return GRAPHQL_CACHE[cache_key]
            
        # Execute the query
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        if operation_name:
            payload["operationName"] = operation_name
            
        try:
            response = self.session.post(
                self.api_url,
                headers=self.headers,
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            
            # Cache successful responses
            if not data.get("errors"):
                GRAPHQL_CACHE[cache_key] = data
                
            return data
            
        except requests.exceptions.RequestException as e:
            logging.error(f"GraphQL query failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logging.error(f"Response: {e.response.text}")
            raise

    def _generate_cache_key(
        self,
        query: str,
        variables: Optional[Dict[str, Any]] = None,
        operation_name: Optional[str] = None,
    ) -> str:
        """Generate a cache key for the query."""
        key_parts = [query]
        if variables:
            key_parts.append(json.dumps(variables, sort_keys=True))
        if operation_name:
            key_parts.append(operation_name)
        return "|".join(key_parts)

    def get_rate_limit(self) -> Dict[str, Any]:
        """Get current rate limit information."""
        query = """
        query {
          rateLimit {
            limit
            cost
            remaining
            resetAt
            used
            nodeCount
          }
        }
        """
        result = self.execute_query(query)
        return result.get("data", {}).get("rateLimit", {})
