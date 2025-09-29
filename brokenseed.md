# Database Seeding Script Fix: Schema Mismatch and Connection Issues

## Problem Description
The [seed_org_repos.py](cci:7://file:///Users/rob.vance@sleepnumber.com/Documents/GitHub/auditgh/scripts/seed_org_repos.py:0:0-0:0) script was failing to seed GitHub organization repositories into the database due to two main issues:

1. **Database Connection Failure**:
   - The script was trying to connect to a host named "db" which was only resolvable within the Docker network
   - The connection parameters didn't match the actual database configuration

2. **Schema Mismatch**:
   - The SQL query included columns (`is_private`, `is_archived`, `last_push_at`, `primary_language`) that didn't exist in the `projects` table
   - This caused a PostgreSQL error: `column "is_private" of relation "projects" does not exist`

## Root Cause Analysis

### Connection Issues
- The script was using a hardcoded hostname "db" which is only valid inside Docker's internal network
- The database port mapping (5434:5432) wasn't being respected in the connection string
- The script didn't have proper fallback values for database connection parameters

### Schema Mismatch
- The `projects` table schema in the database didn't match the fields the script was trying to insert
- The script was trying to insert GitHub-specific fields that weren't part of the application's data model
- No validation was in place to ensure the script's expectations matched the database schema

## Solution Implemented

### 1. Database Connection Fixes
- Changed the default host from "db" to "localhost" for local development
- Set the correct default port to 5434 (mapped from container's 5432)
- Added proper environment variable fallbacks for all database connection parameters
- Implemented connection error handling with meaningful error messages

### 2. Schema Alignment
- Updated the SQL query to only include columns that exist in the `projects` table:
  - Removed: `is_private`, `is_archived`, `last_push_at`, `primary_language`
  - Kept: `name`, `repo_url`, `description`, `created_at`, `updated_at`
- Modified the data preparation to only include fields that match the database schema
- Added null checks and default values for optional fields

### 3. Code Improvements
- Added better error handling and logging
- Improved configuration management with environment variables
- Added input validation for required fields
- Made the script more robust by handling edge cases (e.g., None values)

## Verification
The script was successfully tested and:
1. Connected to the database on localhost:5434
2. Fetched 2,068 repositories from the GitHub organization
3. Successfully inserted/updated all repositories in the database
4. Handled conflicts by updating existing records

## Prevention for Future Issues

### 1. Schema Validation
- Add a schema validation step at script startup
- Compare expected columns with actual database schema
- Provide clear error messages for schema mismatches

### 2. Configuration Management
- Create a configuration class with type hints
- Add validation for all configuration parameters
- Provide meaningful error messages for missing or invalid configuration

### 3. Testing
- Add unit tests for database operations
- Create integration tests with a test database
- Add CI/CD pipeline to catch schema mismatches early

### 4. Documentation
- Document the expected database schema
- Add example .env file
- Document required permissions and setup steps

## Example Fix
```python
# Before (problematic code)
cursor.execute("""
    INSERT INTO projects (
        name, repo_url, description,
        is_private, is_archived,  # These columns don't exist
        created_at, updated_at
    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
""", (name, url, desc, is_private, is_archived, created, updated))

# After (fixed code)
cursor.execute("""
    INSERT INTO projects (
        name, repo_url, description,
        created_at, updated_at
    ) VALUES (%s, %s, %s, %s, %s)
    ON CONFLICT (name) 
    DO UPDATE SET
        repo_url = EXCLUDED.repo_url,
        description = EXCLUDED.description,
        updated_at = NOW()
""", (name, url, desc or '', created, updated))
