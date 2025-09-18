#!/bin/bash
set -e

# Set Python path
export PYTHONPATH=/app:$PYTHONPATH

# Create required directories
mkdir -p /app/shaihulu_reports

# Run the scanner with debug output
set -x
python3 /app/scan_ShaiHulu.py --org "$GITHUB_ORG" --output-dir /app/shaihulu_reports -v
