#!/usr/bin/env python3
"""
Compare vulnerable packages from npm_vulnerability_report.json with packages in shaihulupkg.txt
"""
import json
import re
from typing import Dict, List, Set, Tuple

def load_shaihulu_packages(filepath: str) -> Set[str]:
    """Load package names from shaihulupkg.txt"""
    packages = set()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                # Extract package name (everything before the first space or parenthesis)
                if line.strip() and not line.startswith(' '):
                    pkg_name = line.split(' ')[0].split('(')[0].strip()
                    if pkg_name:
                        packages.add(pkg_name.lower())
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
    return packages

def extract_package_name_from_context(context: str) -> str:
    """Extract package name from vulnerability context"""
    # Look for patterns like "in package @package/name" or "in @package/name"
    patterns = [
        r'in (?:package\s+)?(@?[\w-]+(?:/[@\w-]+)*)',
        r'package (@?[\w-]+(?:/[@\w-]+)*) has',
        r'(@?[\w-]+(?:/[@\w-]+)*) is vulnerable',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, context, re.IGNORECASE)
        if match:
            return match.group(1).lower()
    
    return ""

def main():
    # Load the npm vulnerability report
    try:
        with open('npm_vulnerability_report.json', 'r', encoding='utf-8') as f:
            vulnerability_data = json.load(f)
    except FileNotFoundError:
        print("Error: npm_vulnerability_report.json not found. Please run the vulnerability analysis first.")
        return
    
    # Load the shaihulu packages
    shaihulu_packages = load_shaihulu_packages('shaihulupkg.txt')
    
    # Find matches
    matches = []
    
    for repo in vulnerability_data:
        for vuln in repo.get('npm_vulnerabilities', []):
            context = vuln.get('context', '').lower()
            pkg_name = extract_package_name_from_context(context)
            
            if pkg_name and pkg_name in shaihulu_packages:
                matches.append({
                    'repository': repo.get('repo', 'Unknown'),
                    'vulnerability_id': vuln.get('id', 'Unknown'),
                    'severity': vuln.get('severity', 'Unknown'),
                    'package': pkg_name,
                    'context': context[:200] + '...' if len(context) > 200 else context
                })
    
    # Print results
    if matches:
        print("\nVulnerable Packages Found in shaihulupkg.txt:")
        print("=" * 80)
        
        for i, match in enumerate(matches, 1):
            print(f"\n{i}. Repository: {match['repository']}")
            print(f"   Package: {match['package']}")
            print(f"   Vulnerability ID: {match['vulnerability_id']}")
            print(f"   Severity: {match['severity']}")
            print(f"   Context: {match['context']}")
            print("-" * 80)
        
        # Generate summary
        unique_packages = {match['package'] for match in matches}
        unique_repos = {match['repository'] for match in matches}
        
        print(f"\nSummary:")
        print(f"- Total matches: {len(matches)}")
        print(f"- Unique vulnerable packages: {len(unique_packages)}")
        print(f"- Affected repositories: {len(unique_repos)}")
        
        # Save detailed report
        with open('vulnerable_packages_report.md', 'w', encoding='utf-8') as f:
            f.write("# Vulnerable Packages Report\n\n")
            f.write("## Packages from shaihulupkg.txt with Known Vulnerabilities\n\n")
            f.write("| # | Repository | Package | Vulnerability ID | Severity |\n")
            f.write("|---|------------|---------|------------------|-----------|\n")
            
            for i, match in enumerate(matches, 1):
                f.write(f"| {i} | {match['repository']} | {match['package']} | {match['vulnerability_id']} | {match['severity']} |\n")
            
            f.write("\n## Summary\n\n")
            f.write(f"- **Total matches**: {len(matches)}\n")
            f.write(f"- **Unique vulnerable packages**: {len(unique_packages)}\n")
            f.write(f"- **Affected repositories**: {len(unique_repos)}\n")
            
            f.write("\n## Recommended Actions\n\n")
            f.write("1. Update the affected packages to their latest secure versions.\n")
            f.write("2. Run security audits on the affected repositories.\n")
            f.write("3. Consider using Dependabot or similar tools for automated dependency updates.\n")
            f.write("4. Review the security advisories for each vulnerability.\n")
            
        print("\nDetailed report saved to: vulnerable_packages_report.md")
    else:
        print("No vulnerable packages from shaihulupkg.txt were found in the vulnerability reports.")

if __name__ == "__main__":
    main()
