import os
import requests
from collections import defaultdict
from graphviz import Digraph
from license_expression import Licensing, ExpressionError
import subprocess

# Constants
PYPI_API_URL = "https://pypi.org/pypi/{package}/json"
VULNERABILITY_DB_URL = "https://api.osv.dev/v1/query"
LICENSE_COMPLIANCE = ["MIT", "Apache-2.0", "BSD-3-Clause"]

# Function to Read requirements.txt
def read_requirements_file(file_path):
    """Parse a requirements.txt file and return a dictionary of packages with versions."""
    packages = {}
    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#"):  # Ignore empty lines and comments
                continue
            if "==" in line:
                try:
                    name, version = line.split("==")
                    packages[name.strip()] = version.strip()
                except ValueError:
                    print(f"Invalid format in requirements.txt: {line}")
            else:
                print(f"Ignoring line in requirements.txt (unsupported format): {line}")
    return packages

# Vulnerability Checker
def check_vulnerabilities(package, version):
    """Check vulnerabilities for a package using OSV.dev."""
    payload = {
        "package": {"name": package, "ecosystem": "PyPI"},
        "version": version,
    }
    try:
        response = requests.post(VULNERABILITY_DB_URL, json=payload)
        response.raise_for_status()
        return response.json().get("vulns", [])
    except requests.RequestException as e:
        print(f"Error checking vulnerabilities for {package}: {e}")
    return []

# License Compliance Checker
def check_license(package):
    """Check the license of a package."""
    try:
        response = requests.get(PYPI_API_URL.format(package=package))
        response.raise_for_status()
        info = response.json().get("info", {})
        license_info = info.get("license", "")
        if not license_info:
            license_info = info.get("classifiers", [])
        return license_info
    except requests.RequestException as e:
        print(f"Error fetching license information for {package}: {e}")
    return None

def is_license_compliant(license_info):
    """Check if the license is compliant."""
    licensing = Licensing()
    
    if isinstance(license_info, str):
        try:
            parsed_license = licensing.parse(license_info)
            for license in LICENSE_COMPLIANCE:
                if licensing.parse(license) in parsed_license:
                    return True
        except ExpressionError as e:
            print(f"Invalid license expression: {license_info}. Error: {e}")
    
    elif isinstance(license_info, list):
        for license_entry in license_info:
            try:
                parsed_license = licensing.parse(license_entry)
                for license in LICENSE_COMPLIANCE:
                    if licensing.parse(license) in parsed_license:
                        return True
            except ExpressionError as e:
                print(f"Invalid license expression in classifiers: {license_entry}. Error: {e}")
    
    return False

# Dependency Tree Visualization
def visualize_dependency_tree(packages):
    """Visualize the dependency tree."""
    dot = Digraph(comment="Dependency Tree")
    for package, dependencies in packages.items():
        dot.node(package)
        for dep in dependencies:
            dot.edge(package, dep)
    dot.render("dependency_tree", format="png")
    print("Dependency tree visualized as 'dependency_tree.png'")

def build_dependency_tree(requirements):
    """Simulate a dependency tree from the requirements."""
    dependency_tree = defaultdict(list)
    for package in requirements.keys():
        try:
            result = subprocess.run(
                ["pip", "show", package], stdout=subprocess.PIPE, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.startswith("Requires"):
                        dependencies = line.split(":")[1].strip().split(", ")
                        dependency_tree[package].extend(dep.strip() for dep in dependencies if dep)
            else:
                print(f"Error: 'pip show {package}' failed with return code {result.returncode}.")
        except Exception as e:
            print(f"Error fetching dependencies for {package}: {e}")
    return dependency_tree

# Main Program
def main():
    file_path = "sample.txt"
    
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found.")
        return
    
    requirements = read_requirements_file(file_path)
    if not requirements:
        print("No valid packages found in the requirements file.")
        return
    
    print(f"Found {len(requirements)} packages in {file_path}.")

    # Scan for vulnerabilities and licenses
    for package, version in requirements.items():
        print(f"\nPackage: {package} (Version: {version})")
        
        # Vulnerability Check
        vulnerabilities = check_vulnerabilities(package, version)
        if vulnerabilities:
            print("  Vulnerabilities:")
            for vuln in vulnerabilities:
                print(f"    - {vuln.get('summary', 'No summary available')} ({vuln.get('id')})")
        else:
            print("  No known vulnerabilities found.")
        
        # License Check
        license_info = check_license(package)
        if license_info:
            compliance = is_license_compliant(license_info)
            print(f"  License: {license_info} (Compliant: {compliance})")
        else:
            print("  License information not found.")

    # Dependency Tree Visualization
    print("\nBuilding dependency tree...")
    dependency_tree = build_dependency_tree(requirements)
    visualize_dependency_tree(dependency_tree)
    print("Done!")

if __name__ == "__main__":
    main()
