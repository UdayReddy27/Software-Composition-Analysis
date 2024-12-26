import os
import json
from collections import defaultdict
from graphviz import Digraph
from license_expression import Licensing, ExpressionError
import subprocess
from packaging.version import Version
from packaging.specifiers import SpecifierSet

# INPUT_FILE = "hello.py"

# Constants
LICENSE_COMPLIANCE = ["MIT", "Apache-2.0", "BSD-3-Clause"]
LOCAL_VULNERABILITY_DB = "vulnerability_mapping.json"  # JSON file with known vulnerabilities

# Function to scan package folder
def scan_local_packages(directory):
    """Scan a local directory for installed Python packages and their versions."""
    packages = {}
    for root, dirs, files in os.walk(directory):
        if "METADATA" in files:
            metadata_path = os.path.join(root, "METADATA")
            with open(metadata_path, "r", encoding="utf-8") as f:
                package_name, version = None, None
                for line in f:
                    if line.startswith("Name:"):
                        package_name = line.split(":", 1)[1].strip()
                    elif line.startswith("Version:"):
                        version = line.split(":", 1)[1].strip()
                    if package_name and version:
                        packages[package_name] = version
                        break
    return packages

# Vulnerability Checker with Mapping
def check_vulnerabilities_local(package, version):
    """Check vulnerabilities for a package using a local mapping database."""
    if not os.path.exists(LOCAL_VULNERABILITY_DB):
        print(f"Warning: Local vulnerability database '{LOCAL_VULNERABILITY_DB}' not found.")
        return []
    
    with open(LOCAL_VULNERABILITY_DB, "r") as f:
        vulnerability_data = json.load(f)

    if package not in vulnerability_data["vulnerabilities"]:
        return []

    vulnerabilities = []
    for vuln in vulnerability_data["vulnerabilities"][package]:
        specifier_set = SpecifierSet(",".join(vuln["versions"]))
        if Version(version) in specifier_set:
            vulnerabilities.append(vuln)
    return vulnerabilities

# License Compliance Checker
def check_license(package, directory):
    """Check the license of a package using local metadata.json files."""
    for root, dirs, files in os.walk(directory):
        if "metadata.json" in files:
            metadata_path = os.path.join(root, "metadata.json")
            with open(metadata_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)
                # Check if this metadata corresponds to the desired package
                if metadata.get("name") == package:
                    return metadata.get("license")
    return None

def is_license_compliant(license_info):
    """Check if the license is compliant."""
    licensing = Licensing()
    try:
        parsed_license = licensing.parse(license_info)
        for license in LICENSE_COMPLIANCE:
            if licensing.parse(license) in parsed_license:
                return True
    except ExpressionError as e:
        print(f"Invalid license expression: {license_info}. Error: {e}")
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

def read_packages_from_file(file_path):
    """Read package names and versions from a file."""
    if not os.path.exists(file_path):
        print(f"Error: Input file '{file_path}' not found.")
        return {}
    
    packages = {}
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue  # Skip empty lines and comments
            parts = line.split("==")
            package_name = parts[0].strip()
            package_version = parts[1].strip() if len(parts) > 1 else None
            packages[package_name] = package_version
    return packages





import xml.etree.ElementTree as ET

# Function to scan Java packages from Maven (pom.xml) and Gradle (build.gradle)
def scan_java_packages(directory):
    """Scan Java packages from pom.xml or build.gradle."""
    packages = {}

    # Scan pom.xml for Maven dependencies
    pom_path = os.path.join(directory, "pom.xml")
    if os.path.exists(pom_path):
        tree = ET.parse(pom_path)
        root = tree.getroot()
        for dependency in root.findall(".//dependency"):
            group_id = dependency.find("groupId").text if dependency.find("groupId") is not None else "unknown"
            artifact_id = dependency.find("artifactId").text if dependency.find("artifactId") is not None else "unknown"
            version = dependency.find("version").text if dependency.find("version") is not None else "unknown"
            packages[f"{group_id}:{artifact_id}"] = version

    # Scan build.gradle for Gradle dependencies
    gradle_path = os.path.join(directory, "build.gradle")
    if os.path.exists(gradle_path):
        with open(gradle_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("implementation") or line.startswith("compile"):
                    parts = line.split("'")
                    if len(parts) > 1:
                        dependency = parts[1]
                        group_id, artifact_id, version = dependency.split(":")
                        packages[f"{group_id}:{artifact_id}"] = version

    return packages

# Function to scan C++ packages from CMakeLists.txt or vcpkg/conan manifests
def scan_cpp_packages(directory):
    """Scan C++ packages from CMakeLists.txt or vcpkg/conan manifests."""
    packages = {}

    # Scan CMakeLists.txt for dependencies
    cmake_path = os.path.join(directory, "CMakeLists.txt")
    if os.path.exists(cmake_path):
        with open(cmake_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("find_package"):
                    package_name = line.split("(")[1].split(")")[0]
                    packages[package_name] = "unknown"  # Version info is not in CMakeLists.txt

    # Scan vcpkg.json for vcpkg dependencies
    vcpkg_path = os.path.join(directory, "vcpkg.json")
    if os.path.exists(vcpkg_path):
        with open(vcpkg_path, "r", encoding="utf-8") as f:
            vcpkg_data = json.load(f)
            for dependency in vcpkg_data.get("dependencies", []):
                packages[dependency] = "unknown"  # vcpkg.json doesn't always specify versions

    # Scan conanfile.txt or conanfile.py for Conan dependencies
    conan_path = os.path.join(directory, "conanfile.txt")
    if os.path.exists(conan_path):
        with open(conan_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                package = line.split("/")
                if len(package) > 1:
                    packages[package[0]] = package[1]  # Format: name/version

    return packages





# Main Program
def main():
    package_dir = "local_packages"
    
    if not os.path.exists(package_dir):
        print(f"Error: {package_dir} not found.")
        return
    
    print("Scanning for Python packages...")
    python_packages = scan_local_packages(package_dir)
    print(f"Found {len(python_packages)} Python packages.")
    
    print("Scanning for Java packages...")
    java_packages = scan_java_packages(package_dir)
    print(f"Found {len(java_packages)} Java packages.")
    
    print("Scanning for C++ packages...")
    cpp_packages = scan_cpp_packages(package_dir)
    print(f"Found {len(cpp_packages)} C++ packages.")

    # Combine all packages
    all_packages = {
        **python_packages,
        **java_packages,
        **cpp_packages,
    }
    
    if not all_packages:
        print("No valid packages found in the local directory.")
        return
    
    # Scan for vulnerabilities and licenses
    for package, version in all_packages.items():
        print(f"\nPackage: {package} (Version: {version})")
        
        # Vulnerability Check
        vulnerabilities = check_vulnerabilities_local(package, version)
        if vulnerabilities:
            print("  Vulnerabilities:")
            for vuln in vulnerabilities:
                print(f"    - {vuln.get('summary', 'No summary available')} (ID: {vuln.get('id')})")
        else:
            print("  No known vulnerabilities found.")
        
        # License Check
        license_info = check_license(package, package_dir)
        if license_info:
            compliance = is_license_compliant(license_info)
            print(f"  License: {license_info} (Compliant: {compliance})")
        else:
            print("  License information not found.")

    # Dependency Tree Visualization
    print("\nBuilding dependency tree...")
    dependency_tree = build_dependency_tree(all_packages)
    visualize_dependency_tree(dependency_tree)
    print("Done!")
