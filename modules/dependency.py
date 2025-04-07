from graphviz import Digraph
import os
import subprocess
from collections import defaultdict

def visualize_dependency_tree(dependencies, output_folder, scan_uuid):
    """Visualize the dependency tree and save it with a UUID-based filename."""
    filename = f"dependency_graph_{scan_uuid}.png"
    output_path = os.path.join(output_folder, filename)
    os.makedirs(output_folder, exist_ok=True)  # Ensure the folder exists

    dot = Digraph(comment="Dependency Tree")

    # Assuming dependencies is a dictionary of package -> list of dependencies
    for package, deps in dependencies.items():
        dot.node(package)  # Add a node for the main package
        
        # Add nodes and edges for each dependency
        for dep in deps:
            dot.node(dep)  # Add a node for the dependency
            dot.edge(package, dep)  # Draw an edge from the package to its dependency

    # Render the graph to the specified path
    dot.render(output_path.replace(".png", ""), format="png", cleanup=True)
    return filename

def build_dependency_tree(requirements):
    """Simulate a dependency tree from the requirements."""
    dependency_tree = defaultdict(list)
    
    # Iterate through each package in the requirements
    for package in requirements.keys():
        try:
            # Run the 'pip show' command to get package details
            result = subprocess.run(
                ["pip", "show", package], stdout=subprocess.PIPE, text=True
            )
            if result.returncode == 0:
                # Parse the 'Requires' field for dependencies
                for line in result.stdout.splitlines():
                    if line.startswith("Requires"):
                        dependencies = line.split(":")[1].strip().split(", ")
                        dependency_tree[package].extend(dep.strip() for dep in dependencies if dep)
            else:
                print(f"Error: 'pip show {package}' failed with return code {result.returncode}.")
        except Exception as e:
            print(f"Error fetching dependencies for {package}: {e}")
    
    return dependency_tree
