import argparse
import json
import os
from pathlib import Path

def build_dependency_tree(dependency, indent="", is_last=True, current_vulnerability=None):
    """
    Recursively build a Maven-style dependency tree string with proper formatting.
    """
    prefix = "└─ " if is_last else "├─ "

    current_line = f"{indent}{prefix}{dependency.get('name', 'unknown-artifact')}"
    vulnerabilities = dependency.get("vulnerabilities", [])

    # Annotate all vulnerabilities if writing a full graph
    if vulnerabilities and current_vulnerability is None:
        vuln_names = ", ".join(v.get("name", "") for v in vulnerabilities)
        current_line += f" ({vuln_names})"

    # Annotate only the current vulnerability if specified
    elif current_vulnerability and any(v.get("name") == current_vulnerability for v in vulnerabilities):
        current_line += f" ({current_vulnerability})"

    # Recursively process children
    children = dependency.get("children", [])
    lines = [current_line]
    for i, child in enumerate(children):
        new_indent = indent + ("   " if is_last else "|  ")
        lines.append(build_dependency_tree(child, new_indent, i == len(children) - 1, current_vulnerability))

    return "\n".join(lines)

def find_vulnerable_dependencies(dependencies):
    """
    Traverse dependencies to find those with vulnerabilities.
    """
    vulnerable_dependencies = []

    def traverse(dep):
        vulnerabilities = dep.get("vulnerabilities", [])
        if vulnerabilities:
            vulnerable_dependencies.append(dep)
        for child in dep.get("children", []):
            traverse(child)

    for dependency in dependencies:
        traverse(dependency)

    return vulnerable_dependencies

def detect_tool_type(dependency):
    """
    Determine tool type (e.g., gradle, yarn) from dependency file.
    """
    dep_file = dependency.get("dependencyFile", "").lower()
    if "build.gradle" in dep_file or "build.gradle.kts" in dep_file:
        return "gradle"
    elif "yarn.lock" in dep_file:
        return "yarn"
    else:
        return "unknown"

def group_by_tool_type(dependencies):
    """
    Group dependencies by their tool type.
    """
    grouped = {}
    for dep in dependencies:
        tool_type = detect_tool_type(dep)
        if tool_type not in grouped:
            grouped[tool_type] = []
        grouped[tool_type].append(dep)
    return grouped

def create_sarif(vulnerable_dependencies, dependencies_by_tool):
    """
    Create a SARIF object from the vulnerable dependencies.
    """
    results = []
    rules = []
    processed_issues = set()  # To track unique (dependency, vulnerability) pairs
    rule_ids = set()

    for dep in vulnerable_dependencies:
        name = dep.get("name", "unknown-artifact")
        vulnerabilities = dep.get("vulnerabilities", [])
        tool_type = detect_tool_type(dep)
        tool_deps = dependencies_by_tool.get(tool_type, [])

        for vuln in vulnerabilities:
            vuln_id = vuln.get("name", "unknown-vulnerability")

            # Skip if this (dependency, vulnerability) combination is already processed
            if (name, vuln_id) in processed_issues:
                continue

            title = f"{name} is affected by {vuln_id}"
            topFix = vuln.get("topFix", {})
            fixResolution = topFix.get("fixResolution", "No title provided")
            cve_title = topFix.get("message", "No title provided")
            url = topFix.get("url", "No URL provided")
            score = vuln.get("score")
            severity = vuln.get("severity")

            # Add rule if not already added
            if vuln_id not in rule_ids:
                rules.append({
                    "id": vuln_id,
                    "name": title,
                    "shortDescription": {
                        "text": title
                    },
                    "fullDescription": {
                        "text": fixResolution
                    },
                    "helpUri": url,
                    "properties": {
                        # "precision": f"{score}",
                        "security-severity": f"{score}"
                        # "severity": score
                    }
                })
                rule_ids.add(vuln_id)

            # Build dependency tree for this specific vulnerability from correct tool group
            tree_for_sarif = "\n".join(
                build_dependency_tree(root_dep, is_last=(i == len(tool_deps) - 1), current_vulnerability=vuln_id)
                for i, root_dep in enumerate(tool_deps)
            )

            markdown_msg = f"<b>Recommendations for [{vuln_id}]({url}):</b><br/><br/>" \
                           f"* {fixResolution}.<br/><br/>";

            # if display_dependency_graph_link:
            #     markdown_msg += f"<b>[View dependency graphs]({github_url}/{github_repository}/actions/runs/{workflow_run})<br/>"

            # Add formatted details
            results.append({
                "ruleId": vuln_id,
                "message": {
                    "text": f"{title}",
                    "markdown": markdown_msg
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": dep.get("dependencyFile", "unknown-file")
                            }
                        }
                    }
                ],
                "properties": {
                    "vulnerability": {
                        "id": vuln_id,
                        "severity": score,
                        "description": cve_title,  # CVE title as the description
                        "url": url
                    }
                }
            })

            # Mark this issue as processed
            processed_issues.add((name, vuln_id))

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Mend: Dependency Scanner",
                        "rules": rules
                    }
                },
                "results": results
            }
        ]
    }
    return sarif

def write_dependency_graphs(dependencies_by_tool):
    """
    Write each dependency graph to a separate file based on tool type.
    """
    output_dir = Path("dependency-graphs")
    output_dir.mkdir(exist_ok=True)

    for tool_type, deps in dependencies_by_tool.items():
        tree = "\n".join(
            build_dependency_tree(dep, is_last=(i == len(deps) - 1), current_vulnerability=None)
            for i, dep in enumerate(deps)
        )
        filename = output_dir / f"dependency-graph-{tool_type}.txt"
        with open(filename, "w") as f:
            f.write(tree)
        print(f"📜 Dependency graph written to: {filename}")

def main(input_file, output_file):

    """
    Main script function.
    """
    # Load the JSON input file
    with open(input_file, 'r') as f:
        dependencies_data = json.load(f)

    # Ensure proper JSON structure
    if not isinstance(dependencies_data, list):
        raise ValueError("Unexpected JSON structure: Root must be a list.")

    # Group dependencies by tool type (e.g., gradle, yarn)
    dependencies_by_tool = group_by_tool_type(dependencies_data)

    # Build and print full Maven-style dependency tree per tool type
    print("\nGenerated Full Dependency Trees:")
    for tool_type, deps in dependencies_by_tool.items():
        print(f"\nTool: {tool_type}")
        print("\n".join(
            build_dependency_tree(dep, is_last=(i == len(deps) - 1), current_vulnerability=None)
            for i, dep in enumerate(deps)
        ))

    # Write dependency graphs to files per tool
    write_dependency_graphs(dependencies_by_tool)

    # Find vulnerable dependencies
    vulnerable_dependencies = find_vulnerable_dependencies(dependencies_data)
    if not vulnerable_dependencies:
        print("No vulnerabilities found.")
        return

    # Create SARIF output
    sarif_data = create_sarif(vulnerable_dependencies, dependencies_by_tool)

    # Write SARIF to output file
    try:
        with open(output_file, 'w') as f:
            json.dump(sarif_data, f, indent=2)
        print(f"\nSARIF file successfully created at: {output_file}")
    except IOError as e:
        print(f"Failed to write SARIF file: {e}")

if __name__ == "__main__":
    global display_dependency_graph_link
    global github_url
    global github_repository
    global workflow_run

    parser = argparse.ArgumentParser(description="Convert dependencies to SARIF with optional GitHub workflow link.")
    parser.add_argument("--display-dependency-graph-link", default="true", help="Whether to display a link to the dependency graph")
    parser.add_argument("--github-url", help="The GitHub host URL")
    parser.add_argument("--github-repository", help="The GitHub repository owner/name")
    parser.add_argument("--input", default="dependencies.json", help="Path to input JSON file")
    parser.add_argument("--output", default="results.sarif", help="Path to output SARIF file")
    parser.add_argument("--workflow-run", help="GitHub Actions workflow run ID")
    args = parser.parse_args()

    display_dependency_graph_link = args.display_dependency_graph_link
    github_url = args.github_url
    github_repository = args.github_repository
    workflow_run = args.workflow_run

    main(args.input, args.output)
