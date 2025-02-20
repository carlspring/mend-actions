import json

def build_dependency_tree(dependency, indent="", is_last=True, current_vulnerability=None):
    """
    Recursively build a Maven-style dependency tree string with proper formatting.
    """
    prefix = "└─ " if is_last else "├─ "

    current_line = f"{indent}{prefix}{dependency.get('name', 'unknown-artifact')}"
    vulnerabilities = dependency.get("vulnerabilities", [])

    # Annotate only the current vulnerability if specified
    if current_vulnerability and any(v.get("name") == current_vulnerability for v in vulnerabilities):
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

def create_sarif(vulnerable_dependencies, dependencies):
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

            # Build dependency tree for this specific vulnerability
            tree_for_sarif = "\n".join(
                build_dependency_tree(dep, is_last=(i == len(dependencies) - 1), current_vulnerability=vuln_id)
                for i, dep in enumerate(dependencies)
            )

            # Add formatted details
            results.append({
                "ruleId": vuln_id,
                "message": {
                    "text": f"{title}",
                    "markdown": f"<b>Recommendations for [{vuln_id}]({url}):</b><br/><br/>"
                                f"* {fixResolution}.<br/><br/>"
                                f"<b>Dependency tree</b><br/><br/>"
                                f"{tree_for_sarif}<br/>"
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

    # Build the full Maven-style dependency tree
    full_dependency_tree = "\n".join(
        build_dependency_tree(dep, is_last=(i == len(dependencies_data) - 1))
        for i, dep in enumerate(dependencies_data)
    )

    print("\nGenerated Full Dependency Tree:")
    print(full_dependency_tree)

    # Find vulnerable dependencies
    vulnerable_dependencies = find_vulnerable_dependencies(dependencies_data)
    if not vulnerable_dependencies:
        print("No vulnerabilities found.")
        return

    # Create SARIF output
    sarif_data = create_sarif(vulnerable_dependencies, dependencies_data)

    # Write SARIF to output file
    try:
        with open(output_file, 'w') as f:
            json.dump(sarif_data, f, indent=2)
        print(f"\nSARIF file successfully created at: {output_file}")
    except IOError as e:
        print(f"Failed to write SARIF file: {e}")

if __name__ == "__main__":
    input_json = "dependencies.json"  # Path to input JSON
    output_sarif = "results.sarif"    # Path to output SARIF file
    main(input_json, output_sarif)
