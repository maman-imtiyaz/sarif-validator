import json
import sys

FILENAME = "findings.json"

# Helper for pretty output
def print_pass(msg):
    print(f"[PASS] {msg}")

def main():
    try:
        with open(FILENAME, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load or parse {FILENAME}: {e}")
        sys.exit(1)

    # SARIF structure: runs[0].results
    try:
        results = data["runs"][0]["results"]
    except (KeyError, IndexError) as e:
        print(f"[ERROR] SARIF structure is invalid or missing results: {e}")
        sys.exit(1)

    # 1. Assert exactly 6 findings
    assert len(results) == 6, f"Expected 6 findings, found {len(results)}"
    print_pass("File contains exactly 6 findings.")

    # 2. SQL Injection finding checks
    sql_rule_id = "php.lang.security.injection.tainted-sql-string.tainted-sql-string"
    sql_findings = [r for r in results if r.get("ruleId") == sql_rule_id]
    assert sql_findings, f"No finding with ruleId '{sql_rule_id}' found."
    for finding in sql_findings:
        # Level is "error"
        assert finding.get("level") == "error", f"SQL Injection finding level is not 'error'"
        print_pass("SQL Injection finding has level 'error'.")
        # security-severity > 8.0
        severity = float(finding.get("properties", {}).get("security-severity", 0))
        assert severity > 8.0, f"SQL Injection finding security-severity is not > 8.0 (got {severity})"
        print_pass(f"SQL Injection finding security-severity is {severity} (>8.0).")
        # issue_owner is "tmalbos"
        owner = finding.get("properties", {}).get("issue_owner")
        assert owner == "tmalbos", f"SQL Injection finding issue_owner is not 'tmalbos' (got {owner})"
        print_pass("SQL Injection finding issue_owner is 'tmalbos'.")
        # Located in index.php
        locations = finding.get("locations", [])
        assert any(loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri") == "index.php" for loc in locations), "SQL Injection finding is not located in index.php"
        print_pass("SQL Injection finding is located in index.php.")

    # 3. package.json findings checks
    pkg_rule_id = "json.npm.security.package-dependencies-check.package-dependencies-check"
    pkg_findings = [r for r in results if r.get("ruleId") == pkg_rule_id]
    assert pkg_findings, f"No finding with ruleId '{pkg_rule_id}' found."
    for finding in pkg_findings:
        owner = finding.get("properties", {}).get("issue_owner")
        assert owner == "Jose", f"package.json finding issue_owner is not 'Jose' (got {owner})"
        print_pass("package.json finding issue_owner is 'Jose'.")

    print("\nAll SARIF validation checks passed successfully.")

if __name__ == "__main__":
    main() 