# SARIF API Validator

This script checks the findings.json file exported from the SARIF API. Just run:

```bash
python3 sarif_validator.py
```
The Results
```bash
[PASS] File contains exactly 6 findings.
[PASS] SQL Injection finding has level 'error'.
[PASS] SQL Injection finding security-severity is 8.7 (>8.0).
[PASS] SQL Injection finding issue_owner is 'tmalbos'.
[PASS] SQL Injection finding is located in index.php.
[PASS] package.json finding issue_owner is 'Jose'.
[PASS] package.json finding issue_owner is 'Jose'.
    
All SARIF validation checks passed successfully.
```

If everything meets the standard, you'll see success messages. If something is wrong, the script will tell you what needs fixing.

Make sure you have Python 3 installed. No extra libraries needed. 
