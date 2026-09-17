# Secure Coding Review

## 1. Project Overview

This project performs a security audit of a Python Flask web application.

Two versions of the application are included:

- `vulnerable_app.py` - intentionally vulnerable version used for security testing.
- `secure_app.py` - remediated version containing secure coding practices.

The objective is to identify security vulnerabilities, analyze them using static analysis tools and manual code review, and apply appropriate remediation techniques.

---

## 2. Technologies Used

- Python
- Flask
- SQLite
- Bandit
- Semgrep
- Werkzeug
- JSON

---

## 3. Security Testing Methodology

The application was reviewed using:

1. Manual source-code inspection
2. Bandit static security analysis
3. Semgrep static security analysis
4. Comparison of vulnerable and remediated source code

The vulnerable application was scanned first to identify security issues. The secure application was then scanned again to verify that the vulnerabilities had been remediated.

---

# 4. Tools Used

## 4.1 Bandit

Bandit is a Python security linter used to identify common security problems in Python source code.

Command used:

```text
python -m bandit -r vulnerable_app.py