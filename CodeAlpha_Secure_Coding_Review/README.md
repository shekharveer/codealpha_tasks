CodeAlpha_Secure_Coding_Review

## Overview

This project is part of the CodeAlpha Cybersecurity Internship.

The project performs a security audit of a Python Flask web application. An intentionally vulnerable application was analyzed using static analysis tools and manual code review. A secure version was then created to remediate the identified vulnerabilities.

## Objectives

- Identify security vulnerabilities in Python code.
- Perform manual source-code inspection.
- Use static analysis tools.
- Remediate identified vulnerabilities.
- Verify the security improvements using automated scanning.
- Document findings and remediation steps.

## Project Structure

```text
CodeAlpha_Secure_Coding_Review/
│
├── vulnerable_app.py
├── secure_app.py
├── requirements.txt
│
├── bandit_report.txt
├── secure_bandit_report.txt
├── semgrep_report.json
├── secure_semgrep_report.json
│
├── security_report.md
├── README.md
│
└── docs/