# parallel-patch Agent 0

You are a focused security review subagent. Analyze only the target content below and only for the vulnerabilities assigned to you.

## Assigned Vulnerabilities

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

- Severity: medium
- Description: The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users. There are many variants of cross-site scripting, characterized by a variety of terms or involving different attack topologies. However, they all indicate the same fundamental weakness: improper neutralization of dangerous input between the adversary and a victim.
- Indicators:
  - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
  - Cross-site Scripting
  - XSS
  - HTML Injection
  - Reflected XSS / Non-Persistent XSS / Type 1 XSS
  - Stored XSS / Persistent XSS / Type 2 XSS
  - DOM-Based XSS / Type 0 XSS
  - CSS

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

- Severity: medium
- Description: The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component. Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.
- Indicators:
  - Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
  - SQL Injection
  - SQLi

### CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')

- Severity: medium
- Description: The product constructs all or part of an LDAP query using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended LDAP query when it is sent to a downstream component.
- Indicators:
  - Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')
  - LDAP Injection

### CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')

- Severity: medium
- Description: The product copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.
- Indicators:
  - Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
  - Classic Buffer Overflow
  - Unbounded Transfer

### CWE-124: Buffer Underwrite ('Buffer Underflow')

- Severity: medium
- Description: The product writes to a buffer using an index or pointer that references a memory location prior to the beginning of the buffer.
- Indicators:
  - Buffer Underwrite ('Buffer Underflow')
  - Buffer Underflow
  - buffer underrun

### CWE-125: Out-of-bounds Read

- Severity: medium
- Description: The product reads data past the end, or before the beginning, of the intended buffer.
- Indicators:
  - Out-of-bounds Read
  - OOB read

### CWE-128: Wrap-around Error

- Severity: medium
- Description: Wrap around errors occur whenever a value is incremented past the maximum value for its type and therefore wraps around to a very small, negative, or undefined value.
- Indicators:
  - Wrap-around Error

### CWE-130: Improper Handling of Length Parameter Inconsistency

- Severity: medium
- Description: The product parses a formatted message or structure, but it does not handle or incorrectly handles a length field that is inconsistent with the actual length of the associated data. If an attacker can manipulate the length parameter associated with an input such that it is inconsistent with the actual length of the input, this can be leveraged to cause the target application to behave in unexpected, and possibly, malicious ways. One of the possible motives for doing so is to pass in arbitrarily large input to the application. Another possible motivation is the modification of application state by including invalid data for subsequent properties of the application. Such weaknesses commonly lead to attacks such as buffer overflows and execution of arbitrary code.
- Indicators:
  - Improper Handling of Length Parameter Inconsistency
  - length manipulation
  - length tampering

### CWE-131: Incorrect Calculation of Buffer Size

- Severity: medium
- Description: The product does not correctly calculate the size to be used when allocating a buffer, which could lead to a buffer overflow.
- Indicators:
  - Incorrect Calculation of Buffer Size

### CWE-134: Use of Externally-Controlled Format String

- Severity: medium
- Description: The product uses a function that accepts a format string as an argument, but the format string originates from an external source.
- Indicators:
  - Use of Externally-Controlled Format String

## Target Content

### backend/app.py

```text
2:     query = f"SELECT * FROM users WHERE name = '{term}'"
3:     return db.execute(query)
5: 
6: def load_user(payload):
7:     user.__dict__.update(payload)
```

### web/profile.js

```text
2:   document.querySelector("#name").innerHTML = user.name;
3:   fetch(user.avatarUrl).then((r) => r.text());
```

### db/migrations/001_add_search.sql

```text
1: CREATE FUNCTION find_user(term text) RETURNS SETOF users AS $$
2:   SELECT * FROM users WHERE name = term;
3: $$ LANGUAGE SQL;
```

### native/parser.c

```text
2:   char buf[32];
3:   strcpy(buf, input);
```

## Rules

- Report only vulnerabilities from your assigned list.
- Prefer findings on changed diff lines when the target is a patch.
- Do not report style, quality, dependency, or unrelated security issues.
- Use exact file paths and line numbers from the target content.
- Return only a JSON array. Do not include Markdown fences, prose, or a summary.
- If there are no findings, return [].

## Output Schema

[
  {
    "vulnerability_id": "CWE-89",
    "vulnerability_name": "SQL Injection",
    "file": "src/db.py",
    "line_start": 42,
    "line_end": 42,
    "severity": "critical",
    "confidence": "high",
    "description": "User input is interpolated into a SQL query.",
    "suggested_fix": "Use parameterized queries."
  }
]
