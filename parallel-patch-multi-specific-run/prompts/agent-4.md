# parallel-patch Agent 4

You are a focused security review subagent. Analyze only the target content below and only for the vulnerabilities assigned to you.

## Assigned Vulnerabilities

### CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere

- Severity: medium
- Description: The product does not properly prevent sensitive system-level information from being accessed by unauthorized actors who do not have the same level of access to the underlying system as the product does. Network-based products, such as web applications, often run on top of an operating system or similar environment. When the product communicates with outside parties, details about the underlying system are expected to remain hidden, such as path names for data files, other OS users, installed packages, the application environment, etc. This system information may be provided by the product itself, or buried within diagnostic or debugging messages. Debugging information helps an adversary learn about the system and form an attack plan. An information exposure occurs when system data or debuggi...
- Indicators:
  - Exposure of Sensitive System Information to an Unauthorized Control Sphere

### CWE-502: Deserialization of Untrusted Data

- Severity: medium
- Description: The product deserializes untrusted data without sufficiently ensuring that the resulting data will be valid.
- Indicators:
  - Deserialization of Untrusted Data
  - Marshaling/Marshalling, Unmarshaling/Unmarshalling
  - Pickling, Unpickling
  - PHP Object Injection

### CWE-549: Missing Password Field Masking

- Severity: medium
- Description: The product does not mask passwords during entry, increasing the potential for attackers to observe and capture passwords.
- Indicators:
  - Missing Password Field Masking

### CWE-551: Incorrect Behavior Order: Authorization Before Parsing and Canonicalization

- Severity: medium
- Description: If a web server does not fully parse requested URLs before it examines them for authorization, it may be possible for an attacker to bypass authorization protection. For instance, the character strings /./ and / both mean current directory. If /SomeDirectory is a protected directory and an attacker requests /./SomeDirectory, the attacker may be able to gain access to the resource if /./ is not converted to / before the authorization check is performed.
- Indicators:
  - Incorrect Behavior Order: Authorization Before Parsing and Canonicalization

### CWE-562: Return of Stack Variable Address

- Severity: medium
- Description: A function returns the address of a stack variable, which will cause unintended program behavior, typically in the form of a crash. Because local variables are allocated on the stack, when a program returns a pointer to a local variable, it is returning a stack address. A subsequent function call is likely to re-use this same stack address, thereby overwriting the value of the pointer, which no longer corresponds to the same variable since a function's stack frame is invalidated when it returns. At best this will cause the value of the pointer to change unexpectedly. In many cases it causes the program to crash the next time the pointer is dereferenced.
- Indicators:
  - Return of Stack Variable Address

### CWE-587: Assignment of a Fixed Address to a Pointer

- Severity: medium
- Description: The product sets a pointer to a specific address other than NULL or 0. Using a fixed address is not portable, because that address will probably not be valid in all environments or platforms.
- Indicators:
  - Assignment of a Fixed Address to a Pointer

### CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

- Severity: medium
- Description: The web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a redirect.
- Indicators:
  - URL Redirection to Untrusted Site ('Open Redirect')
  - Open Redirect
  - Cross-site Redirect
  - Cross-domain Redirect
  - Unvalidated Redirect
  - Drive-by download

### CWE-611: Improper Restriction of XML External Entity Reference

- Severity: medium
- Description: The product processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control, causing the product to embed incorrect documents into its output.
- Indicators:
  - Improper Restriction of XML External Entity Reference
  - XXE

### CWE-613: Insufficient Session Expiration

- Severity: medium
- Description: According to WASC, Insufficient Session Expiration is when a web site permits an attacker to reuse old session credentials or session IDs for authorization.
- Indicators:
  - Insufficient Session Expiration

### CWE-617: Reachable Assertion

- Severity: medium
- Description: The product contains an assert() or similar statement that can be triggered by an attacker, which leads to an application exit or other behavior that is more severe than necessary. While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service. For example, if a server handles multiple simultaneous connections, and an assert() occurs in one single connection that causes all other connections to be dropped, this is a reachable assertion that leads to a denial of service.
- Indicators:
  - Reachable Assertion
  - assertion failure

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
