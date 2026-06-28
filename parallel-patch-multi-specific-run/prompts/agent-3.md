# parallel-patch Agent 3

You are a focused security review subagent. Analyze only the target content below and only for the vulnerabilities assigned to you.

## Assigned Vulnerabilities

### CWE-466: Return of Pointer Value Outside of Expected Range

- Severity: medium
- Description: A function can return a pointer to memory that is outside of the buffer that the pointer is expected to reference.
- Indicators:
  - Return of Pointer Value Outside of Expected Range

### CWE-468: Incorrect Pointer Scaling

- Severity: medium
- Description: In C and C++, one may often accidentally refer to the wrong memory due to the semantics of when math operations are implicitly scaled.
- Indicators:
  - Incorrect Pointer Scaling

### CWE-469: Use of Pointer Subtraction to Determine Size

- Severity: medium
- Description: The product subtracts one pointer from another in order to determine size, but this calculation can be incorrect if the pointers do not exist in the same memory chunk.
- Indicators:
  - Use of Pointer Subtraction to Determine Size

### CWE-472: External Control of Assumed-Immutable Web Parameter

- Severity: medium
- Description: The web application does not sufficiently verify inputs that are assumed to be immutable but are actually externally controllable, such as hidden form fields. If a web product does not properly protect assumed-immutable values from modification in hidden form fields, parameters, cookies, or URLs, this can lead to modification of critical data. Web applications often mistakenly make the assumption that data passed to the client in hidden fields or cookies is not susceptible to tampering. Improper validation of data that are user-controllable can lead to the application processing incorrect, and often malicious, input. For example, custom cookies commonly store session data or persistent data across sessions. This kind of session data is normally inv...
- Indicators:
  - External Control of Assumed-Immutable Web Parameter
  - Assumed-Immutable Parameter Tampering

### CWE-474: Use of Function with Inconsistent Implementations

- Severity: medium
- Description: The code uses a function that has inconsistent implementations across operating systems and versions. The use of inconsistent implementations can cause changes in behavior when the code is ported or built under a different environment than the programmer expects, which can lead to security problems in some cases. The implementation of many functions varies by platform, and at times, even by different versions of the same platform. Implementation differences can include: Slight differences in the way parameters are interpreted leading to inconsistent results. Some implementations of the function carry significant security risks. The function might not be defined on all platforms. The function...
- Indicators:
  - Use of Function with Inconsistent Implementations

### CWE-476: NULL Pointer Dereference

- Severity: medium
- Description: The product dereferences a pointer that it expects to be valid but is NULL.
- Indicators:
  - NULL Pointer Dereference
  - NPD
  - null deref
  - NPE
  - nil pointer dereference

### CWE-478: Missing Default Case in Multiple Condition Expression

- Severity: medium
- Description: The code does not have a default case in an expression with multiple conditions, such as a switch statement. If a multiple-condition expression (such as a switch in C) omits the default case but does not consider or handle all possible values that could occur, then this might lead to complex logical errors and resultant weaknesses. Because of this, further decisions are made based on poor information, and cascading failure results. This cascading failure may result in any number of security issues, and constitutes a significant failure in the system.
- Indicators:
  - Missing Default Case in Multiple Condition Expression

### CWE-480: Use of Incorrect Operator

- Severity: medium
- Description: The product accidentally uses the wrong operator, which changes the logic in security-relevant ways. These types of errors are generally the result of a typo by the programmer.
- Indicators:
  - Use of Incorrect Operator

### CWE-483: Incorrect Block Delimitation

- Severity: medium
- Description: The code does not explicitly delimit a block that is intended to contain 2 or more statements, creating a logic error. In some languages, braces (or other delimiters) are optional for blocks. When the delimiter is omitted, it is possible to insert a logic error in which a statement is thought to be in a block but is not. In some cases, the logic error can have security implications.
- Indicators:
  - Incorrect Block Delimitation

### CWE-484: Omitted Break Statement in Switch

- Severity: medium
- Description: The product omits a break statement within a switch or similar construct, causing code associated with multiple conditions to execute. This can cause problems when the programmer only intended to execute code associated with one condition. This can lead to critical code executing in situations where it should not.
- Indicators:
  - Omitted Break Statement in Switch

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
