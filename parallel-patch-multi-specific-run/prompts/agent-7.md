# parallel-patch Agent 7

You are a focused security review subagent. Analyze only the target content below and only for the vulnerabilities assigned to you.

## Assigned Vulnerabilities

### CWE-843: Access of Resource Using Incompatible Type ('Type Confusion')

- Severity: medium
- Description: The product allocates or initializes a resource such as a pointer, object, or variable using one type, but it later accesses that resource using a type that is incompatible with the original type. When the product accesses the resource using an incompatible type, this could trigger logical errors because the resource does not have expected properties. In languages without memory safety, such as C and C++, type confusion can lead to out-of-bounds memory access. While this weakness is frequently associated with unions when parsing data with many different embedded object types in C, it can be present in any application that can interpret the same variable or memory location in multiple ways. This weakness is not unique to C and C++. For example, errors in PHP applications can be triggere...
- Indicators:
  - Access of Resource Using Incompatible Type ('Type Confusion')
  - Type Confusion
  - Object Type Confusion

### CWE-910: Use of Expired File Descriptor

- Severity: medium
- Description: The product uses or accesses a file descriptor after it has been closed. After a file descriptor for a particular file or device has been released, it can be reused. The code might not write to the original file, since the reused file descriptor might reference a different file or device.
- Indicators:
  - Use of Expired File Descriptor
  - Stale file descriptor

### CWE-911: Improper Update of Reference Count

- Severity: medium
- Description: The product uses a reference count to manage a resource, but it does not update or incorrectly updates the reference count. Reference counts can be used when tracking how many objects contain a reference to a particular resource, such as in memory management or garbage collection. When the reference count reaches zero, the resource can be de-allocated or reused because there are no more objects that use it. If the reference count accidentally reaches zero, then the resource might be released too soon, even though it is still in use. If all objects no longer use the resource, but the reference count is not zero, then the resource might not ever be released.
- Indicators:
  - Improper Update of Reference Count

### CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes

- Severity: medium
- Description: The product receives input from an upstream component that specifies multiple attributes, properties, or fields that are to be initialized or updated in an object, but it does not properly control which attributes can be modified. If the object contains attributes that were only intended for internal use, then their unexpected modification could lead to a vulnerability. This weakness is sometimes known by the language-specific mechanisms that make it possible, such as mass assignment, autobinding, or object injection.
- Indicators:
  - Improperly Controlled Modification of Dynamically-Determined Object Attributes
  - Mass Assignment
  - AutoBinding
  - PHP Object Injection

### CWE-918: Server-Side Request Forgery (SSRF)

- Severity: medium
- Description: The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.
- Indicators:
  - Server-Side Request Forgery (SSRF)
  - XSPA
  - SSRF

### CWE-1007: Insufficient Visual Distinction of Homoglyphs Presented to User

- Severity: medium
- Description: The product displays information or identifiers to a user, but the display mechanism does not make it easy for the user to distinguish between visually similar or identical glyphs (homoglyphs), which may cause the user to misinterpret a glyph and perform an unintended, insecure action. Some glyphs, pictures, or icons can be semantically distinct to a program, while appearing very similar or identical to a human user. These are referred to as homoglyphs. For example, the lowercase l (ell) and uppercase I (eye) have different character codes, but these characters can be displayed in exactly the same way to a user, depending on the font. This can also occur between different character sets. For example, the Latin capital letter A and the Greek capital letter Α (Alpha) are treated as distinct by programs, but may be displayed in exactly the same way to a user. Accent marks may...
- Indicators:
  - Insufficient Visual Distinction of Homoglyphs Presented to User
  - Homograph Attack

### CWE-1021: Improper Restriction of Rendered UI Layers or Frames

- Severity: medium
- Description: The web application does not restrict or incorrectly restricts frame objects or UI layers that belong to another application or domain.
- Indicators:
  - Improper Restriction of Rendered UI Layers or Frames
  - Clickjacking
  - UI Redress Attack
  - Tapjacking

### CWE-1024: Comparison of Incompatible Types

- Severity: medium
- Description: The product performs a comparison between two entities, but the entities are of different, incompatible types that cannot be guaranteed to provide correct results when they are directly compared.
- Indicators:
  - Comparison of Incompatible Types

### CWE-1073: Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses

- Severity: medium
- Description: The product contains a client with a function or method that contains a large number of data accesses/queries that are sent through a data manager, i.e., does not use efficient database capabilities. While the interpretation of large number of data accesses/queries may vary for each product or developer, CISQ recommends a default maximum of 2 data accesses per function/method.
- Indicators:
  - Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses

### CWE-1335: Incorrect Bitwise Shift of Integer

- Severity: medium
- Description: An integer value is specified to be shifted by a negative amount or an amount greater than or equal to the number of bits contained in the value causing an unexpected or indeterminate result. Specifying a value to be shifted by a negative amount is undefined in various languages. Various computer architectures implement this action in different ways. The compilers and interpreters when generating code to accomplish a shift generally do not do a check for this issue. Specifying an over-shift, a shift greater than or equal to the number of bits contained in a value to be shifted, produces a result which varies by architecture and compiler. In some languages, this action is specifically listed as producing an undefined result.
- Indicators:
  - Incorrect Bitwise Shift of Integer

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
