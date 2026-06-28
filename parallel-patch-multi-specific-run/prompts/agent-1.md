# parallel-patch Agent 1

You are a focused security review subagent. Analyze only the target content below and only for the vulnerabilities assigned to you.

## Assigned Vulnerabilities

### CWE-135: Incorrect Calculation of Multi-Byte String Length

- Severity: medium
- Description: The product does not correctly calculate the length of strings that can contain wide or multi-byte characters.
- Indicators:
  - Incorrect Calculation of Multi-Byte String Length

### CWE-170: Improper Null Termination

- Severity: medium
- Description: The product does not terminate or incorrectly terminates a string or array with a null character or equivalent terminator. Null termination errors frequently occur in two different ways. An off-by-one error could cause a null to be written out of bounds, leading to an overflow. Or, a program could use a strncpy() function call incorrectly, which prevents a null terminator from being added at all. Other scenarios are possible.
- Indicators:
  - Improper Null Termination

### CWE-190: Integer Overflow or Wraparound

- Severity: medium
- Description: The product performs a calculation that can produce an integer overflow or wraparound when the logic assumes that the resulting value will always be larger than the original value. This occurs when an integer value is incremented to a value that is too large to store in the associated representation. When this occurs, the value may become a very small or negative number.
- Indicators:
  - Integer Overflow or Wraparound
  - Overflow
  - Wraparound
  - wrap, wrap-around, wrap around

### CWE-191: Integer Underflow (Wrap or Wraparound)

- Severity: medium
- Description: The product subtracts one value from another, such that the result is less than the minimum allowable integer value, which produces a value that is not equal to the correct result. This can happen in signed and unsigned cases.
- Indicators:
  - Integer Underflow (Wrap or Wraparound)
  - Integer underflow

### CWE-193: Off-by-one Error

- Severity: medium
- Description: A product calculates or uses an incorrect maximum or minimum value that is 1 more, or 1 less, than the correct value.
- Indicators:
  - Off-by-one Error
  - off-by-five

### CWE-242: Use of Inherently Dangerous Function

- Severity: medium
- Description: The product calls a function that can never be guaranteed to work safely. Certain functions behave in dangerous ways regardless of how they are used. Functions in this category were often implemented without taking security concerns into account. The gets() function is unsafe because it does not perform bounds checking on the size of its input. An attacker can easily send arbitrarily-sized input to gets() and overflow the destination buffer. Similarly, the >> operator is unsafe to use when reading into a statically-allocated character array because it does not perform bounds checking on the size of its input. An attacker can easily send arbitrarily-sized input to t...
- Indicators:
  - Use of Inherently Dangerous Function

### CWE-243: Creation of chroot Jail Without Changing Working Directory

- Severity: medium
- Description: The product uses the chroot() system call to create a jail, but does not change the working directory afterward. This does not prevent access to files outside of the jail. Improper use of chroot() may allow attackers to escape from the chroot jail. The chroot() function call does not change the process's current working directory, so relative paths may still refer to file system resources outside of the chroot jail after chroot() has been called.
- Indicators:
  - Creation of chroot Jail Without Changing Working Directory

### CWE-295: Improper Certificate Validation

- Severity: medium
- Description: The product does not validate, or incorrectly validates, a certificate.
- Indicators:
  - Improper Certificate Validation

### CWE-346: Origin Validation Error

- Severity: medium
- Description: The product does not properly verify that the source of data or communication is valid.
- Indicators:
  - Origin Validation Error

### CWE-364: Signal Handler Race Condition

- Severity: medium
- Description: The product uses a signal handler that introduces a race condition. Race conditions frequently occur in signal handlers, since signal handlers support asynchronous actions. These race conditions have a variety of root causes and symptoms. Attackers may be able to exploit a signal handler race condition to cause the product state to be corrupted, possibly leading to a denial of service or even code execution. These issues occur when non-reentrant functions, or state-sensitive actions occur in the signal handler, where they may be called at any time. These behaviors can violate assumptions being made by the regular code that is interrupted, or by other signal h...
- Indicators:
  - Signal Handler Race Condition

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
