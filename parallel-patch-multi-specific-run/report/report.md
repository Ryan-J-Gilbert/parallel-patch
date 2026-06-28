# parallel-patch Report

- Scan ID: `f451c2fe-42e0-4a89-a23d-c90374139490`
- Target: `tests/fixtures/multi_surface.diff`
- Agents: 9
- Failed agents: 0
- Findings: 7

## Findings

### MEDIUM CWE-89: SQL Injection

- Location: `backend/app.py:2`
- Confidence: high
- Description: The SQL query is built by interpolating term directly into the statement, allowing attacker-controlled input to alter the query syntax.
- Suggested fix: Use parameterized queries or prepared statements and bind term as a value instead of concatenating it into SQL.

### MEDIUM CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes

- Location: `backend/app.py:7`
- Confidence: high
- Description: The payload is applied directly to user.__dict__, allowing upstream input to modify arbitrary object attributes, including internal or security-sensitive fields.
- Suggested fix: Only copy explicitly allowed fields from the payload into the user object and reject or ignore all other attributes.

### MEDIUM CWE-120: Classic Buffer Overflow

- Location: `native/parser.c:3`
- Confidence: high
- Description: strcpy copies input into a fixed 32-byte buffer without checking the input length, which can overflow buf.
- Suggested fix: Validate the input length before copying or use a bounded copy routine that preserves null termination and rejects oversized input.

### MEDIUM CWE-242: Use of Inherently Dangerous Function

- Location: `native/parser.c:3`
- Confidence: high
- Description: The code copies attacker-controlled input into a fixed-size stack buffer with strcpy(), which performs no bounds checking and can overflow the destination.
- Suggested fix: Replace strcpy() with a bounded copy that uses the destination buffer size and guarantees null termination, or validate the input length before copying.

### MEDIUM CWE-676: Use of Potentially Dangerous Function

- Location: `native/parser.c:3`
- Confidence: high
- Description: The parser copies attacker-controlled input with strcpy, a potentially dangerous function that performs no bounds checking and can overflow the fixed-size buffer.
- Suggested fix: Use a bounded copy or length-checked parsing routine and ensure the destination buffer is always null-terminated.

### MEDIUM CWE-787: Out-of-bounds Write

- Location: `native/parser.c:3`
- Confidence: high
- Description: Unbounded strcpy copies attacker-controlled input into a fixed 32-byte stack buffer, which can write past the end of the buffer when input is longer than the destination.
- Suggested fix: Bound the copy to the size of the destination buffer and ensure null termination, or validate input length before copying.

### MEDIUM CWE-79: Cross-site Scripting

- Location: `web/profile.js:2`
- Confidence: high
- Description: User-controlled name data is assigned to innerHTML, so HTML or script content in the value can execute in the page.
- Suggested fix: Assign untrusted text with textContent or sanitize the value with a trusted HTML sanitizer before inserting it as markup.
