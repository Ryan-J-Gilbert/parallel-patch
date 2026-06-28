# parallel-patch Agent 2

You are a focused security review subagent. Analyze only the target content below and only for the vulnerabilities assigned to you.

## Assigned Vulnerabilities

### CWE-366: Race Condition within a Thread

- Severity: medium
- Description: If two threads of execution use a resource simultaneously, there exists the possibility that resources may be used while invalid, in turn making the state of execution undefined.
- Indicators:
  - Race Condition within a Thread

### CWE-374: Passing Mutable Objects to an Untrusted Method

- Severity: medium
- Description: The product sends non-cloned mutable data as an argument to a method or function. The function or method that has been called can alter or delete the mutable data. This could violate assumptions that the calling function has made about its state. In situations where unknown code is called with references to mutable data, this external code could make changes to the data sent. If this data was not previously cloned, the modified data might not be valid in the context of execution.
- Indicators:
  - Passing Mutable Objects to an Untrusted Method

### CWE-375: Returning a Mutable Object to an Untrusted Caller

- Severity: medium
- Description: Sending non-cloned mutable data as a return value may result in that data being altered or deleted by the calling function. In situations where functions return references to mutable data, it is possible that the external code which called the function may make changes to the data sent. If this data was not previously cloned, the class will then be using modified data which may violate assumptions about its internal state.
- Indicators:
  - Returning a Mutable Object to an Untrusted Caller

### CWE-396: Declaration of Catch for Generic Exception

- Severity: medium
- Description: Catching overly broad exceptions promotes complex error handling code that is more likely to contain security vulnerabilities. Multiple catch blocks can get ugly and repetitive, but condensing catch blocks by catching a high-level class like Exception can obscure exceptions that deserve special treatment or that should not be caught at this point in the program. Catching an overly broad exception essentially defeats the purpose of a language's typed exceptions, and can become particularly dangerous if the program grows and begins to throw new types of exceptions. The new exception types will not receive any attention.
- Indicators:
  - Declaration of Catch for Generic Exception

### CWE-397: Declaration of Throws for Generic Exception

- Severity: medium
- Description: The product throws or raises an overly broad exceptions that can hide important details and produce inappropriate responses to certain conditions. Declaring a method to throw Exception or Throwable promotes generic error handling procedures that make it difficult for callers to perform proper error handling and error recovery. For example, Java's exception mechanism makes it easy for callers to anticipate what can go wrong and write code to handle each specific exceptional circumstance. Declaring that a method throws a generic form of exception defeats this system.
- Indicators:
  - Declaration of Throws for Generic Exception

### CWE-403: Exposure of File Descriptor to Unintended Control Sphere ('File Descriptor Leak')

- Severity: medium
- Description: A process does not close sensitive file descriptors before invoking a child process, which allows the child to perform unauthorized I/O operations using those descriptors. When a new process is forked or executed, the child process inherits any open file descriptors. When the child process has fewer privileges than the parent process, this might introduce a vulnerability if the child process can access the file descriptor but does not have the privileges to access the associated file.
- Indicators:
  - Exposure of File Descriptor to Unintended Control Sphere ('File Descriptor Leak')
  - File Descriptor Leak

### CWE-425: Direct Request ('Forced Browsing')

- Severity: medium
- Description: The web application does not adequately enforce appropriate authorization on all restricted URLs, scripts, or files.
- Indicators:
  - Direct Request ('Forced Browsing')
  - Forced Browsing

### CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')

- Severity: medium
- Description: The product acts as an intermediary HTTP agent (such as a proxy or firewall) in the data flow between two entities such as a client and server, but it does not interpret malformed HTTP requests or responses in ways that are consistent with how the messages will be processed by those entities that are at the ultimate destination. HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load balancers, reverse proxies, web caching proxies, application firewalls, etc. For example, an adversary may be able to add duplicate or different header fields that a client or server might interpret as one set of messages, whereas the intermediary might interpret the same sequence of bytes as a different set of messages. For example, discrepancies can arise in how to handle duplicate headers like t...
- Indicators:
  - Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')
  - HTTP Request/Response Smuggling
  - HTTP Request Smuggling
  - HTTP Response Smuggling
  - HTTP Smuggling

### CWE-463: Deletion of Data Structure Sentinel

- Severity: medium
- Description: The accidental deletion of a data-structure sentinel can cause serious programming logic problems. Often times data-structure sentinels are used to mark structure of the data structure. A common example of this is the null character at the end of strings. Another common example is linked lists which may contain a sentinel to mark the end of the list. It is dangerous to allow this type of control data to be easily accessible. Therefore, it is important to protect from the deletion or modification outside of some wrapper interface which provides safety.
- Indicators:
  - Deletion of Data Structure Sentinel

### CWE-464: Addition of Data Structure Sentinel

- Severity: medium
- Description: The accidental addition of a data-structure sentinel can cause serious programming logic problems. Data-structure sentinels are often used to mark the structure of data. A common example of this is the null character at the end of strings or a special sentinel to mark the end of a linked list. It is dangerous to allow this type of control data to be easily accessible. Therefore, it is important to protect from the addition or modification of sentinels.
- Indicators:
  - Addition of Data Structure Sentinel

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
