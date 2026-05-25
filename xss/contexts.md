# XSS Injection Contexts

> **Purpose:** Understanding *where* user input lands in a document is the foundation of XSS testing and prevention. The same string can be harmless in one context and executable in another. This document maps each major injection context to its parsing behaviour, breakout logic, and correct prevention.

Pair with [`bypass-techniques.md`](./bypass-techniques.md) and [`prevention.md`](./prevention.md).

---

## Table of Contents

1. [What Is an Injection Context?](#1-what-is-an-injection-context)
2. [HTML Body Context](#2-html-body-context)
3. [Attribute Context](#3-attribute-context)
4. [JavaScript Context](#4-javascript-context)
5. [URL Context](#5-url-context)
6. [DOM-Based Context](#6-dom-based-context)
7. [Quick Comparison Table](#7-quick-comparison-table)
8. [Common Mistakes](#8-common-mistakes)
9. [Key Defensive Takeaway](#9-key-defensive-takeaway)

---

## 1. What Is an Injection Context?

When a browser receives an HTML document, it doesn't read it as a single flat string. It passes content through several distinct parsers — each with its own rules about which characters are meaningful and which are inert.

```
HTML response
     │
     ├── HTML parser        →  reads tags, attributes, text nodes
     │     ├── CSS parser   →  reads style blocks and attributes
     │     ├── URL parser   →  reads href, src, action values
     │     └── JS engine    →  reads <script> blocks and event handlers
```

**The injection context is wherever user-controlled data is inserted into this pipeline.** The same input — say, `"><img src=x onerror=alert(1)>` — may:

- Execute in an HTML body context (parser treats `>` as tag boundary)
- Execute in an unquoted attribute (space or `>` breaks out)
- Fail in a JavaScript string context (those characters don't break a JS string)
- Fail completely if the output is correctly encoded for that context

XSS testing is fundamentally about identifying the context first, then selecting or crafting a payload appropriate to it. Sending random payloads without knowing the context is guessing, not testing.

---

## 2. HTML Body Context

### What it looks like

```html
<div>USER_INPUT</div>
<p>Welcome, USER_INPUT</p>
```

User input lands as text content between HTML tags.

### How the parser behaves

The HTML parser reads content between tags as text by default. However, if it encounters `<`, it switches to tag-parsing mode. This means injecting an angle bracket allows an attacker to introduce new HTML elements — including elements with event handlers.

### Breakout logic

```html
<!-- Input: <img src=x onerror=alert(1)> -->
<div><img src=x onerror=alert(1)></div>

<!-- The parser sees a new <img> tag, not text.
     src=x causes an image load failure.
     onerror fires, executing alert(1). -->
```

### Prevention

HTML-encode the output. `<` becomes `&lt;`, `>` becomes `&gt;`. The parser now sees a text node containing the literal characters — no tag is opened.

```html
<!-- After encoding -->
<div>&lt;img src=x onerror=alert(1)&gt;</div>
<!-- Browser renders: <img src=x onerror=alert(1)>  ← visible text, not a tag -->
```

---

## 3. Attribute Context

User input is placed inside an HTML attribute value.

```html
<input value="USER_INPUT">
<a href="USER_INPUT">
<div class="USER_INPUT">
```

---

### 3.1 Quoted Attribute

```html
<input value="USER_INPUT">
```

The attribute value ends at the next matching quote. If user input contains `"`, it closes the attribute early. Anything after it is interpreted as new attributes or markup.

```html
<!-- Input: " onfocus="alert(1)" autofocus=" -->
<input value="" onfocus="alert(1)" autofocus="">

<!-- The injected onfocus is now a real event handler.
     autofocus triggers the focus event automatically on page load. -->
```

**Prevention:** Encode `"` as `&quot;` (and `'` as `&#x27;` for single-quoted attributes). The quote never reaches the parser as a delimiter.

---

### 3.2 Unquoted Attribute

```html
<input value=USER_INPUT>
```

Without surrounding quotes, the attribute value ends at the first whitespace or `>`. This is a wider breakout surface — the attacker doesn't even need to inject a quote.

```html
<!-- Input: x onfocus=alert(1) autofocus -->
<input value=x onfocus=alert(1) autofocus>

<!-- Space after x terminates the value.
     onfocus=alert(1) is parsed as a new attribute. -->
```

**Prevention:** Always quote attribute values in HTML output, and encode the quote character. Unquoted attributes should not appear in server-rendered templates.

---

### 3.3 Event Handler Attributes

Certain attributes execute JavaScript directly — no tag injection required.

```html
<img src="USER_INPUT" onerror="USER_INPUT">
<body onload="USER_INPUT">
```

Never insert untrusted data into an `on*` attribute. There is no safe encoding that neutralises it — the value is executed verbatim as JavaScript.

---

## 4. JavaScript Context

User input is reflected inside a `<script>` block.

```html
<script>
  var username = "USER_INPUT";
  var count = USER_INPUT;
</script>
```

### Why this context is different

The HTML parser stops most of its processing inside `<script>` blocks. This means **HTML entity encoding provides no protection here**. The JavaScript engine receives the content directly.

```html
<!-- Input: "; alert(1); var x=" -->
<script>
  var username = ""; alert(1); var x="";
</script>

<!-- The injected " closes the string literal.
     alert(1) is now a standalone JS statement.
     var x=" reopens a string to avoid a syntax error. -->
```

### String breakout and escaping

To stay safe, user data placed inside a JS string must be encoded using a JavaScript-specific encoder — not HTML encoding.

```python
# Correct: JSON serialisation encodes quotes, backslashes, and </script>
import json
safe_value = json.dumps(username)
# Input:  He said "hello"
# Output: "He said \"hello\""   ← quotes escaped for JS string context
```

One additional risk: the sequence `</script>` inside a script block causes the HTML parser to terminate the block prematurely, before the JS engine processes it.

```html
<script>
  var data = "</script><script>alert(1)//";
</script>
<!-- The HTML parser sees </script> and ends the block.
     The injected <script> then starts a new block. -->
```

A JSON encoder escapes `/` as `\/`, preventing this.

### Prevention

Use JSON serialisation for embedding data, or pass data via a `data-*` attribute and read it with `textContent`:

```html
<!-- Safe pattern: data attribute + textContent read -->
<div id="init-data" data-user="{{ username_encoded }}"></div>
<script>
  const username = document.getElementById('init-data').dataset.user;
</script>
```

---

## 5. URL Context

User input is placed in a URL-accepting attribute.

```html
<a href="USER_INPUT">
<img src="USER_INPUT">
<iframe src="USER_INPUT">
<form action="USER_INPUT">
```

### Protocol injection

The core risk in URL context is not HTML structure — it's the `javascript:` URI scheme. When a browser navigates to a `javascript:` URI, it executes the contents as JavaScript.

```html
<!-- Input: javascript:alert(document.cookie) -->
<a href="javascript:alert(document.cookie)">Click me</a>

<!-- Clicking the link executes JavaScript in the page's origin context. -->
```

The `data:text/html,...` scheme can inject an entire HTML document in some element contexts.

### Encoding considerations

Percent-encoding the input is not sufficient protection if the scheme is not also validated. `javascript:` can survive encoding in some contexts:

```html
<a href="&#106;avascript:alert(1)">  <!-- entity-encoded j -->
<a href="  javascript:alert(1)">     <!-- leading whitespace stripped by some parsers -->
```

### Prevention

Validate the scheme server-side before placing any user-supplied string into a URL attribute. Reject anything that is not `http://`, `https://`, or an explicit site-relative path starting with `/`.

```python
from urllib.parse import urlparse

def is_safe_url(url):
    parsed = urlparse(url.strip())
    return parsed.scheme in ('http', 'https') or (not parsed.scheme and url.startswith('/'))
```

---

## 6. DOM-Based Context

DOM-based XSS does not involve server reflection. The payload never touches the server — it travels from a browser-accessible **source** to a dangerous **sink** entirely within client-side JavaScript.

```
Source: location.hash, location.search, document.referrer,
        window.name, localStorage, postMessage

        │
        │  (no server involvement)
        ▼

Sink:   element.innerHTML, document.write(), eval(),
        setTimeout("string"), location.href = ...
```

### How it works

```javascript
// Vulnerable code in the page's own JavaScript:
const name = location.hash.slice(1);       // source: reads from URL hash
document.getElementById('msg').innerHTML = name;  // sink: writes raw HTML to DOM
```

A victim visits:
```
https://example.com/page#<img src=x onerror=alert(1)>
```

The JavaScript reads the hash, passes it to `innerHTML`, and the browser executes it. The server never saw the payload.

### Why server-side filtering doesn't help

The hash (`#...`) is never sent to the server in HTTP requests. Server-side output encoding, WAFs, and server-side validation are all completely blind to this attack.

### Dangerous sinks

| Sink | Risk |
|---|---|
| `element.innerHTML = value` | Parses value as HTML; executes event handlers |
| `document.write(value)` | Writes to document stream; parsed as HTML |
| `eval(value)` | Executes value as JavaScript directly |
| `setTimeout("string", n)` | String form executes as JS; callback form is safe |
| `location.href = value` | `javascript:` URI executes on navigation |
| `element.src = value` | `javascript:` URI in some contexts |

### Prevention

Use safe DOM APIs that treat values as text, not as markup:

```javascript
// Dangerous
element.innerHTML = userValue;

// Safe
element.textContent = userValue;          // treats value as plain text
element.setAttribute('data-x', userValue); // attribute value, not HTML
```

When rich HTML must be rendered from a client-side source, sanitise it with DOMPurify before passing it to any sink:

```javascript
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userValue);
```

Use browser DevTools **DOM Invader** (Burp Suite's built-in browser) to automatically trace source-to-sink data flows in client-side code.

---

## 7. Quick Comparison Table

| Context | How to Break Out | Main Risk | Prevention |
|---|---|---|---|
| **HTML body** | Inject `<` to open a new tag | Tag injection, event handler injection | HTML-encode `< > & " '` |
| **Quoted attribute** | Inject `"` or `'` to close the attribute | Inject new attributes including `on*` handlers | Encode the quote character; always quote attributes |
| **Unquoted attribute** | Inject a space or `>` | Same as quoted, with a wider breakout surface | Always quote attributes; encode delimiters |
| **JavaScript string** | Inject `"` or `'` to close the string; inject `</script>` to exit the block | Arbitrary JS execution | JSON serialisation; JavaScript-specific encoder |
| **URL attribute** | Supply a `javascript:` or `data:` URI | JS execution on click or load | Validate scheme; allow only `http`, `https`, or relative paths |
| **DOM sink** | Supply HTML/JS to a source read by dangerous sink | Arbitrary JS execution; bypasses server-side controls entirely | Use safe DOM APIs (`textContent`); sanitise with DOMPurify for HTML |

---

## 8. Common Mistakes

### Using the same payload everywhere

A payload crafted for HTML body context — e.g., `<script>alert(1)</script>` — will not work in a JavaScript string context. The goal in a JS string is to inject `"` to break out, not `<` to open a tag. Matching the payload to the context is the first step.

### Ignoring quote style in attributes

```html
<input value='USER_INPUT'>   ← single-quoted
<input value="USER_INPUT">   ← double-quoted
```

A payload that injects `"` breaks out of a double-quoted attribute but is inert in a single-quoted one. Check the surrounding quotes in the rendered source before crafting the payload.

### Confusing reflection with execution

Seeing your input appear in the HTML source or in the DOM does not mean XSS is confirmed. For execution, the input must:

1. Land in an executable context
2. Not be encoded in a way that neutralises its syntax
3. Be parsed by the browser in a way that triggers code execution

Always verify execution in the browser, not just reflection in the raw source. Use the **Inspector (Elements)** tab to see the parsed DOM and the **Console** to check for errors.

### Forgetting DOM-based sinks

Focusing exclusively on server-reflected input misses an entire class of XSS. Audit client-side JavaScript for source-to-sink patterns, especially in single-page applications that read from `location`, `document.referrer`, or `postMessage`.

### Assuming HTML encoding is universal

HTML encoding (`&lt;`, `&quot;`) is correct for HTML contexts. It does **not** protect JavaScript contexts, CSS contexts, or URL contexts. Applying the wrong encoding to the wrong context either creates a double-encoding display bug or leaves the injection unprotected.

---

## 9. Key Defensive Takeaway

### One rule covers most cases

> **Encode output for the context it is placed into — not for the context it came from.**

The same data requires different treatment depending on where it is rendered. A value going into a JavaScript string needs JS encoding. A value going into an HTML attribute needs attribute encoding. A value going into a URL needs scheme validation and URL encoding. There is no shortcut.

### Prevention hierarchy

```
1. Context-aware output encoding   ← solves the root cause for server-rendered output
2. Safe DOM APIs                   ← textContent over innerHTML; avoid eval
3. HTML sanitisation               ← DOMPurify when rich HTML is required
4. Framework auto-escaping         ← React, Angular, Vue protect by default; don't bypass
5. Content Security Policy         ← limits impact if a control is missed
```

### Minimum encoding rules by context

| Context | Apply |
|---|---|
| HTML body | HTML-encode `< > & " '` |
| HTML attribute | HTML-encode, especially the delimiter quote |
| JavaScript string | JSON serialisation / JS-specific encoder |
| URL attribute | Validate scheme; percent-encode parameters |
| CSS value | Validate against allowlist or CSS-encode |
| DOM sink | Use `textContent`; sanitise with DOMPurify for HTML |

Context-driven thinking is what separates systematic security work from payload guessing.

---

*Part of the [`web-security-notes`](../) repository. See also: [`bypass-techniques.md`](./bypass-techniques.md) · [`prevention.md`](./prevention.md)*