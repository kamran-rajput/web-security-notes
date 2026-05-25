# Preventing Cross-Site Scripting (XSS)

> **Scope:** This document covers XSS prevention from a secure development perspective — what controls exist, why they work, where they apply, and how they fail when misused. It is organised by prevention layer, not by attack type. Pair it with [`bypass-techniques.md`](./bypass-techniques.md) for the full picture.

---

## Table of Contents

1. [Core Security Principle](#1-core-security-principle)
2. [Output Encoding](#2-output-encoding)
3. [Sanitisation](#3-sanitisation)
4. [Safe Frameworks](#4-safe-frameworks)
5. [Dangerous Developer Mistakes](#5-dangerous-developer-mistakes)
6. [Content Security Policy (CSP)](#6-content-security-policy-csp)
7. [Secure Cookies and Session Impact](#7-secure-cookies-and-session-impact)
8. [Testing for Prevention](#8-testing-for-prevention)
9. [Defence-in-Depth Checklist](#9-defence-in-depth-checklist)
10. [Key Takeaway Summary](#10-key-takeaway-summary)

---

## 1. Core Security Principle

### Never Trust User Input

"User input" is broader than it might seem. It includes anything that originates outside the application's own codebase:

- URL parameters and path segments
- Form fields and HTTP request bodies
- HTTP headers (`Referer`, `User-Agent`, custom headers)
- Cookies and local storage values
- Data fetched from third-party APIs
- Data read from a database that was originally provided by a user
- `postMessage` payloads from other origins
- Browser APIs: `location.hash`, `document.referrer`, `window.name`

The last category is particularly easy to overlook. Data sitting in your own database still carries its original trust level: if it was provided by a user, it is user-controlled data, regardless of where it is stored now.

### Input Validation vs. Output Encoding

These two controls are complementary but solve different problems. Conflating them is a common source of vulnerabilities.

| | Input Validation | Output Encoding |
|---|---|---|
| **Question it answers** | Does this input make sense for this field? | Is this data safe to render in this context? |
| **When it runs** | At the point of ingestion | At the point of output/rendering |
| **What it does** | Rejects or normalises unexpected values | Transforms characters so the parser treats them as data |
| **XSS prevention?** | Partial — helps narrow attack surface | Yes — the primary XSS control |
| **Example** | Reject a name field containing `<script>` | Encode `<` as `&lt;` when inserting a name into HTML |

Input validation is necessary but not sufficient for XSS prevention. A `<` character might be perfectly valid in some fields (a comparison operator in a maths expression, a symbol in a name). Rejecting it at ingestion breaks functionality. Encoding it correctly at output preserves functionality and prevents injection.

**Rule:** Validate input for business logic. Encode output for rendering context.

### Why Prevention Depends on Rendering Context

A browser processes a document through several distinct parsing stages, each with its own rules:

```
HTTP response
     │
     ▼
HTML parser         →  interprets tags, attributes, entities
     │
     ├── CSS parser →  interprets style rules and values
     │
     ├── URL parser →  interprets href, src, action values
     │
     └── JS engine  →  interprets <script> content and event handlers
```

The same character or string is interpreted differently depending on which parser is active at the point of injection. For example:

- `"` terminates an HTML attribute value — but it is just a string character inside a JavaScript block
- `&lt;` is decoded to `<` by the HTML parser — but the JavaScript engine sees it literally as `&lt;`
- `javascript:` in a URL attribute triggers code execution — but it is inert in HTML body text

This means there is no single universal encoding that makes data safe in all contexts. The encoding applied must match the context where the data will be rendered.

---

## 2. Output Encoding

Output encoding is the act of transforming characters that have special meaning in a given parser context into representations that the parser treats as inert data. It does not alter the logical meaning of the content — a user named `O'Brien` still appears as `O'Brien` on screen — but it ensures the parser cannot misinterpret the data as markup or code.

---

### 2.1 HTML Encoding

**Context:** Data inserted into HTML body content — between tags, not inside attributes.

```html
<p>Welcome, [USER_INPUT]</p>
<div class="bio">[USER_INPUT]</div>
```

**Characters to encode:**

| Character | HTML Entity | Why |
|---|---|---|
| `<` | `&lt;` | Opens a tag |
| `>` | `&gt;` | Closes a tag |
| `&` | `&amp;` | Opens an entity reference; encode first to avoid double-encoding issues |
| `"` | `&quot;` | Terminates a double-quoted attribute (also encode in body for safety) |
| `'` | `&#x27;` | Terminates a single-quoted attribute; `&apos;` is valid XML but not always HTML4 |

**Example:**

```python
# Unsafe
output = f"<p>Hello, {username}</p>"

# Safe — using a library
from markupsafe import escape
output = f"<p>Hello, {escape(username)}</p>"

# What the library does:
# username = '<script>alert(1)</script>'
# escape(username) = '&lt;script&gt;alert(1)&lt;/script&gt;'
# Browser renders:  <script>alert(1)</script>  (as visible text, not executed code)
```

**Why it works:** The HTML parser encounters `&lt;` and decodes it to `<` for display purposes, but it has already passed the point where it would interpret `<` as opening a new tag. The character is bound to the text node, not the tag-parsing phase.

---

### 2.2 Attribute Encoding

**Context:** Data inserted into HTML attribute values.

```html
<input value="[USER_INPUT]">
<a href="[USER_INPUT]">
<div data-info="[USER_INPUT]">
```

**Quoted attributes** are the standard case. The risk is that the user-supplied data contains the quote character used to delimit the attribute, allowing an attacker to close the attribute and inject new attributes (including event handlers).

```html
<!-- Vulnerable template: -->
<input value="{{ username }}">

<!-- If username = '" onfocus="alert(1)" autofocus="': -->
<input value="" onfocus="alert(1)" autofocus="">
<!-- The injected onfocus fires, executing JavaScript -->
```

**Safe approach:** HTML-encode the attribute value. At minimum, encode `"` (or `'` for single-quoted attributes), `<`, `>`, and `&`.

```html
<!-- After encoding username = '&quot; onfocus=&quot;alert(1)&quot; autofocus=&quot;': -->
<input value="&quot; onfocus=&quot;alert(1)&quot; autofocus=&quot;">
<!-- Browser renders the literal text: " onfocus="alert(1)" autofocus=" -->
```

**Dangerous attributes** require additional care because their values are interpreted by parsers beyond the HTML attribute parser:

| Attribute | Risk | Additional Control Needed |
|---|---|---|
| `href`, `src`, `action`, `formaction` | `javascript:` URI execution | Validate scheme; allow only `http://`, `https://`, or site-relative paths |
| `style` | CSS injection, expression execution (IE legacy) | CSS encoding or reject entirely |
| `on*` (event handlers) | Direct JS execution | Never insert untrusted data here |
| `srcdoc` | Full HTML injection into iframe | Sanitise as HTML; treat as HTML body context |

**Never insert untrusted data into an `on*` attribute**, even with encoding applied. There is no safe way to do this — the value is executed as JavaScript verbatim by the browser.

---

### 2.3 JavaScript Encoding

**Context:** Untrusted data embedded inside a `<script>` block or an inline event handler value.

```html
<script>
  var username = "[USER_INPUT]";
  var config = [USER_INPUT];
</script>
```

This context has important differences from HTML encoding:

- The HTML parser does **not** decode entities inside `<script>` blocks. `&lt;` inside a script is the literal string `&lt;`, not `<`. HTML encoding therefore provides **no protection here**.
- The JavaScript engine interprets the content directly as source code.
- The injector's goal is to escape the string literal context (by injecting a `"` or `'`) or to inject `</script>` to terminate the block and re-enter HTML context.

**Safe approach for string values:** Use JSON serialisation via a security-aware encoder.

```javascript
// Python / Django example
import json
from django.utils.html import escapejs

# Approach 1: JSON serialisation (preferred for complex values)
user_data = json.dumps(username)  # produces a properly quoted, escaped JSON string
# Then in template:
# var name = {{ user_data|safe }};   ← the json.dumps output is already safe for JS string context

// Approach 2: JavaScript escape for simple string insertion
escaped = escapejs(username)
// Encodes: \ " ' \n \r < > & = `
```

**What JSON serialisation encodes:**

```
Input:    O'Brien</script><script>alert(1)
Output:   "O'Brien<\/script><script>alert(1)"
                  ^^
                  The forward slash is escaped, preventing </script> injection
```

Note the `\/` — a standards-compliant JSON encoder escapes `</` as `<\/` to prevent the sequence from being interpreted as a closing script tag by the HTML parser before the JS parser has seen it.

**Embedding structured data:** The safest pattern for passing server-side data to JavaScript is to place it in a `data-*` attribute and read it with JavaScript, or to use a `<script type="application/json">` block (which browsers do not execute as JavaScript):

```html
<!-- Safe pattern: JSON in a non-executable script type -->
<script id="app-data" type="application/json">
  {"username": "O&#x27;Brien", "role": "user"}
</script>

<script>
  const data = JSON.parse(document.getElementById('app-data').textContent);
  // textContent is safe to read — it returns raw text, not decoded HTML
</script>
```

**Escaping pitfalls:**

- Do not use `innerHTML` to write script-context data; use `textContent` for data reads.
- Do not construct JavaScript strings through concatenation in server templates without a JavaScript-specific encoder.
- Do not assume HTML encoding protects JS contexts — it does not.

---

### 2.4 URL Encoding

**Context:** Untrusted data inserted into a URL, either as a query parameter or as a full URL value in an attribute.

```html
<a href="/search?q=[USER_INPUT]">
<a href="[USER_INPUT]">
<img src="/avatar?user=[USER_INPUT]">
```

**Query parameter encoding:** Percent-encode all characters that are not unreserved URI characters (`A-Z a-z 0-9 - _ . ~`).

```python
from urllib.parse import quote

safe_param = quote(user_input, safe='')
url = f"/search?q={safe_param}"

# Input:  <script>alert(1)</script>
# Output: %3Cscript%3Ealert%281%29%3C%2Fscript%3E
```

**Full URL validation:** When user-supplied data is the entire URL (e.g., a redirect target or user-submitted link), encoding the value is not sufficient. You must also validate the scheme.

```python
from urllib.parse import urlparse

def is_safe_url(url):
    parsed = urlparse(url)
    # Allow only http and https — block javascript:, data:, vbscript:
    return parsed.scheme in ('http', 'https')
```

**Dangerous protocols:**

| Protocol | Risk |
|---|---|
| `javascript:` | Executes JS when navigated to or in `<a href>`, `<iframe src>`, etc. |
| `data:text/html,...` | Injects a full HTML document; may execute JS |
| `vbscript:` | Legacy IE — executes VBScript |

A common vulnerable pattern is an open redirect that reflects a user-supplied URL without scheme validation:

```python
# Vulnerable
return redirect(request.args.get('next'))

# Vulnerable to: ?next=javascript:alert(document.cookie)
```

---

### 2.5 CSS Encoding

**Context:** Untrusted data embedded in a `<style>` block or a `style` attribute.

```html
<div style="background-color: [USER_INPUT]">
<style>
  .profile { color: [USER_INPUT]; }
</style>
```

**CSS injection risks:**

- **Value injection:** An attacker closes the expected CSS value context and injects additional rules (e.g., to exfiltrate data via `background-image: url(...)`).
- **IE CSS expressions (historical):** Older versions of Internet Explorer supported `expression(...)` syntax inside CSS, allowing JavaScript execution via style injection. Modern browsers do not support this, but it is worth knowing when testing legacy applications.
- **Context escape:** Injecting `</style>` to terminate the style block and re-enter HTML context.

**Safe approach:** For simple values like colours or sizes, validate against an allowlist or a strict format (e.g., a hex colour regex). For anything more dynamic, avoid inserting untrusted data into CSS entirely.

```python
import re

def safe_color(value):
    # Only allow valid hex colours or named CSS colours
    if re.match(r'^#[0-9a-fA-F]{3,6}$', value):
        return value
    if value in ALLOWED_CSS_COLORS:  # predefined allowlist
        return value
    return 'inherit'  # safe fallback
```

If CSS encoding is required (rather than validation), encode all characters except alphanumerics as `\HH ` (CSS hex escape with trailing space):

```
Input:  expression(alert(1))
Output: \65 \78 \70 \72 ...  (each non-alphanumeric character escaped)
```

In practice, most modern applications avoid dynamic CSS generation with user data entirely. If a user needs to customise a colour, store the preference server-side and apply it via a predefined CSS class or variable — never by injecting the raw value.

---

## 3. Sanitisation

### Sanitisation vs. Encoding

Output encoding and HTML sanitisation solve different problems:

| | Output Encoding | HTML Sanitisation |
|---|---|---|
| **Use case** | Plain text that should appear as-is | Rich HTML that users are permitted to submit (e.g., from a WYSIWYG editor) |
| **What it does** | Converts all special characters to safe representations | Parses HTML and removes disallowed elements and attributes |
| **Output** | Escaped plain text | A subset of HTML with dangerous constructs removed |
| **When to use** | Everywhere you insert untrusted data into a template | Only when you must accept and render user-provided HTML |

Sanitisation is not a substitute for encoding. If a field is expected to hold plain text, encode it — do not sanitise it. Sanitisation accepts HTML as input and returns a safe subset; encoding treats all input as plain text.

### Allowlist-Based Sanitisation

A correct sanitiser parses the input using a real HTML parser, walks the resulting DOM, and **removes everything not on an explicit allowlist** of permitted elements and attributes. This is fundamentally different from blacklist-based filtering.

**Why blacklists fail:**

```
Blacklist blocks: <script>, onerror, javascript:
Does not block: <svg onload=...>, <details ontoggle=...>,
                <img src=x onerror=...> (onerror with different casing),
                ... and anything added to HTML after the blacklist was written
```

**Why allowlists work:**

```
Allowlist permits: <p>, <b>, <i>, <a href> (http/https only), <ul>, <li>
Removes by default: every element and attribute not in this list
```

An attacker cannot bypass an allowlist by finding a new attack vector — new elements are blocked by default.

### DOMPurify

[DOMPurify](https://github.com/cure53/DOMPurify) is the current community standard for client-side HTML sanitisation. It uses the browser's own HTML parser to build a DOM from the input, then walks that DOM and removes unsafe nodes, returning a sanitised HTML string.

```javascript
import DOMPurify from 'dompurify';

// Basic usage
const clean = DOMPurify.sanitize(userHtml);
element.innerHTML = clean;

// Stricter: allow only a narrow set of elements
const clean = DOMPurify.sanitize(userHtml, {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'ul', 'ol', 'li'],
  ALLOWED_ATTR: ['href', 'title'],
  ALLOWED_URI_REGEXP: /^https?:/i  // block javascript: URIs in href
});

// Strip all HTML, return plain text only
const text = DOMPurify.sanitize(userHtml, { ALLOWED_TAGS: [] });
```

**Key properties of DOMPurify:**
- Uses the browser's parser — sees exactly what the browser will see
- Actively maintained by Cure53
- Handles edge cases (SVG, MathML, namespace confusion) that manual sanitisers miss

**Server-side alternatives:**
- Python: [bleach](https://bleach.readthedocs.io/) (uses html5lib)
- Java: [OWASP Java HTML Sanitizer](https://owasp.org/www-project-java-html-sanitizer/)
- Ruby: [Loofah](https://github.com/flavorjones/loofah) (used by Rails)
- Go: [bluemonday](https://github.com/microcosm-cc/bluemonday)

### Sanitisation Limitations

Sanitisation is more complex than encoding and carries its own risks:

- **Library bugs:** A vulnerability in the sanitiser itself can bypass all protections. Monitor CVEs for the libraries you use.
- **Mutation XSS (mXSS):** A class of attacks where HTML that is safe when sanitised becomes unsafe after a browser parses and re-serialises it. The sanitiser sees one DOM; the browser produces a different one. DOMPurify includes specific mXSS protections.
- **Context mismatch:** A sanitiser designed for HTML body content may not be safe for sanitising HTML placed inside an attribute.
- **Not a substitute for encoding:** Sanitisation should only be applied when rich HTML input is genuinely required. For plain text, use encoding.

---

## 4. Safe Frameworks

Modern front-end frameworks provide built-in XSS protection through automatic output encoding in their templating engines. Understanding what they protect — and the escape hatches that bypass those protections — is essential.

### 4.1 React

React's JSX syntax encodes all dynamic values inserted into the rendered output by default. When you write:

```jsx
function Greeting({ username }) {
  return <p>Hello, {username}</p>;
}
```

React calls `React.createElement` internally and assigns the value to a text node via the DOM API, not via HTML string construction. This means `username = '<script>alert(1)</script>'` renders as visible text, not executed script.

**React's protection covers:** JSX expressions (`{value}`) in element content and attribute values.

**Escape hatch — `dangerouslySetInnerHTML`:**

```jsx
// ⚠️ Bypasses all React encoding — use only with sanitised content
function RichContent({ htmlContent }) {
  return <div dangerouslySetInnerHTML={{ __html: htmlContent }} />;
}

// Safe only if htmlContent has been sanitised:
function RichContent({ rawHtml }) {
  const clean = DOMPurify.sanitize(rawHtml);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

The name `dangerouslySetInnerHTML` is intentional — React's authors chose it to make developers stop and think. Treat every use of it as a mandatory code review point.

**Other React escape hatches to audit:**
- `href` values constructed from user input (validate scheme)
- `ref` callbacks that interact with the DOM directly
- Server-side rendering templates where React's encoding may not apply

### 4.2 Angular

Angular's template engine HTML-encodes all interpolated values by default:

```html
<!-- Angular template — {{ username }} is automatically encoded -->
<p>Hello, {{ username }}</p>

<!-- Attribute binding — also encoded -->
<input [value]="username">
```

**Angular's security model** uses a concept of *trust*: all values are untrusted by default. To mark a value as trusted (bypassing sanitisation), you use Angular's `DomSanitizer` service with an explicit bypass method.

**Escape hatches:**

```typescript
import { DomSanitizer } from '@angular/platform-browser';

// ⚠️ Bypasses Angular's HTML sanitisation
this.safeHtml = this.sanitizer.bypassSecurityTrustHtml(userContent);

// ⚠️ Bypasses URL sanitisation — never use with user-controlled URLs
this.safeUrl = this.sanitizer.bypassSecurityTrustUrl(userUrl);

// ⚠️ Bypasses script sanitisation — almost never justified
this.safeScript = this.sanitizer.bypassSecurityTrustScript(code);
```

Each `bypassSecurityTrust*` method is a red flag in code review. They should be rare, documented, and reviewed.

**`[innerHTML]` binding:**

```html
<!-- Angular sanitises this, but it still deserves scrutiny -->
<div [innerHTML]="userContent"></div>
```

Angular applies its own HTML sanitiser to `[innerHTML]` bindings — it does not use the raw value. However, Angular's sanitiser may be less comprehensive than DOMPurify for edge cases; pairing them is prudent for high-risk content.

### 4.3 Vue

Vue auto-escapes text interpolation:

```html
<!-- {{ }} interpolation is HTML-encoded -->
<p>{{ username }}</p>
```

**Escape hatch — `v-html`:**

```html
<!-- ⚠️ v-html renders raw HTML without encoding -->
<div v-html="userContent"></div>
```

This is Vue's equivalent of `dangerouslySetInnerHTML`. Vue's documentation explicitly warns against using `v-html` with user-supplied content. Pair it with DOMPurify when required:

```javascript
// Vue composable for safe rich content
import DOMPurify from 'dompurify';

export function useSafeHtml(raw) {
  return computed(() => DOMPurify.sanitize(raw.value));
}

// In component:
const safeContent = useSafeHtml(userContent);
// <div v-html="safeContent"></div>
```

**Server-Side Rendering (Nuxt / Vue SSR):** Template interpolation is encoded during SSR as well. The risk area is the same: `v-html` with unvalidated content, or manual HTML string construction outside the template.

### 4.4 Server-Side Templating Engines

| Engine | Auto-escape? | Unsafe syntax |
|---|---|---|
| Django Templates | Yes (by default) | `{{ value\|safe }}`, `{% autoescape off %}` |
| Jinja2 | Yes (when enabled) | `{{ value\|safe }}`, `Markup(value)` |
| ERB (Rails) | Yes (`<%= %>` encodes) | `<%= raw value %>`, `html_safe` |
| Handlebars | Yes (`{{ }}` encodes) | `{{{ value }}}` (triple braces) |
| Twig (PHP) | Yes (by default) | `{{ value\|raw }}` |
| Go `html/template` | Yes | Using `template.HTML(value)` type cast |

**Pattern to watch for in code review:** Any template output that uses the framework's "raw" or "safe" marker. Every such occurrence requires a documented justification and should be traced back to a sanitisation step.

---

## 5. Dangerous Developer Mistakes

### 5.1 `innerHTML`

```javascript
// ⚠️ Dangerous
element.innerHTML = userInput;

// Safe alternatives:
element.textContent = userInput;         // treats value as plain text, always safe
element.insertAdjacentText('beforeend', userInput);  // also plain text
```

**Why it's risky:** `innerHTML` passes the value through the HTML parser. Any HTML in the string — including tags with event handlers — is parsed and rendered as markup. There is no encoding step.

Even setting `innerHTML` to a value that has been HTML-encoded at the server creates a double-encoding bug (the `&amp;` appears as visible text) and provides no security benefit at the DOM level.

### 5.2 `document.write`

```javascript
// ⚠️ Dangerous
document.write('<p>Hello ' + username + '</p>');

// Safe alternative: create DOM nodes explicitly
const p = document.createElement('p');
p.textContent = 'Hello ' + username;
document.body.appendChild(p);
```

**Why it's risky:** `document.write` injects a raw string directly into the document stream, which the HTML parser then processes. It has the same risk as `innerHTML` but is harder to audit because the injection may be far from the string construction. It also has serious performance implications and is deprecated for modern use.

### 5.3 `eval` and Related Functions

```javascript
// ⚠️ Dangerous — eval family
eval(userInput);
new Function(userInput)();
setTimeout(userInput, 100);        // when first arg is a string
setInterval(userInput, 100);       // same
window[userInput]();               // indirect function call via bracket notation

// Safe alternatives:
setTimeout(() => doSomething(), 100);    // callback, not string
const fn = ALLOWED_FUNCTIONS[name];      // lookup from an explicit map
if (fn) fn();
```

**Why it's risky:** `eval` and its equivalents pass a string directly to the JavaScript engine as source code. If user-controlled data reaches any of these functions, it is arbitrary code execution. There is no encoding that makes user input safe to pass to `eval`.

### 5.4 Unsafe Template Rendering

```javascript
// ⚠️ Dangerous — string concatenation template
const html = '<div class="' + className + '">' + content + '</div>';
container.innerHTML = html;

// ⚠️ Dangerous — template literal with innerHTML
container.innerHTML = `<p>${userMessage}</p>`;
```

Template literals look cleaner but provide no security benefit over concatenation when combined with `innerHTML`. The string is still parsed as HTML.

```javascript
// Safe — build the DOM programmatically
const div = document.createElement('div');
div.className = className;          // className property is not HTML-parsed
div.textContent = content;          // textContent is not HTML-parsed
container.appendChild(div);
```

### 5.5 Inline JavaScript Injection

```python
# ⚠️ Dangerous — server-side template injecting into script tag
template = f"""
<script>
  var user = '{username}';
</script>
"""
```

If `username` contains `'; alert(document.cookie); var x='`, the injected JavaScript executes. Server-side templates that build JavaScript strings through interpolation require a JavaScript-specific encoder, not HTML encoding (see [Section 2.3](#23-javascript-encoding)).

### 5.6 Trusting Client-Side Validation

```javascript
// ⚠️ False sense of security
function submitForm() {
  const input = document.getElementById('username').value;
  if (input.includes('<')) {
    alert('Invalid input');
    return;
  }
  // ... submits to server
}
```

Client-side validation is trivially bypassed: disable JavaScript, use browser DevTools to modify the DOM, or send a raw HTTP request with a tool like Burp Suite or curl. Client-side validation is a UX feature that provides fast feedback to users. It is not a security control. All validation and encoding must also be enforced on the server.

---

## 6. Content Security Policy (CSP)

### Purpose

Content Security Policy is an HTTP response header that instructs the browser about which resource origins and execution modes are permitted for a given page. It is enforced by the browser, not by the application.

```
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com
```

When a page has a CSP, the browser refuses to load or execute resources that violate the policy — regardless of whether they were injected by an attacker. CSP reduces the *impact* of an XSS vulnerability but does not prevent the injection itself.

### Key Directives

| Directive | Controls | Example |
|---|---|---|
| `default-src` | Fallback for other `*-src` directives | `default-src 'self'` |
| `script-src` | JavaScript sources and execution modes | `script-src 'self' 'nonce-{random}'` |
| `style-src` | CSS sources | `style-src 'self'` |
| `img-src` | Image sources | `img-src 'self' data:` |
| `connect-src` | XHR, fetch, WebSocket destinations | `connect-src 'self' https://api.example.com` |
| `frame-ancestors` | Which origins can embed this page | `frame-ancestors 'none'` |
| `base-uri` | Restricts `<base>` tag injection | `base-uri 'self'` |
| `form-action` | Restricts form submission targets | `form-action 'self'` |

### Nonces

A nonce (number used once) is a cryptographically random value generated per-request by the server and embedded in the CSP header and in each `<script>` tag the page legitimately includes. The browser only executes scripts that carry the matching nonce.

```python
# Server generates a random nonce per request
import secrets
nonce = secrets.token_hex(16)

# CSP header:
# Content-Security-Policy: script-src 'nonce-{nonce}'

# In the HTML template:
# <script nonce="{{ nonce }}">...</script>
# <script nonce="{{ nonce }}" src="/app.js"></script>
```

An injected `<script>` tag that lacks the correct nonce is blocked by the browser. Because the nonce is regenerated each request and never predictable, an attacker cannot forge it.

**Nonce requirements:**
- Must be generated server-side using a cryptographically secure random function
- Must be different on every page load
- Must not appear in the URL or in any user-accessible location

### `strict-dynamic`

Used with nonces or hashes to allow scripts loaded by trusted scripts, without needing to maintain a URL allowlist:

```
Content-Security-Policy: script-src 'nonce-{nonce}' 'strict-dynamic'
```

### CSP Limitations

CSP is a meaningful defence layer, but it has real limitations:

- **`unsafe-inline`:** Adding `'unsafe-inline'` to `script-src` (often done to avoid breaking existing inline scripts) defeats nonce-based protection.
- **`unsafe-eval`:** Required by some legitimate libraries (e.g., older AngularJS, some template engines). Allows `eval()` and related functions, weakening the policy significantly.
- **JSONP bypass:** If your `script-src` allows a domain that serves JSONP endpoints, an attacker can use those endpoints to inject arbitrary JavaScript from an allowed domain.
- **Overly permissive domains:** Allowing `*.googleapis.com` or `*.cloudflare.com` may introduce bypass paths via hosted files on those CDNs.
- **DOM-based XSS:** CSP `script-src` does not prevent JavaScript that is already executing on the page from passing user-controlled data to a DOM sink. A page with an injected payload that runs entirely within existing scripts may not be blocked.
- **Browser support gaps:** Older browsers have incomplete or absent CSP support.

### CSP Is a Backup, Not a Primary Defence

CSP is a defence-in-depth measure. If your application relies on CSP as the primary XSS prevention, you have a gap in your security model. Correct output encoding prevents the injection; CSP limits the damage if encoding is missed somewhere.

**Recommended approach:** Use output encoding as the primary control, then add a strict CSP (nonce-based) as a secondary layer. Audit CSP configurations using [Google's CSP Evaluator](https://csp-evaluator.withgoogle.com/).

---

## 7. Secure Cookies and Session Impact

XSS vulnerabilities are most damaging when they lead to session hijacking — an attacker stealing the session cookie and impersonating the victim. Cookie security attributes directly limit this impact.

### 7.1 `HttpOnly`

```
Set-Cookie: session=abc123; HttpOnly
```

A cookie with the `HttpOnly` flag cannot be read by JavaScript (`document.cookie` returns nothing for it). This means that even if XSS is achieved, the attacker's injected script cannot exfiltrate the session cookie.

**What it prevents:** Cookie theft via `document.cookie` in XSS payloads.

**What it does not prevent:** XSS itself, or attacks that do not require cookie theft (e.g., performing actions as the victim using the existing browser session).

### 7.2 `Secure`

```
Set-Cookie: session=abc123; Secure
```

A `Secure` cookie is only sent over HTTPS connections. This prevents it from being transmitted in plaintext over HTTP, protecting it from network-level interception.

**Requirement:** The application must be served over HTTPS for this attribute to be meaningful.

### 7.3 `SameSite`

```
Set-Cookie: session=abc123; SameSite=Strict
Set-Cookie: session=abc123; SameSite=Lax
```

`SameSite` controls whether the browser sends the cookie with cross-site requests.

| Value | Behaviour |
|---|---|
| `Strict` | Cookie sent only on same-site requests; never on cross-site navigations |
| `Lax` | Cookie sent on same-site requests and top-level navigations (e.g., link clicks), but not on cross-site subresource loads |
| `None` | Cookie sent on all requests; requires `Secure` flag |

`SameSite=Strict` provides the strongest protection. It also mitigates CSRF, as the cookie is not sent with cross-origin requests.

**Relationship to XSS:** `SameSite` limits the effectiveness of some XSS-driven CSRF attacks. If an attacker can execute JavaScript in the context of the victim's origin (which XSS enables), `SameSite` does not prevent the malicious request, because the request originates from the same site.

### 7.4 Recommended Cookie Configuration

```
Set-Cookie: session=<token>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=<seconds>
```

### 7.5 The Limits of Cookie Flags

Cookie security flags reduce the *impact* of XSS but do not eliminate it. With JavaScript execution in the victim's origin, an attacker can:

- Make authenticated requests on the victim's behalf (even without reading the cookie)
- Read sensitive data from the DOM
- Capture keystrokes, form inputs, and screen content
- Redirect the victim to a phishing page
- Modify the DOM to deceive the victim

The only reliable way to prevent these outcomes is to prevent the XSS in the first place.

---

## 8. Testing for Prevention

Testing XSS prevention is an ongoing process, not a one-time check. A layered testing strategy catches different classes of vulnerability at different stages.

### 8.1 Unit Testing for Output Encoding

Write unit tests that verify encoding functions produce correct output for known-dangerous inputs:

```python
import unittest
from markupsafe import escape

class TestOutputEncoding(unittest.TestCase):

    def test_html_encodes_angle_brackets(self):
        self.assertEqual(str(escape('<script>')), '&lt;script&gt;')

    def test_html_encodes_ampersand(self):
        self.assertEqual(str(escape('a & b')), 'a &amp; b')

    def test_html_encodes_quotes(self):
        self.assertEqual(str(escape('"quoted"')), '&#34;quoted&#34;')

    def test_preserves_normal_text(self):
        self.assertEqual(str(escape('Hello World')), 'Hello World')
```

Also test that your template rendering helpers pass these encoded values through correctly.

### 8.2 Code Review

Code review for XSS focuses on **tracing data flow from source to sink**. Key questions:

- Where is user-controlled data accepted? (sources)
- Where is that data output to a response or to the DOM? (sinks)
- What encoding or sanitisation is applied between source and sink?
- Is the encoding appropriate for the output context?
- Are there any uses of unsafe APIs (`innerHTML`, `dangerouslySetInnerHTML`, `eval`, `v-html`, `|safe`, etc.)?

**Code review checklist for XSS:**

```
[ ] All user-supplied values are encoded before output
[ ] Encoding matches the output context (HTML, JS, URL, CSS, attribute)
[ ] No use of innerHTML/document.write/eval with user data
[ ] Framework escape hatches (dangerouslySetInnerHTML, v-html, |safe) are audited
[ ] URL-accepting attributes validate the scheme
[ ] CSP is configured and tested
[ ] Cookie flags are set correctly
```

### 8.3 Static Application Security Testing (SAST)

SAST tools analyse source code without executing it, looking for patterns that suggest insecure data flow:

| Tool | Language | Notes |
|---|---|---|
| Semgrep | Multi-language | Highly configurable; extensive XSS rule sets available |
| Bandit | Python | Good for detecting `eval`, `exec`, unsafe template usage |
| ESLint (security plugins) | JavaScript | `eslint-plugin-security`, `no-unsanitized` plugin |
| SonarQube / SonarCloud | Multi-language | Commercial; XSS taint analysis rules |
| CodeQL | Multi-language | GitHub's analysis engine; taint tracking across files |

SAST produces false positives and may miss context-sensitive vulnerabilities. Use it as a forcing function to review suspicious patterns, not as a definitive verdict.

### 8.4 Dynamic Application Security Testing (DAST)

DAST tools interact with a running application, inserting probe inputs and analysing responses for reflected or executed payloads:

| Tool | Type | Notes |
|---|---|---|
| OWASP ZAP | Open source | Active scan includes XSS detection |
| Burp Suite Pro | Commercial | Comprehensive scanner with active XSS detection |
| Nikto | Open source | Basic scanner; limited XSS detection |
| Nuclei | Open source | Template-based; community XSS templates available |

DAST is limited to the application surface the tool can reach. Authenticated areas, SPAs, and DOM-based sinks (which don't involve server responses) may require manual testing or browser-based tooling.

### 8.5 Burp Suite Manual Verification

For targeted manual testing:

1. **Proxy:** Intercept all requests and responses. Identify reflection points.
2. **Repeater:** Send individual requests with probe payloads and inspect the raw response to confirm reflection and encoding.
3. **DOM Invader:** Browser extension (Burp's built-in Chromium) that automatically identifies DOM sources and sinks and traces data flow in client-side JavaScript.
4. **Active Scanner:** Run on specific endpoints after confirming they accept user input.

### 8.6 Browser-Based Testing

After confirming reflection:

1. Open the page in the browser.
2. Use **Inspector (Elements tab)** to view the parsed DOM — what the browser built from the HTML, not the raw source. This shows whether your input was placed in a text node (safe) or in an element's HTML (potentially unsafe).
3. Use the **Console** to check for JavaScript errors that indicate near-execution (e.g., syntax errors from partially-broken injection attempts).
4. Check the **Network tab** to confirm CSP headers are present and correctly configured.
5. Use the **Application tab** to verify cookie flags (`HttpOnly`, `Secure`, `SameSite`).

---

## 9. Defence-in-Depth Checklist

Use this checklist as a developer reference during design, implementation, and review.

### Output Encoding

```
[ ] User-supplied data is never inserted into HTML without context-appropriate encoding
[ ] HTML encoding applied for HTML body context
[ ] Attribute encoding applied for HTML attribute context (including quote character)
[ ] JavaScript encoding (JSON serialisation) applied for script contexts
[ ] URL scheme validated for URL-context attributes (href, src, action)
[ ] CSS values validated or restricted to an allowlist
[ ] No use of HTML entity encoding as a substitute for JavaScript encoding
```

### Sanitisation

```
[ ] Sanitisation is used only where rich HTML input is genuinely required
[ ] Sanitisation uses an allowlist-based library (DOMPurify, bleach, etc.)
[ ] Sanitisation library is up to date and monitored for CVEs
[ ] Sanitised output is verified to not double-encode when placed in a template
```

### Framework Usage

```
[ ] Framework default encoding is not disabled globally
[ ] Every use of dangerouslySetInnerHTML (React) is documented and reviewed
[ ] Every use of v-html (Vue) is documented and reviewed
[ ] Every use of bypassSecurityTrust* (Angular) is documented and reviewed
[ ] Every template |safe / raw filter is documented and reviewed
[ ] Server-side templates do not construct JavaScript strings via interpolation
```

### DOM Safety

```
[ ] No assignment to innerHTML from user-controlled data
[ ] No use of document.write in active code
[ ] No use of eval, new Function(), or setTimeout/setInterval with string args
[ ] DOM sources (location.hash, URLSearchParams, document.referrer) are sanitised before reaching any DOM sink
[ ] postMessage handlers validate origin before processing data
```

### Content Security Policy

```
[ ] CSP header is present on all application responses
[ ] script-src uses nonces or hashes (not unsafe-inline)
[ ] unsafe-eval is not present unless specifically justified
[ ] CSP is validated using CSP Evaluator
[ ] Report-Only mode was used during CSP rollout; violations monitored
```

### Cookie Security

```
[ ] Session cookies have HttpOnly flag
[ ] Session cookies have Secure flag
[ ] Session cookies have SameSite=Strict or SameSite=Lax
[ ] Sensitive cookies are not accessible to JavaScript
```

### Testing

```
[ ] Unit tests cover encoding helper functions
[ ] Code review process includes XSS-specific data flow analysis
[ ] SAST tooling is integrated into CI pipeline
[ ] DAST scan is run against staging environment before release
[ ] Manual testing performed on high-risk input/output paths
[ ] Browser Developer Tools used to verify DOM rendering and cookie flags
```

---

## 10. Key Takeaway Summary

XSS prevention is not a single control — it is a layered security model where each layer handles what the previous one cannot.

### The Hierarchy

```
1. Output encoding          ← Primary XSS control. Solves the root cause.
                              Must be context-aware: HTML, JS, URL, CSS.

2. Input validation         ← Reduces attack surface for business logic.
                              Not a substitute for output encoding.

3. Sanitisation             ← Applied only when accepting rich HTML.
                              Use allowlist-based libraries only.

4. Safe framework defaults  ← Auto-escaping templates and DOM APIs.
                              Never bypass without explicit justification.

5. Content Security Policy  ← Limits impact if injection occurs.
                              Nonce-based; no unsafe-inline.

6. Cookie flags             ← Limits session hijacking impact.
                              HttpOnly + Secure + SameSite=Strict.

7. Continuous testing       ← Finds gaps before attackers do.
                              Code review + SAST + DAST + manual.
```

### The Three Rules

**Rule 1 — Encode for context.** There is no universal sanitiser. The encoding applied to user data must match the parser that will process it. HTML encoding in a JavaScript context provides no protection.

**Rule 2 — Never trust data based on its source.** A value from your own database is still user-controlled if it was originally provided by a user. Encode it on the way out, regardless of where it came from.

**Rule 3 — CSP is insurance, not the plan.** A strict CSP is valuable, but an application that relies on CSP to prevent XSS is one encoding mistake away from a bypass. Prevention at the encoding layer removes the dependency on the browser enforcing the policy.

---

## References and Further Reading

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP DOM-based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Content Security Policy](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [PortSwigger Web Security Academy — XSS](https://portswigger.net/web-security/cross-site-scripting)
- [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- [DOMPurify](https://github.com/cure53/DOMPurify)
- [React — Security considerations](https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html)
- [Angular — Security guide](https://angular.io/guide/security)

---

*This document is part of the [`web-security-notes`](../) repository. It is intended for educational use, secure development reference, and security learning. See [`bypass-techniques.md`](./bypass-techniques.md) for the complementary attacker-perspective analysis.*