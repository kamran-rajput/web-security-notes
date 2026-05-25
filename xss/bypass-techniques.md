# XSS Filter Bypass Techniques

> **Scope:** This document covers the *methodology* behind XSS filter bypasses — why they work, how to reason about them by injection context, and how defenders can build more reliable protections. All payload examples are intentionally minimal and educational. This is not an exploit repository.

---

## Table of Contents

1. [Why XSS Filters Fail](#1-why-xss-filters-fail)
2. [Recon Before Bypassing](#2-recon-before-bypassing)
3. [Common Filter Bypass Categories](#3-common-filter-bypass-categories)
4. [Context-Specific Bypass Thinking](#4-context-specific-bypass-thinking)
5. [WAF Bypass Methodology (Conceptual)](#5-waf-bypass-methodology-conceptual)
6. [Common Mistakes Beginners Make](#6-common-mistakes-beginners-make)
7. [Defensive Takeaway](#7-defensive-takeaway)

---

## 1. Why XSS Filters Fail

Understanding *why* filters fail is more valuable than knowing any single payload. Most filter failures trace back to a small set of root causes.

### 1.1 Blacklisting Is Fundamentally Incomplete

A blacklist encodes the author's assumptions about what "bad input" looks like at the time of writing. The HTML specification, however, is permissive by design — browsers accept malformed markup, recover gracefully from broken tags, and support dozens of ways to express the same semantic. No finite blacklist can capture every valid browser interpretation.

```
# Naïve blacklist blocks:
<script>

# Browser also executes JavaScript via:
<img onerror=...>
<svg onload=...>
<details ontoggle=...>
<iframe srcdoc=...>
javascript: URIs in href attributes
... and many more
```

Every time a new HTML element or attribute gains browser support, the blacklist silently becomes stale.

### 1.2 Regex Limitations

Regular expressions operate on flat strings; HTML has hierarchical, context-sensitive structure. This creates several systematic failure modes:

| Failure Mode | Example |
|---|---|
| Case insensitivity missed | `<SCRIPT>` passes a lowercase-only pattern |
| Greedy/lazy mismatch | `<script.*?>` fails on multi-line input or nested comments |
| Encoding blindness | `%3Cscript%3E` is not matched by a literal `<script>` regex |
| Whitespace tolerance | `<script \n>` passes patterns that expect no whitespace |
| Attribute order assumptions | `<img src=x onerror=…>` vs `<img onerror=… src=x>` |

Regexes also cannot reliably parse the same HTML that browsers parse, because browser parsing is a stateful process defined by a complex specification — not a regular grammar.

### 1.3 Browser Parsing Differences

Browsers implement the [WHATWG HTML Living Standard](https://html.spec.whatwg.org/), which defines specific error-recovery behaviour for malformed markup. This means browsers *intentionally* fix broken HTML before rendering it. A filter that evaluates a raw string may see something structurally different from what the browser's parser ultimately produces.

```html
<!-- Filter sees: looks harmless -->
<img src=x onerror
="alert(1)">

<!-- Browser parser: reassembles the attribute across the newline and executes it -->
```

This divergence between "what the filter checks" and "what the browser renders" is the core mechanism behind most structural bypasses.

### 1.4 Context Confusion

Filters that apply a single transformation to all user input ignore the fact that the same string has different meanings depending on where it is inserted. A string reflected into a JavaScript variable context, a URL attribute, an HTML body, or a CSS value each requires different escaping. Generic filters that treat all output the same are almost always wrong in at least one context.

### 1.5 Encoding Normalization Problems

Web applications frequently decode or re-encode user input multiple times as it flows through layers: URL decode at the edge, HTML entity decode in the template engine, JavaScript string decode in the browser. A filter applied at one layer may be bypassed by encoding the payload so that it is harmless *at the filter layer* but becomes executable after subsequent normalization.

```
Input:   %3Cscript%3Ealert(1)%3C%2Fscript%3E
After URL decode (by framework, after filter):  <script>alert(1)</script>
```

### 1.6 Why Filtering Input Is Unreliable Alone

Input filtering attempts to solve an output problem. The correct question is not "is this input dangerous?" but "is this output safe in this context?" The same input string may be safe in one output context and dangerous in another. This is why the security community's consensus is **output encoding first, input validation second**.

---

## 2. Recon Before Bypassing

Effective security testing of XSS filters is methodical, not random. The goal is to build an accurate mental model of the application's filtering and encoding behaviour before crafting any bypass.

### 2.1 Identify Reflection Points

Locate every place where user-controlled data appears in a response. Common reflection vectors include:

- Query string parameters
- Form fields (including hidden fields)
- HTTP headers reflected in the body (e.g., `Referer`, `User-Agent`, custom headers)
- Path segments and file names
- JSON responses consumed by client-side JavaScript
- Error messages and validation feedback

Use a unique marker (e.g., `xsstest1234`) to trace which inputs reach which output locations. Burp Suite's Intruder or a manual search across the response body both work well.

### 2.2 Determine Injection Context

Before crafting any payload, identify *where* in the response your input lands:

```
Context                  Example
─────────────────────────────────────────────────────────
HTML body                <p>Hello, [INPUT]</p>
HTML attribute (unquoted) <input value=[INPUT]>
HTML attribute (quoted)   <input value="[INPUT]">
JavaScript variable       var name = "[INPUT]";
JavaScript block          <script>[INPUT]</script>
URL in href/src           <a href="[INPUT]">
Style attribute           <div style="color:[INPUT]">
Inside a comment          <!-- [INPUT] -->
JSON response             {"name":"[INPUT]"}
```

Context determines which characters are meaningful and which escape sequences apply.

### 2.3 Inspect Response Transformation

Compare input to output character by character. Useful questions:

- Are angle brackets encoded as `&lt;` / `&gt;`?
- Are quotes encoded as `&quot;` or `&#x27;`?
- Are specific keywords (e.g., `script`, `onerror`) stripped, replaced, or blocked with an error?
- Is the transformation applied to the raw input or to a decoded version of it?
- Does the transformation happen before or after URL decoding?

Send a probe string that covers a wide range of characters: `<>"'/\;(){}`.

### 2.4 Test Character Filtering

Send individual characters and character sequences to understand the filter's vocabulary:

```
Probe: <>
Probe: <script>
Probe: <SCRIPT>
Probe: <scr<script>ipt>   ← tests whether stripping is recursive
Probe: %3C%73cript%3E     ← URL-encoded
Probe: &#60;script&#62;   ← HTML entity-encoded
```

Record which probes pass, which are stripped, and which trigger a block or error.

### 2.5 Identify Encoding Behaviour

Determine how many decoding passes the application performs on input:

- Send double-encoded characters: `%253C` (URL-encode of `%3C`)
- Send HTML entities in attribute contexts
- Mix encoding schemes

If double-encoded input is decoded down to a functional character, the filter operates at a layer above the final decode.

### 2.6 Detect WAF / Sanitization Patterns

Signs of WAF intervention include:

- HTTP 403 responses for specific payloads
- Response body alterations without an application error
- Latency differences for flagged payloads
- Generic error pages that differ from application errors

Signs of server-side sanitization include:

- Input stripped or replaced in the response
- Keywords removed silently
- Consistent behavior regardless of HTTP status code

### 2.7 Tool Assistance

| Tool | Purpose |
|---|---|
| **Burp Suite Proxy** | Intercept and modify requests; replay with variations |
| **Burp Repeater** | Iterate on a single request without automation |
| **Burp Intruder** | Fuzz parameter values with a wordlist |
| **Browser DevTools → Network tab** | Inspect raw responses before browser rendering |
| **Browser DevTools → Inspector** | See the parsed DOM — what the browser actually interpreted |
| **Browser DevTools → Console** | Check for JS errors that indicate near-execution |

The browser Inspector is especially important: it shows the *rendered* DOM, not the raw HTML. This helps distinguish between "input was reflected" and "input was executed."

---

## 3. Common Filter Bypass Categories

The categories below represent classes of technique rather than specific payloads. For each, the explanation of *why it works* matters more than any individual example.

---

### 3.1 Case Mutation

**Concept:** HTML attribute names and tag names are case-insensitive in browsers but may be compared case-sensitively in filters.

```html
<!-- If filter only blocks lowercase: -->
<sCrIpT>...</sCrIpT>
<IMG SRC=x ONERROR="...">
```

**Why it works:** The HTML parser normalises tag and attribute names to lowercase internally. A filter doing a literal string comparison against `<script>` will not match `<ScRiPt>`.

---

### 3.2 Tag Mutation

**Concept:** Filters that block a specific set of tags can be bypassed by using lesser-known tags that also support event handlers or JavaScript execution.

```html
<!-- Common targets beyond <script>: -->
<svg onload="...">
<details ontoggle="...">
<video onerror="...">
<math><annotation-xml encoding="text/html"><img src=x onerror="..."></annotation-xml></math>
```

**Why it works:** The browser supports JavaScript execution through event handlers on nearly any HTML element. Filters focused on `<script>` miss the broader attack surface.

---

### 3.3 Attribute-Based Execution

**Concept:** Many HTML elements accept event handler attributes that execute JavaScript when browser-triggered conditions are met — no explicit `<script>` tag required.

```html
<img src="x" onerror="...">       <!-- fires when image fails to load -->
<body onload="...">                <!-- fires on page load -->
<input onfocus="..." autofocus>    <!-- fires on auto-focus -->
<select onchange="...">            <!-- fires on value change -->
```

**Why it works:** Event handler attributes (`on*`) are a core part of the HTML event model. Disabling them would break legitimate web applications, so browsers will always support them.

---

### 3.4 Event Handler Abuse

**Concept:** Even if a filter strips known event handlers, there are many handlers that receive less attention.

```html
<!-- Less commonly filtered handlers: -->
<div onpointerenter="...">
<marquee onstart="...">
<object onerror="...">
<table background="javascript:...">  <!-- legacy, browser-dependent -->
```

**Why it works:** The HTML specification defines dozens of event types. Security filters rarely enumerate all of them, and new ones are added as the web platform evolves.

---

### 3.5 Quote Breaking

**Concept:** When input is reflected inside a quoted HTML attribute, injecting the quote character used to delimit the attribute can break out of the value context and inject new attributes.

```html
<!-- Template: <input value="USER_INPUT"> -->
<!-- Input: " onfocus="..." autofocus="  -->
<!-- Result: <input value="" onfocus="..." autofocus=""> -->
```

**Why it works:** The browser's attribute parser ends the current value at the first matching quote. If the filter does not encode quotes in attribute contexts, the attacker controls the attribute boundary.

---

### 3.6 HTML Entity Encoding

**Concept:** HTML entities are decoded by the browser's HTML parser *before* JavaScript is executed. Encoding characters in certain contexts allows them to reach the browser's parser intact, then be decoded into functional characters.

```html
<!-- Inside an HTML attribute context, browsers decode entities: -->
<a href="javascript&#x3A;...">click</a>
<!--               ^^^ = colon, decoded by parser before href is evaluated -->
```

**Why it works:** Entity decoding is a browser parsing step, not a JavaScript execution step. Filters checking the raw string see `&#x3A;` and may not recognise it as a colon; the browser sees `:` after decoding.

This technique is context-sensitive: entity decoding happens in HTML contexts, not inside `<script>` blocks.

---

### 3.7 URL Encoding

**Concept:** In URL contexts (e.g., `href`, `src`, `action` attributes), browsers decode percent-encoded characters before using them. Encoding key characters in a URL-context payload may bypass filters checking the raw string.

```
javascript%3Aalert(1)   →  javascript:alert(1)  (after URL decode)
```

**Why it works:** The browser's URL parser performs percent-decoding as part of URL resolution, downstream of any filter operating on the raw input string.

---

### 3.8 JavaScript Protocol Tricks

**Concept:** The `javascript:` URI scheme causes the browser to evaluate the remainder of the URL as JavaScript when navigated to or embedded in certain attributes.

```html
<a href="javascript:void(0)">         <!-- legitimate use -->
<a href="javascript:...">             <!-- execution if user clicks -->
<iframe src="javascript:...">         <!-- executes on load in some contexts -->
```

**Why it works:** The `javascript:` protocol is a first-class browser feature, not an exploit. Filters must explicitly detect and neutralise it in URL-accepting attributes.

---

### 3.9 Malformed HTML Recovery Behaviour

**Concept:** Browsers implement detailed error-recovery rules for malformed HTML, as specified in the WHATWG parsing standard. This means a deliberately broken tag may be "repaired" into a functional one by the parser.

```html
<!-- Input with deliberately broken syntax: -->
<img src=x onerror
  ="...">

<!-- Angle bracket in unexpected position: -->
<<script>alert(1)</script>

<!-- Unclosed tag recovery: -->
<svg><script>...</script>
```

**Why it works:** The browser parser must handle real-world malformed HTML from decades of legacy web content. Its error recovery is deterministic and exploitable. A filter evaluating the raw broken string may reach a different conclusion than the browser parser.

---

### 3.10 Nested Tags

**Concept:** If a filter strips a matched tag from input without repeating the check, a payload that contains the target string nested inside itself will survive one pass of stripping with the inner string exposed.

```html
<!-- Filter strips <script>...</script> once: -->
Input:   <scr<script>ipt>...</scr</script>ipt>
After:   <script>...</script>
```

**Why it works:** The filter performs a non-recursive match-and-strip. After removing the inner `<script>`, the outer string assembles into a new `<script>` tag that the filter has already passed.

---

### 3.11 Broken Parser Edge Cases

**Concept:** The difference between the browser's full HTML5 parser and a simplified filter's string matching creates edge cases where structurally unusual input is treated differently by each.

```html
<!-- NULL byte between tag and attribute (historical): -->
<img[NULL]src=x onerror=...>

<!-- Tab character instead of space in attribute: -->
<img	src=x	onerror=...>

<!-- Attribute without quotes: -->
<img src=x onerror=...>

<!-- Self-closing syntax on non-void elements: -->
<div/onmouseover=...>
```

**Why it works:** The HTML5 parsing specification defines precise rules for how whitespace, null bytes, and other characters are treated inside tags. Filters using simpler string-matching or less complete regexes may not implement these rules faithfully.

---

### 3.12 Null Byte and Separator Edge Cases (Historical Context)

**Concept:** Historically, some languages and frameworks treated a null byte (`\x00`) as a string terminator. Injecting a null byte into a payload could cause the filter (operating in a null-terminated string context) to see a truncated, safe-looking string, while the application continued processing the full payload.

```
<scr\x00ipt>  →  Filter sees: <scr  |  Application sees: <script>
```

**Current status:** Modern languages (Python, Java, JavaScript/Node.js, Ruby) use length-prefixed strings, not null-terminated ones. This technique is mostly a historical artefact relevant to older C-based applications or CGI scripts. Its inclusion here is for completeness and to illustrate how implementation language affects filter behaviour.

---

### 3.13 DOM Sink Abuse Patterns

**Concept:** DOM-based XSS does not involve server-side reflection at all. The payload travels directly from a browser-accessible source (e.g., `location.hash`, `document.URL`, `document.referrer`) to a JavaScript sink that writes to the DOM — entirely within the browser. Server-side filters never see this data.

```
Sources (browser-readable input):
  location.hash
  location.search
  document.referrer
  window.name
  postMessage data

Dangerous Sinks (write to DOM/execute code):
  element.innerHTML = ...
  document.write(...)
  eval(...)
  setTimeout("string", ...)
  element.src = ...
  location.href = ...
```

**Why it works:** Server-side filtering operates on HTTP request/response data. DOM sources exist only in the browser environment. Any sanitisation must therefore happen in client-side JavaScript, at the point where source data is read and before it reaches a sink.

DOM-based XSS requires code review and client-side static analysis, not just server-side output encoding.

---

## 4. Context-Specific Bypass Thinking

The single most important concept in XSS bypass methodology is **injection context**. The same payload that works in one context is useless — or requires different treatment — in another. This section maps context to the relevant questions and techniques.

---

### 4.1 HTML Body Context

**Where:** Your input appears as text content between tags.

```html
<p>Hello, [INPUT]</p>
```

**Questions to ask:**
- Are `<` and `>` encoded? If not, you can inject new tags.
- Are HTML entities decoded? If yes, `&lt;` → `<` is a potential path in.

**Relevant techniques:** Tag injection, event handler abuse, entity encoding.

---

### 4.2 Attribute Context (Quoted)

**Where:** Your input appears inside a quoted HTML attribute value.

```html
<input type="text" value="[INPUT]">
<a href="[INPUT]">
```

**Questions to ask:**
- Is the quote character (` " ` or ` ' `) encoded in output? If not → quote breaking.
- Is this a URL-accepting attribute (`href`, `src`, `action`, `formaction`)? If yes → `javascript:` protocol.
- Are HTML entities decoded here? If yes, entity-encoded characters can be decoded into the delimiter.

**Relevant techniques:** Quote breaking, `javascript:` protocol, entity encoding.

---

### 4.3 Attribute Context (Unquoted)

**Where:** Input is reflected without surrounding quotes.

```html
<input value=[INPUT]>
```

**Questions to ask:**
- What ends the attribute? A space or `>` terminates it. Injecting either can break context.
- Can you inject a new attribute by adding a space?

**Relevant techniques:** Whitespace injection to terminate the attribute and inject new ones.

---

### 4.4 JavaScript Context

**Where:** Input is reflected inside a JavaScript block or string literal.

```html
<script>
  var username = "[INPUT]";
</script>
```

**Questions to ask:**
- Is the quote character escaped? If not, break out of the string.
- Are backslashes escaped? (`\\` before `"` prevents quote breaking)
- Is `</script>` matched and filtered? (Inserting it terminates the JS block and re-enters HTML context)
- Is this a numeric or boolean context rather than a string? (No quotes to break out of)

**Relevant techniques:** String termination, script block termination via `</script>`, template literal abuse if backticks are used.

```javascript
// If input is in a template literal:
var msg = `Hello [INPUT]`;
// Injection: ${expression} executes the expression
```

> **Note:** HTML entity encoding does *not* protect JavaScript string contexts. `&quot;` is not interpreted as a quote by JavaScript; it is interpreted by the HTML parser. In a `<script>` block, the HTML parser does minimal processing, so entity encoding provides no sanitisation.

---

### 4.5 URL Context

**Where:** Input is placed directly into a URL or URL-accepting attribute.

```html
<a href="[INPUT]">
<img src="[INPUT]">
<script src="[INPUT]">
```

**Questions to ask:**
- Can you inject a `javascript:` URI?
- Can you inject a `data:` URI for image contexts?
- Is the scheme validated (must start with `http://` or `https://`)?
- Are path traversal sequences relevant here?

**Relevant techniques:** `javascript:` protocol, URL encoding, double encoding if the URL is decoded multiple times.

---

### 4.6 CSS Context

**Where:** Input is reflected inside a style block or attribute.

```html
<div style="background-color: [INPUT]">
<style>
  .user { color: [INPUT]; }
</style>
```

**Questions to ask:**
- Does the browser in scope support CSS expressions? (IE legacy only; largely historical)
- Can you close the style context and inject HTML?
- Can `url()` be used to load external resources or trigger requests?

**Relevant techniques:** Context escape via `}` and `<`, CSS `url()` injection for data exfiltration in some scenarios. Modern browsers have significantly reduced the CSS attack surface.

---

### 4.7 DOM-Based Sinks

**Where:** Client-side JavaScript reads from a source and writes to a DOM sink without server involvement.

**Questions to ask:**
- Which JavaScript sources are used? (`location.hash`, `URLSearchParams`, `document.referrer`, `postMessage`)
- What sanitisation (if any) is applied before the sink?
- Which sink is used? (`innerHTML` is dangerous; `textContent` is safe; `eval` is dangerous)
- Is this a single-page application using a client-side router?

**Relevant techniques:** Identifying source-to-sink paths through code review or dynamic analysis. Tools like **DOM Invader** (built into Burp Suite's browser) automate taint tracking.

```javascript
// Vulnerable DOM sink pattern:
const name = location.hash.slice(1);       // source
document.getElementById('msg').innerHTML = name;  // sink — dangerous
```

---

## 5. WAF Bypass Methodology (Conceptual)

Web Application Firewalls add a layer of detection on top of application-level filtering. Bypassing a WAF follows a structured methodology — not random payload spraying.

### 5.1 Fingerprinting the Filter

Before testing bypasses, identify what kind of filtering is in place:

- **Block page characteristics:** WAF products tend to have distinctive 403/406 response pages or headers (e.g., `X-Sucuri-ID`, `X-Powered-By: ModSecurity`).
- **Behavioural signatures:** Does the block trigger on keywords, character sequences, or request rate? Does it block the entire request or just sanitise the value?
- **Error differentiation:** Compare responses for a clean request, a soft-probe (e.g., `<`), a hard-probe (e.g., `<script>`), and a nonsense probe. Different responses indicate different detection rules firing.

### 5.2 Differential Testing

Send pairs of requests that differ by a single variable. This isolates which specific element triggers the filter:

```
Test A: <script>              → blocked
Test B: <scrip t>             → not blocked
Test C: <script >             → blocked
Test D: <script\t>            → ?
```

Systematic differential testing maps the exact filter rules more accurately than guessing.

### 5.3 Payload Reduction

Start with a known-blocking payload and reduce it to its minimum triggering form:

```
<script>alert(document.cookie)</script>  → blocked
<script>alert(1)</script>                → blocked
<script>x</script>                       → blocked
<script>                                 → blocked
script                                   → not blocked
<script                                  → blocked
```

The minimal triggering form reveals which token the WAF is matching. This then informs character substitution strategies.

### 5.4 Character Substitution

Once the triggering token is identified, test alternative representations:

| Technique | Example |
|---|---|
| Case variation | `ScRiPt` |
| Whitespace insertion | `<script >` |
| Tab instead of space | `<script\t>` |
| Newline insertion | `<script\n>` |
| HTML entity in attribute | `&#115;cript` (in HTML context) |
| URL encoding (URL context) | `%73cript` |
| Comment insertion (JS context) | `scr/**/ipt` |

Not all substitutions work in all contexts — browser parsing rules determine which alternatives are valid.

### 5.5 Browser-Assisted Execution Paths

WAF rule sets are typically signature-based and biased toward common patterns. Consider execution paths the WAF may not have rules for:

- Less common HTML elements with event handlers
- SVG-specific elements and events
- MathML contexts
- CSS-based data exfiltration (not execution, but relevant in some scenarios)
- postMessage-based DOM sinks (server-side WAF cannot inspect this at all)

### 5.6 Why WAFs Are Imperfect

WAFs operate under fundamental constraints that prevent complete protection:

- **Encrypted traffic:** TLS decryption at the WAF introduces latency and certificate management overhead; not all deployments terminate TLS at the WAF.
- **False positive pressure:** Aggressive rules that block more attacks also block more legitimate traffic, creating business pressure to relax rules.
- **Application-specific context:** A WAF cannot know that a specific parameter is reflected into a JavaScript context and requires different escaping than a parameter reflected into HTML.
- **Evolving specifications:** New HTML, JavaScript, and browser features continuously expand the attack surface faster than WAF vendors can update signatures.
- **Client-side code:** WAFs inspect HTTP traffic; DOM-based XSS executes entirely within the browser.

WAFs are a valuable defence layer, not a replacement for secure coding practices.

---

## 6. Common Mistakes Beginners Make

### 6.1 Trying Random Payloads

Spraying payloads from a generic list without understanding the injection context almost always fails and signals unsystematic testing. A single well-chosen probe that maps the context is more useful than a hundred random payloads.

### 6.2 Ignoring Context

Sending an HTML injection payload into a JavaScript string context, or a `javascript:` URI into a plain HTML body, will never work regardless of how well it bypasses a filter. Context determination must come first.

### 6.3 Not Checking Browser Rendering

Reading the raw HTTP response in Burp Suite is not the same as checking whether the browser executed the payload. A payload may be reflected unmodified into the HTML source but still not execute because:
- The DOM parser puts it in a text node rather than parsing it as markup
- A Content Security Policy blocks execution
- The injection is inside a `<noscript>` block or an inert context

Always verify execution in the browser's Inspector and Console, not just in the raw source.

### 6.4 Misunderstanding Encoding

A common mistake is applying HTML entity encoding in a JavaScript context (where it provides no protection) or URL encoding in an HTML body (where it may not be decoded). Each encoding scheme applies to a specific decoding step in the browser's processing pipeline. Matching the encoding to the context is essential.

### 6.5 Confusing Reflection with Execution

Confirming that input is reflected in the response does not confirm XSS. Execution requires:

1. The reflected content to be in an executable context
2. No encoding that neutralises the payload
3. Successful browser parsing of the injected syntax
4. No CSP or other client-side control blocking execution

Test for execution separately from reflection.

### 6.6 Stopping After the First Block

A single blocked payload does not mean the application is fully protected. Different parameters, headers, and paths may have different filter configurations. Different encoding schemes may bypass the same filter. Methodical testing continues past the first blocked attempt.

---

## 7. Defensive Takeaway

Understanding bypass techniques is useful for building better defences. Here is how the techniques in this document map to reliable mitigations.

### 7.1 Output Encoding Beats Blacklisting

The authoritative defence against XSS is **context-aware output encoding**:

| Output Context | Encoding Required |
|---|---|
| HTML body | HTML entity encode: `<` → `&lt;`, `>` → `&gt;`, `&` → `&amp;` |
| HTML attribute (quoted) | HTML entity encode the delimiter: `"` → `&quot;` |
| JavaScript string | JavaScript string escape: `\`, `"`, `'`, newlines |
| URL | Percent-encode all characters except those allowed by the URL scheme |
| CSS | CSS hex escape for all non-alphanumeric characters |

Output encoding addresses the root cause: it neutralises the injection regardless of what the input looks like, because it ensures that the inserted data is always interpreted as *data* by the parser, never as *markup or code*.

Blacklisting fails because it attempts to enumerate and block all possible attack patterns — a task that grows harder as the attack surface expands. Output encoding succeeds because it operates on the data semantically.

Well-maintained libraries that implement this correctly include:
- [OWASP Java Encoder](https://owasp.org/www-project-java-encoder/)
- [DOMPurify](https://github.com/cure53/DOMPurify) (client-side HTML sanitisation)
- [Bleach](https://bleach.readthedocs.io/) (Python)
- Framework built-in escaping: Django templates, Rails ERB, React JSX (all escape by default)

### 7.2 Content Security Policy (CSP)

CSP is a browser-enforced policy delivered via the `Content-Security-Policy` HTTP header. It instructs the browser to only execute scripts from approved sources, disabling inline scripts and `javascript:` URIs by default.

```
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com;
```

**Strengths:**
- Provides a meaningful second layer even when XSS occurs
- Blocks `javascript:` URI execution
- Can prevent data exfiltration via `connect-src`

**Limitations:**
- `unsafe-inline` or `unsafe-eval` in the policy defeats most protections
- JSONP endpoints on allow-listed domains can be abused for script injection
- DOM-based XSS that avoids `eval` may bypass CSP entirely
- Requires careful configuration; permissive policies are common
- Does not prevent the XSS from occurring — only limits its impact

CSP is a mitigation, not a fix. Correct output encoding must come first.

### 7.3 Sanitisation Libraries

When rich HTML input *must* be accepted (e.g., a WYSIWYG editor), the correct approach is to parse the input as HTML and whitelist safe elements and attributes, then re-serialise it. This is fundamentally different from blacklist-based filtering.

**DOMPurify** is the current community standard for client-side sanitisation. It parses the HTML in a sandboxed context, strips everything that is not on its allow-list, and returns safe HTML.

```javascript
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(userInput);
element.innerHTML = clean;
```

Key properties of a good sanitisation library:
- Uses a real HTML parser (not regex)
- Operates on an allow-list of safe elements and attributes
- Maintained and updated as new attack vectors emerge
- Actively developed with a security-focused maintainer

### 7.4 Secure Templating

Most modern web frameworks use templating engines that **auto-escape output by default**. This means that inserting a variable into a template automatically applies HTML encoding without the developer needing to remember to do so.

```html
<!-- Django template: automatically HTML-encoded -->
<p>Hello, {{ username }}</p>

<!-- Explicit unescaped rendering requires deliberate opt-in: -->
<p>{{ body|safe }}</p>    ← developer must consciously decide this is safe
```

Frameworks that escape by default include Django, Ruby on Rails (ERB), ASP.NET Core Razor, and React (JSX). Developers should understand when they are bypassing auto-escaping and ensure that any such bypass is justified and the content has been sanitised through a trusted path.

### 7.5 Defence in Depth

No single control is sufficient. A robust XSS defence combines:

```
Layer 1:  Input validation (reject structurally invalid input; reject formats that have no
          business need, e.g., HTML tags in a name field)

Layer 2:  Context-aware output encoding (the primary XSS control)

Layer 3:  HTML sanitisation where rich content is required (using an allow-list library)

Layer 4:  Content Security Policy (limits blast radius if XSS occurs)

Layer 5:  HttpOnly cookies (prevents cookie theft via XSS)

Layer 6:  SameSite cookies (reduces CSRF; provides some defence against XSS-based CSRF)

Layer 7:  Subresource Integrity (SRI) on external scripts

Layer 8:  Regular security testing (code review, DAST, penetration testing)
```

Understanding how filters fail — the subject of this document — directly informs which of these layers matters most in a given application context.

---

## References and Further Reading

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP DOM-based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [PortSwigger Web Security Academy — XSS](https://portswigger.net/web-security/cross-site-scripting)
- [WHATWG HTML Living Standard — Parsing](https://html.spec.whatwg.org/multipage/parsing.html)
- [Google's XSS Game](https://xss-game.appspot.com/) — for practising in a legal, sandboxed environment
- [DOMPurify](https://github.com/cure53/DOMPurify) — reference implementation of safe HTML sanitisation

---

*This document is part of the [`web-security-notes`](../) repository. It is intended for educational use, CTF practice, and professional security learning. All testing should be performed only on systems you own or have explicit written authorisation to test.*