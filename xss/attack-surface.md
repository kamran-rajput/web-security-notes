# XSS Attack Surface

> Where to look, what to test, and how to identify XSS injection points systematically.

---

## What is an Attack Surface?

The attack surface is every point in an application where user-controlled input can influence the output returned to the browser. If your input appears anywhere in the response — visible or hidden — it is a potential XSS injection point.

```
User Input → Server Processes → Response → Browser Renders
                                    ↑
                          Every reflection here
                          is a potential XSS point
```

---

## 1. Finding Reflection Points

Before any payload, answer one question:

> **Where exactly does my input appear in the page source?**

### Step 1 — Submit a Unique Identifier

Send a unique recognizable string in every input field:

```
xsstest123
```

Then open **View Page Source** (`CTRL+U`) and search for `xsstest123`. Every place it appears is a reflection point and a potential injection context.

### Step 2 — Identify the Context

For each reflection, determine exactly what surrounds your input:

```html
<!-- Context 1: Between HTML tags -->
<p>You searched for: xsstest123</p>

<!-- Context 2: Inside an attribute value -->
<input value="xsstest123">

<!-- Context 3: Inside a JavaScript string -->
<script>var query = 'xsstest123';</script>

<!-- Context 4: Inside a JavaScript template literal -->
<script>var msg = `Results for xsstest123`;</script>

<!-- Context 5: Inside an href attribute -->
<a href="https://site.com/?q=xsstest123">

<!-- Context 6: Inside an HTML comment -->
<!-- User searched for: xsstest123 -->
```

Each context requires a completely different payload. Context identification is the most important step.

---

## 2. Common Input Vectors

### URL Parameters
```
https://site.com/search?q=xsstest123
https://site.com/profile?name=xsstest123
https://site.com/redirect?url=xsstest123
https://site.com/page?id=xsstest123
```
Test every query parameter. Each one may be reflected differently.

### URL Path
```
https://site.com/user/xsstest123
https://site.com/category/xsstest123/products
```
Some applications reflect the URL path directly into the page.

### URL Fragment
```
https://site.com/page#xsstest123
```
Fragments are processed client-side only — never reach the server. Look for JavaScript that reads `location.hash` and writes it to the DOM.

### HTTP Headers
```
Referer: https://xsstest123.com
User-Agent: xsstest123
X-Forwarded-For: xsstest123
Accept-Language: xsstest123
```
Some applications log and display these values in admin panels or error pages.

### Form Fields
```
Search boxes
Login forms (username field)
Registration forms (name, email, address)
Comment and feedback forms
Contact forms
Profile update forms
```

### File Uploads
```
Filename:    xsstest123.jpg
File content: SVG files can contain JavaScript
EXIF data:   Some apps display metadata
```

### JSON and API Inputs
```json
{"name": "xsstest123", "email": "test@test.com"}
```
API responses often feed data back into the frontend. Test every field.

---

## 3. Stored XSS Surface

Stored XSS requires finding places where input is **saved** and later **displayed** to other users.

| Feature | What to Test |
|---|---|
| Blog comments | Name, email, website URL, comment body |
| User profiles | Username, bio, location, website |
| Product reviews | Title, review text, reviewer name |
| Forum posts | Post title, body, signature |
| Support tickets | Subject, message body |
| Chat messages | Any real-time messaging feature |
| Admin panels | Any user-submitted data displayed to admins |
| Error logs | Input that appears in server error messages |
| Email notifications | Data reflected in notification emails |

> **Key insight:** Always check if your input is displayed to OTHER users — admins, other customers, support staff. Stored XSS hitting an admin account is critical severity.

---

## 4. DOM-Based XSS Surface

DOM XSS happens entirely client-side. The server never sees the payload.

### JavaScript Sources — Where Attacker Data Enters

These are the most common places tainted data enters the DOM:

```javascript
document.URL
document.location
document.location.href
document.location.search
document.location.hash
document.referrer
window.name
location.search
location.hash
```

### JavaScript Sinks — Where Data Gets Executed

These are the dangerous functions that execute whatever is passed to them:

```javascript
// HTML sinks
document.write()
document.writeln()
element.innerHTML
element.outerHTML
element.insertAdjacentHTML()

// JavaScript execution sinks
eval()
setTimeout()
setInterval()
Function()
execScript()

// URL sinks
document.location
location.href
location.replace()
location.assign()

// jQuery sinks
$()
$.html()
$.append()
$.prepend()
$.after()
$.before()
```

### How to Find DOM XSS

```
1. Open browser DevTools
2. Search page source for dangerous sinks (innerHTML, eval, document.write)
3. Trace backwards — what data feeds into that sink?
4. Is any of that data user-controllable?
5. If yes → DOM XSS candidate
```

---

## 5. Less Obvious Attack Surface

### Canonical Tags
```html
<link rel="canonical" href="https://site.com/[URL REFLECTED HERE]"/>
```
The page URL is often reflected into the canonical tag. Single quotes may not be filtered.

### Meta Tags
```html
<meta name="description" content="[USER INPUT HERE]">
<meta property="og:title" content="[USER INPUT HERE]">
```
Search terms and page titles often appear here.

### JavaScript Variables
```html
<script>
    var config = {
        userId: '[USER INPUT]',
        searchTerm: '[USER INPUT]',
        returnUrl: '[USER INPUT]'
    };
</script>
```
View source and look for user-supplied data embedded in script blocks.

### Hidden Form Fields
```html
<input type="hidden" name="returnUrl" value="[USER INPUT]">
<input type="hidden" name="username" value="[USER INPUT]">
```
Hidden does not mean safe. These values are still reflected and modifiable.

### HTTP Response Headers
```
X-Custom-Header: [USER INPUT]
```
Some applications reflect user input in custom response headers which can create injection points.

### Error Messages
```
Error: User "xsstest123" not found.
404: Page /xsstest123 does not exist.
```
Error pages often reflect the invalid input directly back without sanitization.

---

## 6. Attack Surface Mapping Checklist

Use this checklist on every target:

```
URL PARAMETERS
☐ Test every query parameter with unique identifier
☐ Check page source for all reflection points
☐ Test URL path segments
☐ Test URL fragment (#) — check for location.hash usage in JS

HTTP HEADERS
☐ Test User-Agent
☐ Test Referer
☐ Test X-Forwarded-For
☐ Test Accept-Language
☐ Test any custom headers the app uses

FORMS
☐ Test every visible input field
☐ Test hidden input fields (modify via DevTools)
☐ Test form field names, not just values
☐ Test file upload filenames

STORED VECTORS
☐ Test all comment/feedback functionality
☐ Test profile fields
☐ Test any data visible to other users
☐ Test data visible to admins

DOM ANALYSIS
☐ Search JS source for dangerous sinks
☐ Check for location.hash reading
☐ Check for document.write usage
☐ Check for innerHTML assignments
☐ Check jQuery selectors fed with user data

HIDDEN SURFACES
☐ Check canonical and meta tags in page source
☐ Check JavaScript variable assignments in script blocks
☐ Check error pages with invalid input
☐ Check 404 pages
```

---

## 7. Tools for Surface Discovery

| Tool | Purpose |
|---|---|
| **Burp Suite Proxy** | Intercept and modify every request |
| **Burp Suite Scanner** | Automated reflection detection |
| **Burp Intruder** | Systematic parameter testing |
| **Browser DevTools** | DOM inspection, JS source analysis |
| **View Page Source** | Find all reflection points |
| **grep / ripgrep** | Search JS files for dangerous sinks |

---

## Key Principle

> **Every place the application reflects user input is a candidate. The context of that reflection determines the technique. The filters in place determine the bypass needed.**

Map first. Exploit second.

---

*Next → [Methodology](./methodology.md) — the systematic step-by-step testing process*