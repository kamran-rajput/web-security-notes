# 🛡️ Web Security Notes

> **Structured, hands-on security research notes** — not copied cheatsheets.  
> Every concept explained from first principles. Every payload broken down character by character.

<br>

## 👤 About This Repository

I'm **Kamran** — currently working through web security systematically via PortSwigger Web Security Academy, bug bounty programs, and CTF challenges.

This repository documents my **actual learning process** — including the mistakes, the discoveries, and the "why does this actually work" moments that most notes skip over.

> *"Tools find vulnerabilities. Understanding exploits them."*

<br>

## 🗂️ Repository Structure

Each vulnerability follows a consistent structure:

```
vulnerability-name/
├── overview.md          → What it is, how it works, real-world impact
├── attack-surface.md    → Where to look, what to test
├── methodology.md       → Step-by-step testing process
├── payloads.md          → Payloads with full character breakdowns
├── bypass-techniques.md → WAF bypasses, filter evasion
├── prevention.md        → How developers should fix it
└── labs/                → Individual lab writeups with solutions
```

<br>

## 📚 Vulnerability Coverage

> Total Labs Across All Topics: **285 Labs**

### 🖥️ Server-Side Topics

| # | Vulnerability | Total Labs | Status |
|---|---|---|---|
| 01 | SQL Injection | 18 | 🟡 Planned |
| 02 | Authentication | 14 | 🟡 Planned |
| 03 | Path Traversal | 6 | 🟡 Planned |
| 04 | Command Injection | 5 | 🟡 Planned |
| 05 | Business Logic Vulnerabilities | 11 | 🟡 Planned |
| 06 | Information Disclosure | 5 | 🟡 Planned |
| 07 | Access Control | 13 | 🟡 Planned |
| 08 | File Upload Vulnerabilities | 7 | 🟡 Planned |
| 09 | Race Conditions | 6 | 🟡 Planned |
| 10 | Server-Side Request Forgery (SSRF) | 7 | 🟡 Planned |
| 11 | XXE Injection | 9 | 🟡 Planned |
| 12 | NoSQL Injection | 4 | 🟡 Planned |
| 13 | API Testing | 5 | 🟡 Planned |
| 14 | Web Cache Deception | 5 | 🟡 Planned |

### 🌐 Client-Side Topics

| # | Vulnerability | Total Labs | Status |
|---|---|---|---|
| 15 | Cross-Site Scripting (XSS) | 30 | 🟢 In Progress |
| 16 | Cross-Site Request Forgery (CSRF) | 12 | 🟡 Planned |
| 17 | Cross-Origin Resource Sharing (CORS) | 3 | 🟡 Planned |
| 18 | Clickjacking | 5 | 🟡 Planned |
| 19 | DOM-Based Vulnerabilities | 7 | 🟡 Planned |
| 20 | WebSockets | 3 | 🟡 Planned |

### ⚡ Advanced Topics

| # | Vulnerability | Total Labs | Status |
|---|---|---|---|
| 21 | Insecure Deserialization | 10 | 🟡 Planned |
| 22 | Web LLM Attacks | 7 | 🟡 Planned |
| 23 | GraphQL API Vulnerabilities | 5 | 🟡 Planned |
| 24 | Server-Side Template Injection | 7 | 🟡 Planned |
| 25 | Web Cache Poisoning | 13 | 🟡 Planned |
| 26 | HTTP Host Header Attacks | 7 | 🟡 Planned |
| 27 | HTTP Request Smuggling | 22 | 🟡 Planned |
| 28 | OAuth Authentication | 6 | 🟡 Planned |
| 29 | JWT Attacks | 8 | 🟡 Planned |
| 30 | Prototype Pollution | 10 | 🟡 Planned |
| 31 | Essential Skills | 2 | 🟡 Planned |

<br>

## 🧠 My Testing Methodology

Every vulnerability section follows the same thinking process:

```
1. Understand the system design        → how does this feature actually work?
2. Find the reflection/injection point → where does my input land?
3. Identify what's filtered            → map the defense, find the gaps
4. Match context to technique          → right tool for the right context
5. Build delivery mechanism            → zero interaction where possible
6. Document everything                 → including what failed and why
```

> Web Application Penetration testing is understanding system design — not pasting payloads into tools.

<br>

## 🏆 Progress Tracker

| Platform | Profile | Status |
|---|---|---|
| PortSwigger Web Security Academy | [View Profile](https://portswigger.net) | 🟢 Active |
| HackerOne | Coming Soon | 🟡 Planned |
| TryHackMe | Coming Soon | 🟡 Planned |
| CTFtime | Coming Soon | 🟡 Planned |

<br>

## 📁 Related Repositories

| Repository | Description |
|---|---|
| [ctf-writeups](https://github.com/kamran-rajput/ctf-writeups) | CTF challenge solutions and methodology |
| [bug-bounty](https://github.com/kamran-rajput/bug-bounty) | Bug bounty methodology and findings |
| [security-tools](https://github.com/kamran-rajput/security-tools) | Custom pentesting tools and automation |

<br>

## 📬 Connect

- **LinkedIn** → [Kamran Rajput](https://www.linkedin.com/in/kami-rajput/)
- **GitHub** → [@kamran-rajput](https://github.com/kamran-rajput)

<br>

---

<div align="center">

**If these notes helped you — drop a ⭐ and follow along.**  
New vulnerabilities added as I complete them.

![GitHub last commit](https://img.shields.io/github/last-commit/kamran-rajput/web-security-notes?color=red&style=flat-square)
![GitHub stars](https://img.shields.io/github/stars/kamran-rajput/web-security-notes?color=red&style=flat-square)

</div>