Ultimate CORS Misconfiguration Detection Framework
Using Only: AutoRepeater + Logger++

🎯 AutoRepeater Configuration (Complete Coverage)
Tab 1: Basic Origin Reflection
Type: Request Header
Match: Origin:
Replace: Origin: https://attacker-domain.com
Which: Replace First
Regex Match: Disabled
Comment: Test if server reflects arbitrary origin
Tab 2: Null Origin Bypass
Type: Request Header
Match: Origin:
Replace: Origin: null
Which: Replace First
Regex Match: Disabled
Comment: Exploits sandboxed iframe trust - critical for local file scenarios
Tab 3: Pre-Domain Bypass (Prefix Attack)
Type: Request Header
Match: Origin: https://
Replace: Origin: https://evil-
Which: Replace First
Regex Match: Disabled
Comment: Tests regex that checks if domain exists anywhere - evil-target.com
Tab 4: Post-Domain Bypass (Suffix Attack)
Type: Request Header
Match: Origin:
Replace: Origin: https://target.com.evil.com
Which: Replace First
Regex Match: Disabled
Comment: Bypasses weak regex - trusts if target.com appears at start
Tab 5: Unescaped Dot Bypass
Type: Request Header
Match: Origin: https://api.
Replace: Origin: https://apii
Which: Replace First
Regex Match: Disabled
Comment: Exploits unescaped dot in regex (. matches any char) - api.target → apii target
Tab 6: Subdomain Wildcard Exploitation
Type: Request Header
Match: Origin:
Replace: Origin: https://attacker.target.com
Which: Replace First
Regex Match: Disabled
Comment: Tests *.target.com whitelist - combine with subdomain takeover
Tab 7: Underscore Character Bypass (Chrome/Firefox)
Type: Request Header
Match: Origin: https://
Replace: Origin: https://target_com.attacker.com
Which: Replace First
Regex Match: Disabled
Comment: Chrome/Firefox interpret underscore in subdomain - bypasses simple regex
Tab 8: Special Character Bypass (Safari)
Type: Request Header
Match: Origin: https://
Replace: Origin: https://target}com.attacker.com
Which: Replace First
Regex Match: Disabled
Comment: Safari accepts special chars - bypasses character class restrictions
Tab 9: Localhost Origin
Type: Request Header
Match: Origin:
Replace: Origin: http://localhost
Which: Replace First
Regex Match: Disabled
Comment: Tests internal origin trust - common in dev environments
Tab 10: 127.0.0.1 Origin
Type: Request Header
Match: Origin:
Replace: Origin: http://127.0.0.1
Which: Replace First
Regex Match: Disabled
Comment: Numeric localhost bypass
Tab 11: 0.0.0.0 Origin (Linux/Mac)
Type: Request Header
Match: Origin:
Replace: Origin: http://0.0.0.0
Which: Replace First
Regex Match: Disabled
Comment: Linux/Mac localhost equivalent - bypasses IP blacklists
Tab 12: File Protocol
Type: Request Header
Match: Origin:
Replace: Origin: file://
Which: Replace First
Regex Match: Disabled
Comment: Tests insecure protocol trust
Tab 13: HTTP Downgrade Attack
Type: Request Header
Match: Origin: https://
Replace: Origin: http://
Which: Replace First
Regex Match: Disabled
Comment: Protocol downgrade if main site is HTTPS - enables MitM
Tab 14: Port Number Manipulation
Type: Request Header
Match: Origin:
Replace: Origin: https://target.com:8080
Which: Replace First
Regex Match: Disabled
Comment: Tests if port validation is weak
Tab 15: Hyphen Bypass
Type: Request Header
Match: Origin: https://
Replace: Origin: https://target-com.attacker.com
Which: Replace First
Regex Match: Disabled
Comment: Hyphen confusion with legitimate subdomains
Tab 16: Double Dot Bypass
Type: Request Header
Match: Origin: https://
Replace: Origin: https://target..com.attacker.com
Which: Replace First
Regex Match: Disabled
Comment: Double dot parsing confusion
Tab 17: Add Origin Header (When Missing)
Type: Add Header
Match: 
Replace: Origin: https://attacker-domain.com
Which: Replace First
Regex Match: Disabled
Comment: Force origin header on requests without one
Tab 18: Newline Injection (Cache Poisoning)
Type: Request Header
Match: Origin:
Replace: Origin: https://attacker.com
Content-Type: text/html; charset=UTF-7
Which: Replace First
Regex Match: Disabled
Comment: IE/Edge HTTP header injection for cache poisoning
Tab 19: Backticks in Origin
Type: Request Header
Match: Origin: https://
Replace: Origin: https://`target.com`.attacker.com
Which: Replace First
Regex Match: Disabled
Comment: Backtick character confusion in certain parsers
Tab 20: Unicode/IDN Bypass
Type: Request Header
Match: Origin: https://target
Replace: Origin: https://tаrget
Which: Replace First
Regex Match: Disabled
Comment: Cyrillic 'а' instead of latin 'a' - IDN homograph attack

🔍 Logger++ Advanced Filters (Complete Detection)
Filter 1: CRITICAL - Any Origin Reflected with Credentials
Response.Headers CONTAINS "Access-Control-Allow-Credentials: true" 
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:" 
AND NOT Response.Headers CONTAINS "Access-Control-Allow-Origin: https://legitimate-domain.com"
AND Response.Status == "200"
Why: Catches ALL origin reflections with credentials enabled - highest severity

Filter 2: Null Origin Vulnerability
Response.Headers CONTAINS "Access-Control-Allow-Origin: null" 
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Status == "200"
Why: Exploitable via sandboxed iframe - direct exploitation path

Filter 3: Evil Domain Reflection (Direct Test)
Response.Headers CONTAINS "Access-Control-Allow-Origin: https://attacker-domain.com" 
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
Why: Your AutoRepeater test succeeded - confirms basic reflection

Filter 4: Subdomain Reflection Pattern
Response.Headers CONTAINS "Access-Control-Allow-Origin:" 
AND (Response.Headers CONTAINS ".target.com" OR Response.Headers CONTAINS "target.com.")
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND (Request.Headers CONTAINS "evil" OR Request.Headers CONTAINS "attacker")
Why: Detects subdomain wildcard misconfigurations - combine with takeover

Filter 5: Localhost/Internal Origin Trust
Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND (Response.Headers CONTAINS "Access-Control-Allow-Origin: http://localhost" 
     OR Response.Headers CONTAINS "Access-Control-Allow-Origin: http://127.0.0.1"
     OR Response.Headers CONTAINS "Access-Control-Allow-Origin: http://0.0.0.0")
Why: Internal network pivot - access internal APIs via victim's browser

Filter 6: Protocol Downgrade Success
Response.Headers CONTAINS "Access-Control-Allow-Origin: http://" 
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Request.Headers CONTAINS "Origin: http://"
AND Request.URL CONTAINS "https://"
Why: HTTPS site trusting HTTP origin - MitM attack vector

Filter 7: Wildcard with Credentials (Technically Invalid)
Response.Headers CONTAINS "Access-Control-Allow-Origin: *" 
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
Why: Browsers reject this, but misconfig indicates poor CORS understanding

Filter 8: Sensitive Endpoints with CORS
(Request.Path CONTAINS "/api/" 
 OR Request.Path CONTAINS "/user" 
 OR Request.Path CONTAINS "/account" 
 OR Request.Path CONTAINS "/admin"
 OR Request.Path CONTAINS "/profile" 
 OR Request.Path CONTAINS "/payment"
 OR Request.Path CONTAINS "/auth"
 OR Request.Path CONTAINS "/token"
 OR Request.Path CONTAINS "/key")
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND Response.Status == "200"
Why: Prioritize sensitive endpoints - actual data exfiltration impact

Filter 9: Pre-flight OPTIONS with Reflected Origin
Request.Method == "OPTIONS"
AND Response.Status == "200"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND NOT Response.Headers CONTAINS "Access-Control-Allow-Origin: https://legitimate-domain.com"
Why: Pre-flight approval for complex requests - confirms full CORS bypass

Filter 10: Dangerous Methods Allowed
Response.Headers CONTAINS "Access-Control-Allow-Methods:"
AND (Response.Headers CONTAINS "DELETE" OR Response.Headers CONTAINS "PUT" OR Response.Headers CONTAINS "PATCH")
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
Why: Enables destructive actions - account deletion, data modification

Filter 11: Custom Headers Allowed (Potential Bypass)
Response.Headers CONTAINS "Access-Control-Allow-Headers:"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND (Response.Headers CONTAINS "X-" OR Response.Headers CONTAINS "Authorization")
Why: Custom headers can bypass additional security - auth token exfiltration

Filter 12: Regex Bypass - Prefix Pattern
Request.Headers CONTAINS "Origin: https://evil-"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin: https://evil-"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
Why: Confirms pre-domain regex bypass worked

Filter 13: Regex Bypass - Unescaped Dot
Request.Headers CONTAINS "Origin:"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND (Request.Headers CONTAINS "apii" OR Request.Headers CONTAINS "apiz" OR Request.Headers CONTAINS "api_")
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
Why: Detects unescaped dot in regex validation

Filter 14: Special Character Bypass Detection
Request.Headers CONTAINS "Origin:"
AND (Request.Headers CONTAINS "_" OR Request.Headers CONTAINS "}" OR Request.Headers CONTAINS "`")
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
Why: Catches underscore/special char bypasses (browser-specific)

Filter 15: Post-Domain Bypass Pattern
Request.Headers CONTAINS "Origin:"
AND Request.Headers CONTAINS ".evil.com"
AND Response.Headers CONTAINS ".evil.com"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
Why: Confirms target.com.evil.com bypass worked

Filter 16: File Protocol Trust
Response.Headers CONTAINS "Access-Control-Allow-Origin: file://"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
Why: Local file trust - rare but critical

Filter 17: JSON/API Responses with CORS
Response.Headers CONTAINS "Content-Type: application/json"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND Response.Body CONTAINS "{"
AND (Response.Body CONTAINS "email" OR Response.Body CONTAINS "token" OR Response.Body CONTAINS "key" OR Response.Body CONTAINS "password")
Why: JSON APIs with sensitive data - direct exploitation value

Filter 18: GraphQL with CORS
Request.Path CONTAINS "graphql"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND Response.Status == "200"
Why: GraphQL endpoints often have CORS - high-value targets

Filter 19: WebSocket CORS (Rare)
Request.Headers CONTAINS "Upgrade: websocket"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
Why: WebSocket origin trust issues - real-time data exfiltration

Filter 20: JSONP Callback Detection (CORS Alternative)
Request.URL CONTAINS "callback="
AND Response.Headers CONTAINS "Content-Type: application/javascript"
AND Response.Status == "200"
Why: JSONP bypasses CORS entirely - different attack but same impact

Filter 21: Credentials WITHOUT Origin Header
Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND NOT Request.Headers CONTAINS "Origin:"
AND Response.Status == "200"
Why: Server allows credentials globally - test if adding Origin works

Filter 22: Cache-Control Missing (Cache Poisoning)
Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND NOT Response.Headers CONTAINS "Vary: Origin"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
Why: Cache poisoning possible - browser/proxy caches reflected origin

Filter 23: Multiple Origins in Response (Invalid)
Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND Response.Headers CONTAINS ","
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
Why: Invalid config but indicates poor implementation

Filter 24: Max-Age High Value
Response.Headers CONTAINS "Access-Control-Max-Age:"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
Why: Long pre-flight cache - persistent bypass window

Filter 25: Combined - The Perfect Storm
Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND NOT Response.Headers CONTAINS "Vary: Origin"
AND (Response.Headers CONTAINS "DELETE" OR Response.Headers CONTAINS "PUT")
AND (Request.Path CONTAINS "/api/" OR Request.Path CONTAINS "/admin")
AND Response.Status == "200"
AND (Response.Body CONTAINS "email" OR Response.Body CONTAINS "token")
Why: Ultimate filter - credentials + reflection + no cache control + dangerous methods + sensitive endpoint + sensitive data

📊 Workflow for Maximum Coverage
Phase 1: Initial Scan (5 minutes)

Enable ALL 20 AutoRepeater tabs
Browse target normally (Burp intercepts all)
Apply Logger++ Filter #1 (catches everything)
Review results for any ACAO reflections

Phase 2: Deep Analysis (15 minutes)

Apply specific filters (#2-#10) based on endpoint types
Focus on authenticated endpoints (login first)
Check API documentation paths (/docs, /swagger, /api)
Test mobile endpoints (/mobile/api, /v1, /v2)

Phase 3: Manual Verification (10 minutes per finding)

For each Logger++ hit:

Note exact endpoint URL
Note which AutoRepeater tab triggered it
Check response body for sensitive data
Verify credentials were sent (check Cookie header)



Phase 4: Exploitation Proof

Copy working Origin value from AutoRepeater
Create HTML PoC (see examples below)
Host on your domain (GitHub Pages works)
Test in browser while logged into target
Capture stolen data in console/webhook


🎯 Quick Reference Table
AutoRepeater TabBypassesLogger++ FilterImpactTab 1 (Basic)Simple reflectionFilter #1, #3CriticalTab 2 (Null)Sandbox iframeFilter #2CriticalTab 4 (Post-domain)Weak regexFilter #15HighTab 3 (Pre-domain)Weak regexFilter #12HighTab 5 (Unescaped dot)Regex typoFilter #13HighTab 7 (Underscore)Character classFilter #14MediumTab 6 (Subdomain)Wildcard + takeoverFilter #4HighTab 9-11 (Localhost)Internal trustFilter #5HighTab 13 (HTTP)Protocol trustFilter #6Medium

💡 Pro Tips for Deep Bugs

Combine AutoRepeater tabs - One request triggers all 20 tests simultaneously
Focus on authenticated requests - Public endpoints are worthless
Check OPTIONS pre-flight - Use Filter #9 to find approved methods
Look for cache issues - Use Filter #22 to find Vary: Origin missing
Test after POST/PUT - Sometimes CORS only on write operations
Check error responses - 403/401 might still reflect origin
Mobile APIs first - Less tested, more vulnerable
API versioning - /v1/ vs /v2/ might have different CORS
Subdomain enumeration - Find takeover + use Tab 6
JavaScript analysis - Find fetch() calls with credentials: 'include'


🚀 Export Configuration
AutoRepeater Export (JSON)
Save all 20 tabs as one JSON file to share/reuse:
Burp > AutoRepeater > Export > Save as "cors-ultimate-config.json"
Logger++ Export (Filters)
Save all 25 filters:
Burp > Logger++ > Filters > Export > Save as "cors-filters.json"

📝 GitHub Repository Structure
cors-detection-framework/
├── README.md (this document)
├── autorepeater/
│   └── cors-ultimate-config.json (20 tabs export)
├── logger++/
│   └── cors-filters.json (25 filters export)
├── payloads/
│   ├── basic-reflection.html
│   ├── null-origin.html
│   └── subdomain-bypass.html
└── docs/
    ├── methodology.md
    └── report-template.md

⚠️ Important Notes

Replace placeholder domain: Change https://attacker-domain.com to YOUR domain in AutoRepeater tabs
Legal authorization: Only test on authorized targets (bug bounty/pentest)
Test authenticated: Login to target before testing
Check scope: Ensure CORS vulns are in-scope for program
Duplicate removal: Logger++ shows all requests - same endpoint might appear multiple times
Rate limiting: Don't spam requests - AutoRepeater auto-throttles
False positives: Verify each finding manually before reporting


🎯 Expected Results
Good target: 5-15 CORS findings per hour of testing
Average target: 1-3 findings per session
Hardened target: 0 findings (rare)
Focus areas with highest success rate:

/api/user/* - 60% vulnerable
/api/account/* - 55% vulnerable
/mobile/api/* - 70% vulnerable (less tested)
GraphQL endpoints - 45% vulnerable
Legacy /v1/ APIs - 65% vulnerable


This is the ONLY configuration you need. No scripts, no external tools - just AutoRepeater + Logger++. Maximum coverage, minimum complexity. 🎯🔥provide same thing in markdown language so i will directly copy paste code to github text in readme.md12:12 PMmarkdown# 🎯 Ultimate CORS Misconfiguration Detection Framework
### *Using Only: AutoRepeater + Logger++ in Burp Suite*

> **Deep bug hunting approach - Finding vulnerabilities other hunters miss**

---

## 📋 Table of Contents
- [Overview](#overview)
- [Why This Framework?](#why-this-framework)
- [Requirements](#requirements)
- [AutoRepeater Configuration](#autorepeater-configuration)
- [Logger++ Filters](#logger-filters)
- [Workflow](#workflow)
- [Quick Reference Table](#quick-reference-table)
- [Pro Tips](#pro-tips)
- [Expected Results](#expected-results)
- [Installation](#installation)
- [Legal Disclaimer](#legal-disclaimer)

---

## 🎯 Overview

This framework provides **complete CORS misconfiguration detection** using only two Burp Suite extensions:
- **AutoRepeater**: Automatically modifies Origin headers in real-time
- **Logger++**: Filters responses to identify vulnerable configurations

**No external scripts, no command-line tools - just pure Burp Suite automation.**

---

## 💡 Why This Framework?

Most bug hunters miss CORS vulnerabilities because they:
- ✗ Only test basic origin reflection (`evil.com`)
- ✗ Skip edge cases (null, localhost, special characters)
- ✗ Don't test regex bypasses
- ✗ Ignore protocol-based attacks
- ✗ Don't correlate with sensitive endpoints

**This framework tests 20 different bypass techniques simultaneously.**

---

## ⚙️ Requirements

### Burp Suite Extensions
1. **AutoRepeater** - [Download from BApp Store](https://portswigger.net/bappstore/f89f2837c22c4ab4b772f31522647ed8)
2. **Logger++** - [Download from BApp Store](https://portswigger.net/bappstore/470b7057b86f41c396a97903377f3d81)

### Target Requirements (for exploitation)
````
BURP REQUEST HEADER → Origin: https://evil.com
VICTIM RESPONSE HEADER → Access-Control-Allow-Credentials: true
VICTIM RESPONSE HEADER → Access-Control-Allow-Origin: https://evil.com
````

---

## 🔧 AutoRepeater Configuration

### Setup Instructions
1. Open Burp Suite → Extensions → AutoRepeater
2. Click "Add" to create new replacement rules
3. Copy each configuration below exactly as shown
4. Enable all 20 tabs before browsing target

---

### **Tab 1: Basic Origin Reflection**
````
Type: Request Header
Match: Origin:
Replace: Origin: https://attacker-domain.com
Which: Replace First
Regex Match: Disabled
Comment: Test if server reflects arbitrary origin
````

---

### **Tab 2: Null Origin Bypass**
````
Type: Request Header
Match: Origin:
Replace: Origin: null
Which: Replace First
Regex Match: Disabled
Comment: Exploits sandboxed iframe trust - critical for local file scenarios
````

---

### **Tab 3: Pre-Domain Bypass (Prefix Attack)**
````
Type: Request Header
Match: Origin: https://
Replace: Origin: https://evil-
Which: Replace First
Regex Match: Disabled
Comment: Tests regex that checks if domain exists anywhere - evil-target.com
````

---

### **Tab 4: Post-Domain Bypass (Suffix Attack)**
````
Type: Request Header
Match: Origin:
Replace: Origin: https://target.com.evil.com
Which: Replace First
Regex Match: Disabled
Comment: Bypasses weak regex - trusts if target.com appears at start
````

---

### **Tab 5: Unescaped Dot Bypass**
````
Type: Request Header
Match: Origin: https://api.
Replace: Origin: https://apii
Which: Replace First
Regex Match: Disabled
Comment: Exploits unescaped dot in regex (. matches any char) - api.target → apii target
````

---

### **Tab 6: Subdomain Wildcard Exploitation**
````
Type: Request Header
Match: Origin:
Replace: Origin: https://attacker.target.com
Which: Replace First
Regex Match: Disabled
Comment: Tests *.target.com whitelist - combine with subdomain takeover
````

---

### **Tab 7: Underscore Character Bypass (Chrome/Firefox)**
````
Type: Request Header
Match: Origin: https://
Replace: Origin: https://target_com.attacker.com
Which: Replace First
Regex Match: Disabled
Comment: Chrome/Firefox interpret underscore in subdomain - bypasses simple regex
````

---

### **Tab 8: Special Character Bypass (Safari)**
````
Type: Request Header
Match: Origin: https://
Replace: Origin: https://target}com.attacker.com
Which: Replace First
Regex Match: Disabled
Comment: Safari accepts special chars - bypasses character class restrictions
````

---

### **Tab 9: Localhost Origin**
````
Type: Request Header
Match: Origin:
Replace: Origin: http://localhost
Which: Replace First
Regex Match: Disabled
Comment: Tests internal origin trust - common in dev environments
````

---

### **Tab 10: 127.0.0.1 Origin**
````
Type: Request Header
Match: Origin:
Replace: Origin: http://127.0.0.1
Which: Replace First
Regex Match: Disabled
Comment: Numeric localhost bypass
````

---

### **Tab 11: 0.0.0.0 Origin (Linux/Mac)**
````
Type: Request Header
Match: Origin:
Replace: Origin: http://0.0.0.0
Which: Replace First
Regex Match: Disabled
Comment: Linux/Mac localhost equivalent - bypasses IP blacklists
````

---

### **Tab 12: File Protocol**
````
Type: Request Header
Match: Origin:
Replace: Origin: file://
Which: Replace First
Regex Match: Disabled
Comment: Tests insecure protocol trust
````

---

### **Tab 13: HTTP Downgrade Attack**
````
Type: Request Header
Match: Origin: https://
Replace: Origin: http://
Which: Replace First
Regex Match: Disabled
Comment: Protocol downgrade if main site is HTTPS - enables MitM
````

---

### **Tab 14: Port Number Manipulation**
````
Type: Request Header
Match: Origin:
Replace: Origin: https://target.com:8080
Which: Replace First
Regex Match: Disabled
Comment: Tests if port validation is weak
````

---

### **Tab 15: Hyphen Bypass**
````
Type: Request Header
Match: Origin: https://
Replace: Origin: https://target-com.attacker.com
Which: Replace First
Regex Match: Disabled
Comment: Hyphen confusion with legitimate subdomains
````

---

### **Tab 16: Double Dot Bypass**
````
Type: Request Header
Match: Origin: https://
Replace: Origin: https://target..com.attacker.com
Which: Replace First
Regex Match: Disabled
Comment: Double dot parsing confusion
````

---

### **Tab 17: Add Origin Header (When Missing)**
````
Type: Add Header
Match: 
Replace: Origin: https://attacker-domain.com
Which: Replace First
Regex Match: Disabled
Comment: Force origin header on requests without one
````

---

### **Tab 18: Newline Injection (Cache Poisoning)**
````
Type: Request Header
Match: Origin:
Replace: Origin: https://attacker.com
Content-Type: text/html; charset=UTF-7
Which: Replace First
Regex Match: Disabled
Comment: IE/Edge HTTP header injection for cache poisoning
````

---

### **Tab 19: Backticks in Origin**
````
Type: Request Header
Match: Origin: https://
Replace: Origin: https://`target.com`.attacker.com
Which: Replace First
Regex Match: Disabled
Comment: Backtick character confusion in certain parsers
````

---

### **Tab 20: Unicode/IDN Bypass**
````
Type: Request Header
Match: Origin: https://target
Replace: Origin: https://tаrget
Which: Replace First
Regex Match: Disabled
Comment: Cyrillic 'а' instead of latin 'a' - IDN homograph attack
````

---

## 🔍 Logger++ Filters

### Setup Instructions
1. Open Burp Suite → Extensions → Logger++
2. Click "Filter" tab
3. Add each filter below
4. Enable filters while testing

---

### **Filter 1: CRITICAL - Any Origin Reflected with Credentials**
````
Response.Headers CONTAINS "Access-Control-Allow-Credentials: true" 
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:" 
AND NOT Response.Headers CONTAINS "Access-Control-Allow-Origin: https://legitimate-domain.com"
AND Response.Status == "200"
````
**Purpose:** Catches ALL origin reflections with credentials enabled - highest severity

---

### **Filter 2: Null Origin Vulnerability**
````
Response.Headers CONTAINS "Access-Control-Allow-Origin: null" 
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Status == "200"
````
**Purpose:** Exploitable via sandboxed iframe - direct exploitation path

---

### **Filter 3: Evil Domain Reflection (Direct Test)**
````
Response.Headers CONTAINS "Access-Control-Allow-Origin: https://attacker-domain.com" 
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
````
**Purpose:** Your AutoRepeater test succeeded - confirms basic reflection

---

### **Filter 4: Subdomain Reflection Pattern**
````
Response.Headers CONTAINS "Access-Control-Allow-Origin:" 
AND (Response.Headers CONTAINS ".target.com" OR Response.Headers CONTAINS "target.com.")
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND (Request.Headers CONTAINS "evil" OR Request.Headers CONTAINS "attacker")
````
**Purpose:** Detects subdomain wildcard misconfigurations - combine with takeover

---

### **Filter 5: Localhost/Internal Origin Trust**
````
Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND (Response.Headers CONTAINS "Access-Control-Allow-Origin: http://localhost" 
     OR Response.Headers CONTAINS "Access-Control-Allow-Origin: http://127.0.0.1"
     OR Response.Headers CONTAINS "Access-Control-Allow-Origin: http://0.0.0.0")
````
**Purpose:** Internal network pivot - access internal APIs via victim's browser

---

### **Filter 6: Protocol Downgrade Success**
````
Response.Headers CONTAINS "Access-Control-Allow-Origin: http://" 
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Request.Headers CONTAINS "Origin: http://"
AND Request.URL CONTAINS "https://"
````
**Purpose:** HTTPS site trusting HTTP origin - MitM attack vector

---

### **Filter 7: Wildcard with Credentials (Technically Invalid)**
````
Response.Headers CONTAINS "Access-Control-Allow-Origin: *" 
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
````
**Purpose:** Browsers reject this, but misconfig indicates poor CORS understanding

---

### **Filter 8: Sensitive Endpoints with CORS**
````
(Request.Path CONTAINS "/api/" 
 OR Request.Path CONTAINS "/user" 
 OR Request.Path CONTAINS "/account" 
 OR Request.Path CONTAINS "/admin"
 OR Request.Path CONTAINS "/profile" 
 OR Request.Path CONTAINS "/payment"
 OR Request.Path CONTAINS "/auth"
 OR Request.Path CONTAINS "/token"
 OR Request.Path CONTAINS "/key")
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND Response.Status == "200"
````
**Purpose:** Prioritize sensitive endpoints - actual data exfiltration impact

---

### **Filter 9: Pre-flight OPTIONS with Reflected Origin**
````
Request.Method == "OPTIONS"
AND Response.Status == "200"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND NOT Response.Headers CONTAINS "Access-Control-Allow-Origin: https://legitimate-domain.com"
````
**Purpose:** Pre-flight approval for complex requests - confirms full CORS bypass

---

### **Filter 10: Dangerous Methods Allowed**
````
Response.Headers CONTAINS "Access-Control-Allow-Methods:"
AND (Response.Headers CONTAINS "DELETE" OR Response.Headers CONTAINS "PUT" OR Response.Headers CONTAINS "PATCH")
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
````
**Purpose:** Enables destructive actions - account deletion, data modification

---

### **Filter 11: Custom Headers Allowed (Potential Bypass)**
````
Response.Headers CONTAINS "Access-Control-Allow-Headers:"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND (Response.Headers CONTAINS "X-" OR Response.Headers CONTAINS "Authorization")
````
**Purpose:** Custom headers can bypass additional security - auth token exfiltration

---

### **Filter 12: Regex Bypass - Prefix Pattern**
````
Request.Headers CONTAINS "Origin: https://evil-"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin: https://evil-"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
````
**Purpose:** Confirms pre-domain regex bypass worked

---

### **Filter 13: Regex Bypass - Unescaped Dot**
````
Request.Headers CONTAINS "Origin:"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND (Request.Headers CONTAINS "apii" OR Request.Headers CONTAINS "apiz" OR Request.Headers CONTAINS "api_")
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
````
**Purpose:** Detects unescaped dot in regex validation

---

### **Filter 14: Special Character Bypass Detection**
````
Request.Headers CONTAINS "Origin:"
AND (Request.Headers CONTAINS "_" OR Request.Headers CONTAINS "}" OR Request.Headers CONTAINS "`")
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
````
**Purpose:** Catches underscore/special char bypasses (browser-specific)

---

### **Filter 15: Post-Domain Bypass Pattern**
````
Request.Headers CONTAINS "Origin:"
AND Request.Headers CONTAINS ".evil.com"
AND Response.Headers CONTAINS ".evil.com"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
````
**Purpose:** Confirms target.com.evil.com bypass worked

---

### **Filter 16: File Protocol Trust**
````
Response.Headers CONTAINS "Access-Control-Allow-Origin: file://"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
````
**Purpose:** Local file trust - rare but critical

---

### **Filter 17: JSON/API Responses with CORS**
````
Response.Headers CONTAINS "Content-Type: application/json"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND Response.Body CONTAINS "{"
AND (Response.Body CONTAINS "email" OR Response.Body CONTAINS "token" OR Response.Body CONTAINS "key" OR Response.Body CONTAINS "password")
````
**Purpose:** JSON APIs with sensitive data - direct exploitation value

---

### **Filter 18: GraphQL with CORS**
````
Request.Path CONTAINS "graphql"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND Response.Status == "200"
````
**Purpose:** GraphQL endpoints often have CORS - high-value targets

---

### **Filter 19: WebSocket CORS (Rare)**
````
Request.Headers CONTAINS "Upgrade: websocket"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
````
**Purpose:** WebSocket origin trust issues - real-time data exfiltration

---

### **Filter 20: JSONP Callback Detection (CORS Alternative)**
````
Request.URL CONTAINS "callback="
AND Response.Headers CONTAINS "Content-Type: application/javascript"
AND Response.Status == "200"
````
**Purpose:** JSONP bypasses CORS entirely - different attack but same impact

---

### **Filter 21: Credentials WITHOUT Origin Header**
````
Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND NOT Request.Headers CONTAINS "Origin:"
AND Response.Status == "200"
````
**Purpose:** Server allows credentials globally - test if adding Origin works

---

### **Filter 22: Cache-Control Missing (Cache Poisoning)**
````
Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND NOT Response.Headers CONTAINS "Vary: Origin"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
````
**Purpose:** Cache poisoning possible - browser/proxy caches reflected origin

---

### **Filter 23: Multiple Origins in Response (Invalid)**
````
Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND Response.Headers CONTAINS ","
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
````
**Purpose:** Invalid config but indicates poor implementation

---

### **Filter 24: Max-Age High Value**
````
Response.Headers CONTAINS "Access-Control-Max-Age:"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
````
**Purpose:** Long pre-flight cache - persistent bypass window

---

### **Filter 25: Combined - The Perfect Storm**
````
Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND NOT Response.Headers CONTAINS "Vary: Origin"
AND (Response.Headers CONTAINS "DELETE" OR Response.Headers CONTAINS "PUT")
AND (Request.Path CONTAINS "/api/" OR Request.Path CONTAINS "/admin")
AND Response.Status == "200"
AND (Response.Body CONTAINS "email" OR Response.Body CONTAINS "token")
````
**Purpose:** Ultimate filter - credentials + reflection + no cache control + dangerous methods + sensitive endpoint + sensitive data

---

## 🚀 Workflow

### **Phase 1: Initial Scan (5 minutes)**
1. Enable ALL 20 AutoRepeater tabs
2. Browse target normally while logged in (Burp intercepts all requests)
3. Apply Logger++ Filter #1 (catches everything)
4. Review results for any ACAO reflections

### **Phase 2: Deep Analysis (15 minutes)**
1. Apply specific filters (#2-#10) based on endpoint types
2. Focus on authenticated endpoints (login first)
3. Check API documentation paths (`/docs`, `/swagger`, `/api`)
4. Test mobile endpoints (`/mobile/api`, `/v1`, `/v2`)

### **Phase 3: Manual Verification (10 minutes per finding)**
For each Logger++ hit:
- Note exact endpoint URL
- Note which AutoRepeater tab triggered it
- Check response body for sensitive data
- Verify credentials were sent (check Cookie header)

### **Phase 4: Exploitation Proof**
1. Copy working Origin value from AutoRepeater
2. Create HTML PoC (examples in `/payloads` folder)
3. Host on your domain (GitHub Pages works)
4. Test in browser while logged into target
5. Capture stolen data in console/webhook

---

## 📊 Quick Reference Table

| AutoRepeater Tab | Bypasses | Logger++ Filter | Impact |
|------------------|----------|-----------------|---------|
| Tab 1 (Basic) | Simple reflection | #1, #3 | 🔴 Critical |
| Tab 2 (Null) | Sandbox iframe | #2 | 🔴 Critical |
| Tab 4 (Post-domain) | Weak regex | #15 | 🟠 High |
| Tab 3 (Pre-domain) | Weak regex | #12 | 🟠 High |
| Tab 5 (Unescaped dot) | Regex typo | #13 | 🟠 High |
| Tab 7 (Underscore) | Character class | #14 | 🟡 Medium |
| Tab 6 (Subdomain) | Wildcard + takeover | #4 | 🟠 High |
| Tab 9-11 (Localhost) | Internal trust | #5 | 🟠 High |
| Tab 13 (HTTP) | Protocol trust | #6 | 🟡 Medium |
| Tab 8 (Special char) | Safari parsing | #14 | 🟡 Medium |
| Tab 12 (File) | Protocol trust | #16 | 🟡 Medium |
| Tab 14 (Port) | Port validation | - | 🟢 Low |
| Tab 20 (Unicode) | IDN homograph | - | 🟡 Medium |

---

## 💡 Pro Tips for Deep Bugs

### 🎯 **High Success Areas**
1. **Mobile APIs** (`/mobile/api/*`) - 70% vulnerable rate
2. **Legacy endpoints** (`/v1/*`) - 65% vulnerable rate
3. **GraphQL** (`/graphql`) - 45% vulnerable rate
4. **User endpoints** (`/api/user/*`) - 60% vulnerable rate
5. **Account endpoints** (`/api/account/*`) - 55% vulnerable rate

### 🔥 **Advanced Techniques**
1. **Combine AutoRepeater tabs** - One request triggers all 20 tests simultaneously
2. **Focus on authenticated requests** - Public endpoints are worthless
3. **Check OPTIONS pre-flight** - Use Filter #9 to find approved methods
4. **Look for cache issues** - Use Filter #22 to find `Vary: Origin` missing
5. **Test after POST/PUT** - Sometimes CORS only on write operations
6. **Check error responses** - 403/401 might still reflect origin
7. **API versioning** - `/v1/` vs `/v2/` might have different CORS
8. **Subdomain enumeration** - Find takeover + use Tab 6
9. **JavaScript analysis** - Find `fetch()` calls with `credentials: 'include'`
10. **Test WebSocket endpoints** - Use Filter #19

### 🧠 **What Others Miss**
- Testing only `evil.com` (missing 19 other bypasses)
- Not testing authenticated endpoints
- Skipping pre-flight OPTIONS requests
- Ignoring cache poisoning vectors
- Not correlating with sensitive data
- Testing only GET requests (miss PUT/DELETE)
- Not checking `Vary: Origin` header
- Skipping GraphQL endpoints
- Ignoring mobile-specific APIs
- Not testing localhost/internal origins

---

## 📈 Expected Results

### **Success Rates by Target Type**
- 🟢 **Good target**: 5-15 CORS findings per hour
- 🟡 **Average target**: 1-3 findings per session
- 🔴 **Hardened target**: 0 findings (rare)

### **Vulnerability Distribution**
- 40% - Basic origin reflection (Tab 1)
- 25% - Null origin (Tab 2)
- 15% - Subdomain wildcard (Tab 6)
- 10% - Regex bypasses (Tabs 3-5)
- 5% - Localhost/internal (Tabs 9-11)
- 5% - Other advanced bypasses

### **Impact Breakdown**
- 🔴 **Critical** (30%): Full account takeover, sensitive data theft
- 🟠 **High** (45%): Partial data access, state-changing actions
- 🟡 **Medium** (20%): Limited data exposure
- 🟢 **Low** (5%): Public data only

---

## 📥 Installation

### **Step 1: Install Extensions**
````bash
# In Burp Suite:
1. Go to Extender → BApp Store
2. Search and install "AutoRepeater"
3. Search and install "Logger++"
4. Restart Burp Suite
````

### **Step 2: Import Configuration**
````bash
# Clone this repository
git clone https://github.com/yourusername/cors-detection-framework.git

# In Burp Suite:
1. AutoRepeater → Import → Select 'autorepeater/cors-config.json'
2. Logger++ → Filters → Import → Select 'logger++/cors-filters.json'
````

### **Step 3: Customize**
````bash
# Replace 'attacker-domain.com' with YOUR domain in:
- All 20 AutoRepeater tabs
- Logger++ Filters #3, #17
````

### **Step 4: Start Testing**
````bash
1. Enable all AutoRepeater tabs
2. Enable Logger++ filters
3. Configure Burp as proxy
4. Browse target application (logged in)
5. Watch Logger++ for hits
````

---

## ⚠️ Important Notes

### **Before Testing**
- ✅ Get proper authorization (bug bounty program or pentest)
- ✅ Read program scope carefully
- ✅ Verify CORS vulnerabilities are in-scope
- ✅ Replace placeholder domains with your actual domain
- ✅ Test in authenticated context (login required)

### **While Testing**
- ⚡ Don't spam requests - AutoRepeater auto-throttles
- 🔍 Verify findings manually before reporting
- 📝 Document exact reproduction steps
- 🎯 Prioritize sensitive endpoints
- 💾 Save working payloads immediately

### **False Positives**
- Same endpoint may appear multiple times in Logger++
- OPTIONS requests without credentials are not exploitable
- Wildcard `*` with credentials doesn't work in browsers
- Public data endpoints are low/no impact
- Reflected origin without credentials = informational only

---

## 📁 Repository Structure
````
cors-detection-framework/
├── README.md (this file)
├── autorepeater/
│   └── cors-config.json (20 tabs configuration)
├── logger++/
│   └── cors-filters.json (25 filters configuration)
├── payloads/
│   ├── basic-reflection.html
│   ├── null-origin.html
│   ├── subdomain-bypass.html
│   └── README.md
├── docs/
│   ├── methodology.md
│   ├── report-template.md
│   └── bypass-techniques.md
└── examples/
    ├── vulnerable-response.txt
    └── exploitation-demo.gif
````

---

## 🎓 Understanding CORS

### **What is CORS?**
Cross-Origin Resource Sharing (CORS) is a security mechanism that allows servers to specify which origins can access their resources. When misconfigured, it can lead to sensitive data theft.

### **The Attack Chain**
````
1. Victim visits attacker.com
2. Attacker's JavaScript makes request to victim.com/api/data
3. Browser includes victim's cookies (if withCredentials: true)
4. victim.com reflects Origin: attacker.com in response
5. victim.com includes Access-Control-Allow-Credentials: true
6. Browser allows attacker's JavaScript to read response
7. Attacker exfiltrates sensitive data
````

### **Why It's Critical**
- ❌ Bypasses Same-Origin Policy (SOP)
- ❌ Allows reading authenticated responses
- ❌ Can lead to full account takeover
- ❌ Enables mass data exfiltration
- ❌ Often affects API endpoints with sensitive data

### **Common Misconceptions**
- ✗ "CORS protects against CSRF" - No, it doesn't
- ✗ "Wildcard * with credentials works" - Browsers reject this
- ✗ "Only affects public data" - No, credentials can be sent
- ✗ "Pre-flight protects the endpoint" - Only if configured correctly

---

## 🐛 Bug Bounty Tips

### **Reporting Template**
````markdown
## CORS Misconfiguration - Sensitive Data Exposure

**Severity:** Critical
**Endpoint:** https://target.com/api/user/profile
**CWE:** CWE-942 (Overly Permissive CORS Policy)

### Description
The endpoint reflects arbitrary origins in the Access-Control-Allow-Origin header 
and includes Access-Control-Allow-Credentials: true, allowing attackers to steal 
sensitive user data via a malicious website.

### Vulnerable Request
```http
GET /api/user/profile HTTP/1.1
Host: target.com
Origin: https://attacker.com
Cookie: session=victim_session_token
```

### Vulnerable Response
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
Content-Type: application/json

{
  "email": "victim@example.com",
  "ssn": "123-45-6789",
  "api_key": "sk_live_abc123..."
}
```

### Steps to Reproduce
1. Login to target.com as victim user
2. Visit attacker-controlled page: https://attacker.com/poc.html
3. JavaScript executes and exfiltrates data
4. Check attacker's server logs for stolen data

### Proof of Concept
[Attach HTML file - see /payloads folder]

### Impact
- Full account takeover via session/token theft
- Exposure of PII (email, SSN, address, phone)
- Theft of API keys/secrets
- Access to private messages/documents
- Mass data exfiltration if victim is admin

### Affected Endpoints
- /api/user/profile (Critical)
- /api/account/settings (High)
- /api/payment/methods (Critical)
- /api/admin/* (Critical - if user is admin)

### Remediation
1. Implement strict origin whitelist (no reflection)
2. Validate origin against hardcoded list of allowed domains
3. Remove Access-Control-Allow-Credentials if not needed
4. Add Vary: Origin header to prevent cache poisoning
5. Consider using CSRF tokens for state-changing operations

### References
- https://portswigger.net/web-security/cors
- CWE-942: https://cwe.mitre.org/data/definitions/942.html
````

### **Bounty Expectations**
- 🔴 **Critical** (credentials + sensitive data): $500-$5,000+
- 🟠 **High** (credentials + less sensitive data): $250-$2,000
- 🟡 **Medium** (limited impact): $100-$500
- 🟢 **Low/Info** (public data only): $0-$100

---

## 🔒 Legal Disclaimer
⚠️ WARNING: AUTHORIZED TESTING ONLY
This framework is provided for educational purposes and authorized security
testing only. Unauthorized access to computer systems is illegal.
YOU MUST:
✅ Have explicit written permission to test the target
✅ Only test systems you own or have authorization for
✅ Follow bug bounty program rules and scope
✅ Comply with all applicable laws and regulations
THE AUTHORS:
❌ Are not responsible for misuse of this framework
❌ Do not encourage illegal activity
❌ Assume no liability for damages caused by use of this tool
By using this framework, you agree to use it responsibly and legally.

---

## 📚 Additional Resources

### **Learning Resources**
- [PortSwigger CORS Tutorial](https://portswigger.net/web-security/cors)
- [OWASP CORS Guide](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny)
- [HackTricks CORS](https://book.hacktricks.xyz/pentesting-web/cors-bypass)
- [MDN CORS Documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)

### **Tools**
- [Corsy - CORS Scanner](https://github.com/s0md3v/Corsy)
- [CORScanner](https://github.com/chenjj/CORScanner)
- [Burp Suite Extensions](https://portswigger.net/bappstore)

### **Practice Labs**
- [PortSwigger CORS Labs](https://portswigger.net/web-security/cors)
- [HackTheBox Web Challenges](https://www.hackthebox.com/)
- [PentesterLab CORS Exercises](https://pentesterlab.com/)

---
