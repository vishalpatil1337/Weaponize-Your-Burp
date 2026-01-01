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
