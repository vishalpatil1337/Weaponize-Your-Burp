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
✓ OAuth/OIDC authentication flows (redirect_uri, callback_url)
✓ Logout/login pages with redirect parameters
✓ Parameters like: url, redirect, next, return, goto, destination, returnTo, continue
✓ /logout, /signin, /signout, /auth/*, /oauth/* endpoints
✓ Link shortener services
✓ External link warning pages

## 🔧 AutoRepeater Configuration Setup Instructions:
1. Open Burp Suite → Extensions → AutoRepeater.
2. Create 25 replacement rules (tabs).
3. Enable all tabs before browsing target.
4. AutoRepeater will test ALL parameters automatically.
 
### Tab Configurations:
**Tab 1: Basic External Domain**
Type: Request Parameter Value  
Match: .*  
Replace: https://evil.com  
Which: Replace All  
Regex Match: Enabled  
Comment: Basic external domain redirect test.
 
**Tab 2: Scheme-Relative URL**
Type: Request Parameter Value  
Match: .*  
dReplace: //evil.com  
dWhich: Replace All  
dRegex Match: Enabled  
dComment: Scheme-relative bypass - inherits current protocol.
...
[Continue with remaining tabs in similar format]
