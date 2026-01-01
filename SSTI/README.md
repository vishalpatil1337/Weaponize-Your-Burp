SSTI Bug Bounty Automation - Logger++ & AutoRepeater Configuration
Here's an optimized setup for finding SSTI vulnerabilities using only Logger++ and AutoRepeater in Burp Suite.
AutoRepeater Configuration
1. Basic SSTI Detection Payloads
Replace Configuration #1 - Mathematical Expression (Universal)
Type: Request Param Value
Match: .*
Replace: {{7*7}}
Which: Replace All
Regex Match: Enabled
Replace Configuration #2 - Alternative Syntax
Type: Request Param Value
Match: .*
Replace: ${7*7}
Which: Replace All
Regex Match: Enabled
Replace Configuration #3 - Polyglot Detection
Type: Request Param Value
Match: .*
Replace: ${{<%[%'"}}%\.
Which: Replace All
Regex Match: Enabled
Replace Configuration #4 - Ruby/ERB
Type: Request Param Value
Match: .*
Replace: <%= 7*7 %>
Which: Replace All
Regex Match: Enabled
Replace Configuration #5 - FreeMarker/Velocity
Type: Request Param Value
Match: .*
Replace: #{7*7}
Which: Replace All
Regex Match: Enabled
Replace Configuration #6 - String Multiplication (Python)
Type: Request Param Value
Match: .*
Replace: {{7*'7'}}
Which: Replace All
Regex Match: Enabled
Replace Configuration #7 - Angle Brackets
Type: Request Param Value
Match: .*
Replace: <% 7*7 %>
Which: Replace All
Regex Match: Enabled
2. POST Body Replacements
Replace Configuration #8 - JSON Body Values
Type: Request Body
Match: ":\s*"([^"]*)"
Replace: ":"{{7*7}}"
Which: Replace All
Regex Match: Enabled
Replace Configuration #9 - Form Data
Type: Request Body
Match: =([^&]*)
Replace: ={{7*7}}
Which: Replace All
Regex Match: Enabled
3. Header Injection Tests
Replace Configuration #10 - Custom Headers
Type: Request Header
Match: User-Agent: .*
Replace: User-Agent: {{7*7}}
Which: Replace All
Regex Match: Enabled
Replace Configuration #11 - Referer Header
Type: Request Header
Match: Referer: .*
Replace: Referer: {{7*7}}
Which: Replace All
Regex Match: Enabled

Logger++ Filter Configuration
Basic Detection Filters
Filter #1 - Detect Mathematical Results
Response.Body CONTAINS "49"
Filter #2 - Detect String Multiplication
Response.Body CONTAINS "7777777"
Filter #3 - Detect Polyglot Errors
Response.Body CONTAINS "template" || Response.Body CONTAINS "syntax" || Response.Body CONTAINS "unexpected"
Filter #4 - Engine-Specific Errors
Response.Body CONTAINS "jinja" || Response.Body CONTAINS "twig" || Response.Body CONTAINS "freemarker" || Response.Body CONTAINS "velocity" || Response.Body CONTAINS "thymeleaf" || Response.Body CONTAINS "smarty" || Response.Body CONTAINS "mako"
Filter #5 - Python Template Errors
Response.Body CONTAINS "TemplateSyntaxError" || Response.Body CONTAINS "UndefinedError" || Response.Body CONTAINS "jinja2"
Filter #6 - Java Template Errors
Response.Body CONTAINS "freemarker" || Response.Body CONTAINS "TemplateException" || Response.Body CONTAINS "ParseException"
Filter #7 - PHP Template Errors
Response.Body CONTAINS "Smarty" || Response.Body CONTAINS "Twig_Error" || Response.Body CONTAINS "TwigException"
Filter #8 - Ruby Template Errors
Response.Body CONTAINS "ActionView" || Response.Body CONTAINS "erb" || Response.Body CONTAINS "SyntaxError"
Filter #9 - Node.js Template Errors
Response.Body CONTAINS "pug" || Response.Body CONTAINS "jade" || Response.Body CONTAINS "handlebars" || Response.Body CONTAINS "nunjucks"
Advanced Detection Filters
Filter #10 - Reflection Detection (Payload Appears in Response)
Response.Body CONTAINS "{{7*7}}" || Response.Body CONTAINS "${7*7}" || Response.Body CONTAINS "#{7*7}" || Response.Body CONTAINS "<%= 7*7 %>"
Filter #11 - Server Error Status
Response.Status == 500 && (Response.Body CONTAINS "template" || Response.Body CONTAINS "render")
Filter #12 - Debug Information Leak
Response.Body CONTAINS "DEBUG" || Response.Body CONTAINS "Traceback" || Response.Body CONTAINS "Stack trace"
Filter #13 - Combined Success Indicator
(Response.Body CONTAINS "49" || Response.Body CONTAINS "7777777") && Response.Status == 200
Filter #14 - High Confidence SSTI
Response.Body CONTAINS "49" && !(Request.Body CONTAINS "49") && Response.Status == 200
Filter #15 - Template Config Exposure
Response.Body CONTAINS "config" || Response.Body CONTAINS "settings" || Response.Body CONTAINS "SECRET_KEY"

Optimization Tips for Bug Bounty
1. Target Specific Endpoints
Focus AutoRepeater on:

PDF generation endpoints
Email preview/send functions
Invoice generation
Report generation
Template customization features
Search functionality
Error pages
Profile/settings pages

2. Logger++ Export Configuration
Set up Logger++ to export matches:

Columns to include: URL, Method, Status, Response Length, Response Body (partial)
Auto-export: Enable for quick review
Color coding: Set different colors for different vulnerability types

3. Staged Testing Approach

Phase 1: Use basic payloads ({{7*7}}, ${7*7}, #{7*7})
Phase 2: If reflection detected, escalate to RCE payloads
Phase 3: Engine-specific exploitation

4. False Positive Reduction
Add these exclusion filters to Logger++:
!(Response.Body CONTAINS "calculator" || Response.Body CONTAINS "math" || Response.Body CONTAINS "compute")
5. Quick Win Patterns
Look for these high-value targets in Logger++:
Request.Path CONTAINS "template" || Request.Path CONTAINS "render" || Request.Path CONTAINS "preview" || Request.Path CONTAINS "pdf" || Request.Path CONTAINS "invoice" || Request.Path CONTAINS "report" || Request.Path CONTAINS "email"

Priority Testing Order

GET Parameters - Easiest to test, common vulnerability point
POST Data - Form submissions, JSON payloads
Custom Headers - User-Agent, Referer, X-Forwarded-For
Cookie Values - Session data, preferences
File Upload Names - Filename parameters
Path Parameters - RESTful API endpoints


Quick Reference: Expected Results
PayloadExpected ResultTemplate Engine{{7*7}}49Jinja2, Twig, Nunjucks${7*7}49FreeMarker, Velocity, Thymeleaf#{7*7}49Velocity (legacy), Thymeleaf<%= 7*7 %>49ERB, ASP{{7*'7'}}7777777Jinja2, Twig${{7*7}}49Some Java engines
