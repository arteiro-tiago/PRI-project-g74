# Information needs:

### 1. Cross-Site Scripting (XSS) vulnerabilities affecting web-based database management interfaces or administrative dashboards.

#### Query:
```json
XSS dashboard administration panel
```

### 2. Technical advisories detailing remote code execution flaws in open-source web frameworks that do not require user authentication.

#### Query:
```json
unauthenticated remote code execution framework
```

### 3. Reports explaining privilege escalation methods utilized by remote attackers within Linux kernel environments.

#### Query:
```json
privilege escalation Linux kernel
```

### 4. Security advisories detailing memory corruption or buffer overflow vulnerabilities leading to Denial of Service (DoS) or arbitrary code execution in network services and protocols.

#### Query:
```json
memory corruption buffer overflow denial of service code execution network services protocols
```
---
---
# SetUps Query Parameters

## Simple Setup:
```
defType=edismax&qf=description summary affected cve_id
```

## Advanced Setup

```
defType=edismax&qf=cve_id^10 summary^5 description^3 affected^2 text_all^1&pf=summary^10 description^5&bq=cvss_severity:CRITICAL^3 cvss_severity:HIGH^1.5
```


# Running the qRels script

```
python3 generate_qrels.py
```
Explanation: populates a csv ready to be manually evaluated. 