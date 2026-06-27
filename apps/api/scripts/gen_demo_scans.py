"""Generate realistic-looking scanner output JSON files for demo / load testing.

Writes one JSON file per scanner under `apps/api/demo_data/`:

  nessus-scan.json          ~375 findings   (host/network — Tenable Nessus)
  qualys-vuln-scan.json     ~330 findings   (host/network — Qualys VMDR)
  grype-scan.json           ~270 findings   (container — Anchore Grype)
  snyk-appsec-scan.json     ~270 findings   (SCA — Snyk Open Source)
  sonarqube-appsec.json     ~180 findings   (SAST — SonarQube)
  burp-suite-scan.json      ~150 findings   (DAST — Burp Suite)

Mix: ~80% real recent CVEs (so EPSS/KEV/NVD enrichment hits real data),
~20% synthetic CVE-2026-NNNNN IDs (to exercise "unknown CVE" code paths).

Severity skew is intentionally demo-friendly: ~25% Critical, 35% High,
30% Medium, 10% Low.

Deterministic — uses a fixed PRNG seed so re-runs produce identical files.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

# ---------------------------------------------------------------------------
# Determinism — same seed every run.
# ---------------------------------------------------------------------------
RNG = random.Random(20260623)

OUT_DIR = Path(__file__).resolve().parent.parent / "demo_data"
OUT_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# CVE POOL — ~200 real recent vulnerabilities, grouped by ecosystem.
# Tuples: (cve_id, package, vuln_version, fixed_version, cvss_v3,
#          severity, title, cwe_list, in_kev_bool)
# Severities here are the *real* assigned ones; the per-tool generator will
# bias selection toward Critical/High to hit the demo distribution.
# ===========================================================================

NPM_CVES: list[tuple] = [
    ("CVE-2021-3807", "ansi-regex", "5.0.0", "5.0.1", 7.5, "High", "Inefficient Regular Expression Complexity in ansi-regex", ["CWE-1333"], False),
    ("CVE-2022-25883", "semver", "7.3.7", "7.5.2", 7.5, "High", "ReDoS in semver via the new Range function", ["CWE-1333"], False),
    ("CVE-2022-24999", "express", "4.17.3", "4.17.4", 7.5, "High", "qs vulnerable to Prototype Pollution via express", ["CWE-1321"], False),
    ("CVE-2022-24785", "moment", "2.29.1", "2.29.2", 7.5, "High", "Path Traversal in moment locale loading", ["CWE-22"], False),
    ("CVE-2023-26136", "tough-cookie", "4.1.2", "4.1.3", 6.5, "Medium", "Prototype Pollution in tough-cookie", ["CWE-1321"], False),
    ("CVE-2023-45857", "axios", "1.5.1", "1.6.0", 6.5, "Medium", "axios XSRF token sent in cross-site requests", ["CWE-352"], False),
    ("CVE-2024-21538", "cross-spawn", "7.0.3", "7.0.5", 7.5, "High", "Regular Expression Denial of Service in cross-spawn", ["CWE-1333"], False),
    ("CVE-2024-37890", "ws", "8.17.0", "8.17.1", 7.5, "High", "ws affected by a DoS when handling a request with many HTTP headers", ["CWE-476"], False),
    ("CVE-2024-29415", "ip", "2.0.0", "2.0.1", 9.8, "Critical", "ip SSRF improper categorization in isPublic", ["CWE-918"], False),
    ("CVE-2020-7660", "serialize-javascript", "3.1.0", "3.1.0", 8.1, "High", "serialize-javascript Cross-Site Scripting", ["CWE-79"], False),
    ("CVE-2022-29078", "ejs", "3.1.7", "3.1.8", 9.8, "Critical", "ejs template injection vulnerability", ["CWE-74"], False),
    ("CVE-2023-26115", "word-wrap", "1.2.3", "1.2.4", 5.3, "Medium", "Regular Expression Denial of Service in word-wrap", ["CWE-1333"], False),
    ("CVE-2023-44270", "postcss", "8.4.30", "8.4.31", 5.3, "Medium", "postcss line return parsing error", ["CWE-144"], False),
    ("CVE-2024-4067", "micromatch", "4.0.5", "4.0.8", 5.3, "Medium", "Regular Expression Denial of Service in micromatch", ["CWE-1333"], False),
    ("CVE-2024-21484", "jsrsasign", "10.9.0", "11.0.0", 7.5, "High", "Forgeable RSA-PSS signatures in jsrsasign", ["CWE-347"], False),
    ("CVE-2024-28849", "follow-redirects", "1.15.5", "1.15.6", 6.5, "Medium", "follow-redirects leaks Authorization header on cross-origin", ["CWE-200"], False),
    ("CVE-2024-43788", "webpack", "5.93.0", "5.94.0", 7.4, "High", "Webpack's AutoPublicPathRuntimeModule can lead to XSS", ["CWE-79"], False),
    ("CVE-2024-45296", "path-to-regexp", "6.2.1", "6.3.0", 7.5, "High", "path-to-regexp ReDoS via backtracking", ["CWE-1333"], False),
    ("CVE-2024-47764", "cookie", "0.6.0", "0.7.0", 6.5, "Medium", "cookie accepts cookie name/path/domain with out of bounds chars", ["CWE-74"], False),
    ("CVE-2023-42282", "ip", "1.1.8", "1.1.9", 9.8, "Critical", "ip SSRF (legacy) via IPv4-mapped IPv6 address bypass", ["CWE-918"], False),
    ("CVE-2024-29180", "webpack-dev-middleware", "5.3.3", "5.3.4", 7.4, "High", "Path traversal in webpack-dev-middleware", ["CWE-22"], False),
    ("CVE-2024-39338", "axios", "1.7.3", "1.7.4", 7.5, "High", "axios SSRF via path-relative URL handling", ["CWE-918"], False),
    ("CVE-2023-28154", "webpack", "5.75.0", "5.76.0", 9.8, "Critical", "Webpack cross-realm object access in ImportParserPlugin", ["CWE-1321"], False),
    ("CVE-2024-30260", "undici", "5.28.3", "5.28.4", 6.8, "Medium", "undici fetch leaks Authorization on cross-origin redirect", ["CWE-200"], False),
    ("CVE-2024-34273", "request", "2.88.2", None, 6.1, "Medium", "request library SSRF in HTTP redirect handling", ["CWE-918"], False),
    ("CVE-2022-37601", "loader-utils", "1.4.1", "1.4.2", 9.8, "Critical", "Prototype pollution in loader-utils", ["CWE-1321"], False),
    ("CVE-2023-38704", "libxmljs", "0.32.0", "1.0.0", 9.8, "Critical", "libxmljs heap buffer overflow", ["CWE-122"], False),
    ("CVE-2023-44270", "postcss", "8.4.30", "8.4.31", 5.3, "Medium", "PostCSS line return parsing error", ["CWE-144"], False),
    ("CVE-2022-46175", "json5", "2.2.1", "2.2.2", 7.1, "High", "Prototype Pollution in JSON5 via Parse Method", ["CWE-1321"], False),
    ("CVE-2024-21490", "angular", "1.8.3", None, 5.3, "Medium", "AngularJS Regular Expression Denial of Service", ["CWE-1333"], False),
]

PYPI_CVES: list[tuple] = [
    ("CVE-2022-40897", "setuptools", "65.5.0", "65.5.1", 5.9, "Medium", "setuptools ReDoS in package_index", ["CWE-1333"], False),
    ("CVE-2023-32681", "requests", "2.30.0", "2.31.0", 6.1, "Medium", "Unintended leak of Proxy-Authorization header in Requests", ["CWE-200"], False),
    ("CVE-2024-22195", "Jinja2", "3.1.2", "3.1.3", 5.4, "Medium", "Jinja2 vulnerable to HTML attribute injection via xmlattr", ["CWE-79"], False),
    ("CVE-2024-3651", "idna", "3.6", "3.7", 6.2, "Medium", "idna denial of service via crafted input", ["CWE-400"], False),
    ("CVE-2023-30861", "Flask", "2.2.4", "2.2.5", 7.5, "High", "Flask session cookie may persist across requests", ["CWE-200"], False),
    ("CVE-2024-35195", "requests", "2.31.0", "2.32.0", 5.6, "Medium", "Requests reuses TLS context after verify=False", ["CWE-670"], False),
    ("CVE-2024-39689", "certifi", "2024.6.2", "2024.7.4", 7.5, "High", "certifi removed e-Tugra root certificates", ["CWE-345"], False),
    ("CVE-2023-43804", "urllib3", "1.26.17", "1.26.18", 8.1, "High", "urllib3 cookie request header isn't stripped on cross-origin redirect", ["CWE-200"], False),
    ("CVE-2024-37891", "urllib3", "2.2.1", "2.2.2", 4.4, "Medium", "urllib3 Proxy-Authorization request header isn't stripped", ["CWE-200"], False),
    ("CVE-2023-50447", "Pillow", "10.1.0", "10.2.0", 8.1, "High", "Pillow arbitrary code execution via the environment parameter", ["CWE-94"], False),
    ("CVE-2024-28219", "Pillow", "10.2.0", "10.3.0", 5.5, "Medium", "Pillow buffer overflow in _imagingcms.c", ["CWE-120"], False),
    ("CVE-2024-3772", "pydantic", "2.4.0", "2.4.1", 7.5, "High", "Pydantic regex ReDoS in email validator", ["CWE-1333"], False),
    ("CVE-2023-37920", "certifi", "2023.7.21", "2023.7.22", 9.8, "Critical", "certifi removed e-Tugra root from the root store", ["CWE-345"], False),
    ("CVE-2024-26130", "cryptography", "42.0.3", "42.0.4", 7.5, "High", "cryptography NULL pointer dereference in PKCS12", ["CWE-476"], False),
    ("CVE-2024-1135", "gunicorn", "22.0.0", "23.0.0", 7.5, "High", "Gunicorn HTTP request smuggling via Transfer-Encoding", ["CWE-444"], False),
    ("CVE-2024-34064", "Jinja2", "3.1.3", "3.1.4", 5.4, "Medium", "Jinja2 xmlattr filter accepts keys with non-attribute chars", ["CWE-79"], False),
    ("CVE-2024-49767", "Werkzeug", "3.0.4", "3.0.6", 7.5, "High", "Werkzeug resource exhaustion in multipart parsing", ["CWE-770"], False),
    ("CVE-2024-1681", "fastapi", "0.108.0", "0.109.1", 5.3, "Medium", "FastAPI ReDoS via Content-Type header parsing", ["CWE-1333"], False),
    ("CVE-2024-35225", "lxml-html-clean", "0.1.0", "0.1.1", 6.1, "Medium", "lxml html clean allows XSS via crafted SVG", ["CWE-79"], False),
    ("CVE-2024-47081", "requests", "2.32.0", "2.32.4", 5.3, "Medium", "requests netrc credentials leak via URL parsing", ["CWE-200"], False),
    ("CVE-2023-29483", "eventlet", "0.33.3", "0.35.2", 7.5, "High", "Eventlet DNS rebinding via dnspython", ["CWE-918"], False),
    ("CVE-2024-22195", "ansible-core", "2.14.13", "2.14.14", 5.5, "Medium", "Ansible template injection in jinja2 filters", ["CWE-94"], False),
    ("CVE-2024-21503", "black", "24.2.0", "24.3.0", 5.3, "Medium", "black formatter ReDoS in input parsing", ["CWE-1333"], False),
    ("CVE-2023-49083", "cryptography", "41.0.5", "41.0.6", 7.5, "High", "cryptography NULL pointer deref when loading PKCS7 cert", ["CWE-476"], False),
    ("CVE-2024-6345", "setuptools", "70.0.0", "70.0.1", 8.8, "High", "setuptools remote code execution via download functions", ["CWE-94"], False),
]

JAVA_CVES: list[tuple] = [
    ("CVE-2021-44228", "org.apache.logging.log4j:log4j-core", "2.14.1", "2.17.1", 10.0, "Critical", "Log4Shell — Apache Log4j2 JNDI RCE", ["CWE-502","CWE-917"], True),
    ("CVE-2021-45046", "org.apache.logging.log4j:log4j-core", "2.15.0", "2.16.0", 9.0, "Critical", "Log4j 2.15.0 incomplete fix — JNDI lookup RCE", ["CWE-502","CWE-917"], True),
    ("CVE-2022-22965", "org.springframework:spring-beans", "5.3.17", "5.3.18", 9.8, "Critical", "Spring4Shell — Spring Framework JDK 9+ RCE", ["CWE-94"], True),
    ("CVE-2022-22963", "org.springframework.cloud:spring-cloud-function-context", "3.2.2", "3.2.3", 9.8, "Critical", "Spring Cloud Function SpEL RCE", ["CWE-94"], False),
    ("CVE-2022-42889", "org.apache.commons:commons-text", "1.9", "1.10.0", 9.8, "Critical", "Text4Shell — Apache Commons Text RCE via StringSubstitutor", ["CWE-94"], False),
    ("CVE-2022-1471", "org.yaml:snakeyaml", "1.32", "2.0", 9.8, "Critical", "SnakeYAML Constructor deserialization RCE", ["CWE-502"], False),
    ("CVE-2017-5638", "org.apache.struts:struts2-core", "2.3.32", "2.3.34", 10.0, "Critical", "Equifax — Struts2 Jakarta Multipart parser RCE", ["CWE-20"], True),
    ("CVE-2019-17571", "log4j:log4j", "1.2.17", None, 9.8, "Critical", "Log4j 1.x SocketServer deserialization RCE", ["CWE-502"], False),
    ("CVE-2022-42003", "com.fasterxml.jackson.core:jackson-databind", "2.13.4", "2.13.4.2", 7.5, "High", "Jackson deep wrapper array nesting DoS", ["CWE-502"], False),
    ("CVE-2020-36518", "com.fasterxml.jackson.core:jackson-databind", "2.13.0", "2.13.2.1", 7.5, "High", "Jackson Java StackOverflow in nested objects", ["CWE-787"], False),
    ("CVE-2023-20860", "org.springframework:spring-web", "5.3.25", "5.3.26", 8.8, "High", "Spring Framework ** path matching mismatch", ["CWE-22"], False),
    ("CVE-2023-20863", "org.springframework:spring-expression", "5.3.26", "5.3.27", 7.5, "High", "Spring Framework SpEL ReDoS", ["CWE-1333"], False),
    ("CVE-2024-38816", "org.springframework:spring-webmvc", "5.3.38", "5.3.39", 7.5, "High", "Spring WebMVC path traversal via static resource handling", ["CWE-22"], False),
    ("CVE-2024-38819", "org.springframework:spring-webflux", "6.1.13", "6.1.14", 7.5, "High", "Spring WebFlux path traversal in functional web framework", ["CWE-22"], False),
    ("CVE-2024-22243", "org.springframework:spring-web", "6.1.3", "6.1.4", 8.1, "High", "Spring Framework URI parsing open redirect / SSRF", ["CWE-601"], False),
    ("CVE-2022-31197", "org.postgresql:postgresql", "42.4.0", "42.4.1", 8.0, "High", "PostgreSQL JDBC driver SQL injection in ResultSet", ["CWE-89"], False),
    ("CVE-2023-26119", "org.apache.tomcat:tomcat-coyote", "9.0.71", "9.0.72", 7.5, "High", "Tomcat HTTP/2 request smuggling", ["CWE-444"], False),
    ("CVE-2024-24549", "org.apache.tomcat:tomcat-coyote", "9.0.85", "9.0.86", 7.5, "High", "Tomcat HTTP/2 DoS via excessive memory", ["CWE-770"], False),
    ("CVE-2024-23672", "org.apache.tomcat:tomcat-websocket", "9.0.85", "9.0.86", 6.5, "Medium", "Tomcat WebSocket DoS via unclosed connections", ["CWE-404"], False),
    ("CVE-2023-44487", "io.netty:netty-codec-http2", "4.1.99", "4.1.100", 7.5, "High", "HTTP/2 Rapid Reset attack — netty", ["CWE-400"], True),
    ("CVE-2024-29025", "io.netty:netty-codec-http", "4.1.107", "4.1.108", 5.3, "Medium", "Netty allocation of resources without limits", ["CWE-770"], False),
    ("CVE-2022-26336", "com.thoughtworks.xstream:xstream", "1.4.18", "1.4.19", 9.8, "Critical", "XStream remote code execution via crafted XML", ["CWE-502"], False),
    ("CVE-2024-22262", "org.springframework:spring-web", "6.1.5", "6.1.6", 7.4, "High", "Spring Framework open redirect via UriComponentsBuilder", ["CWE-601"], False),
    ("CVE-2024-22259", "org.springframework:spring-web", "6.1.4", "6.1.5", 7.4, "High", "Spring Framework SSRF via UriComponentsBuilder", ["CWE-918"], False),
    ("CVE-2023-20861", "org.springframework:spring-expression", "5.3.25", "5.3.26", 6.5, "Medium", "Spring Expression DoS via crafted SpEL expression", ["CWE-770"], False),
]

OS_CVES: list[tuple] = [
    # OpenSSL
    ("CVE-2022-0778", "openssl", "1.1.1m", "1.1.1n", 7.5, "High", "OpenSSL infinite loop in BN_mod_sqrt parsing certs", ["CWE-835"], False),
    ("CVE-2022-3602", "openssl", "3.0.6", "3.0.7", 7.5, "High", "OpenSSL X.509 email address 4-byte buffer overflow", ["CWE-122"], False),
    ("CVE-2022-3786", "openssl", "3.0.6", "3.0.7", 7.5, "High", "OpenSSL X.509 email address variable length buffer overflow", ["CWE-122"], False),
    ("CVE-2023-0286", "openssl", "3.0.7", "3.0.8", 7.4, "High", "OpenSSL X.400 address type confusion in X.509 GeneralName", ["CWE-843"], False),
    ("CVE-2023-0464", "openssl", "3.0.8", "3.0.9", 7.5, "High", "OpenSSL excessive resource use in X.509 policy verification", ["CWE-770"], False),
    ("CVE-2024-0727", "openssl", "3.0.11", "3.0.13", 5.5, "Medium", "OpenSSL NULL pointer dereference in PKCS12 decoding", ["CWE-476"], False),
    ("CVE-2023-5363", "openssl", "3.0.10", "3.0.12", 7.5, "High", "OpenSSL incorrect cipher key/IV length handling", ["CWE-326"], False),
    ("CVE-2024-5535", "openssl", "3.0.13", "3.0.14", 9.1, "Critical", "OpenSSL SSL_select_next_proto buffer overread", ["CWE-126"], False),
    # glibc / Linux
    ("CVE-2023-4911", "glibc", "2.36-9", "2.36-10", 7.8, "High", "Looney Tunables — glibc ld.so GLIBC_TUNABLES buffer overflow", ["CWE-122"], True),
    ("CVE-2024-2961", "glibc", "2.37", "2.39", 7.3, "High", "glibc iconv ISO-2022-CN-EXT buffer overflow", ["CWE-122"], False),
    ("CVE-2023-6246", "glibc", "2.38-1", "2.38-2", 7.8, "High", "glibc __vsyslog_internal heap buffer overflow", ["CWE-122"], False),
    ("CVE-2024-33599", "glibc", "2.38-3", "2.38-4", 7.5, "High", "glibc nscd netgroup cache stack overflow", ["CWE-121"], False),
    ("CVE-2024-2398", "curl", "8.6.0", "8.7.0", 7.5, "High", "curl HTTP/2 push headers memory leak", ["CWE-401"], False),
    ("CVE-2023-38545", "curl", "8.3.0", "8.4.0", 7.5, "High", "curl SOCKS5 heap buffer overflow", ["CWE-122"], True),
    ("CVE-2023-38546", "curl", "8.3.0", "8.4.0", 5.5, "Medium", "curl cookie injection with none file", ["CWE-94"], False),
    ("CVE-2024-7264", "curl", "8.9.0", "8.9.1", 7.5, "High", "curl ASN.1 date parser overread", ["CWE-126"], False),
    ("CVE-2024-6197", "curl", "8.8.0", "8.9.0", 7.5, "High", "curl freeing stack buffer in utf8asn1str", ["CWE-590"], False),
    # OpenSSH / SSH
    ("CVE-2024-6387", "openssh-server", "9.6p1", "9.7p1", 8.1, "High", "regreSSHion — OpenSSH sshd signal handler race RCE", ["CWE-364"], True),
    ("CVE-2023-48795", "openssh-client", "9.5", "9.6", 5.9, "Medium", "Terrapin — SSH transport protocol prefix truncation", ["CWE-222"], False),
    ("CVE-2024-39894", "openssh-server", "9.7p1", "9.8p1", 5.3, "Medium", "OpenSSH ObscureKeystrokeTiming bypass", ["CWE-208"], False),
    # bash / shell
    ("CVE-2014-6271", "bash", "4.2", "4.3", 9.8, "Critical", "Shellshock — bash function definition injection", ["CWE-78"], True),
    # sudo
    ("CVE-2023-22809", "sudo", "1.9.12p1", "1.9.12p2", 7.8, "High", "sudoedit arbitrary file edit via EDITOR env arg injection", ["CWE-269"], True),
    ("CVE-2025-32463", "sudo", "1.9.15", "1.9.16", 9.3, "Critical", "sudo chroot privilege escalation", ["CWE-269"], False),
    # busybox / musl (Alpine)
    ("CVE-2022-28391", "busybox", "1.35.0", "1.35.0-r17", 8.8, "High", "BusyBox netstat allows ANSI escape sequence injection", ["CWE-1289"], False),
    ("CVE-2023-42363", "busybox", "1.36.1", "1.37.0", 5.5, "Medium", "BusyBox awk use-after-free", ["CWE-416"], False),
    ("CVE-2023-42364", "busybox", "1.36.1", "1.37.0", 5.5, "Medium", "BusyBox awk use-after-free in evaluate", ["CWE-416"], False),
    ("CVE-2023-42365", "busybox", "1.36.1", "1.37.0", 5.5, "Medium", "BusyBox awk use-after-free in copyvar", ["CWE-416"], False),
    # xz / liblzma
    ("CVE-2024-3094", "xz-utils", "5.6.0", "5.6.2", 10.0, "Critical", "xz-utils backdoor in liblzma compromising sshd", ["CWE-506"], True),
    # Apache HTTPD
    ("CVE-2021-41773", "httpd", "2.4.49", "2.4.50", 7.5, "High", "Apache HTTP Server path traversal in mod_alias", ["CWE-22"], True),
    ("CVE-2021-42013", "httpd", "2.4.50", "2.4.51", 9.8, "Critical", "Apache HTTP Server path traversal and RCE", ["CWE-22"], True),
    ("CVE-2023-25690", "httpd", "2.4.55", "2.4.56", 9.8, "Critical", "Apache HTTP Server mod_proxy request smuggling", ["CWE-444"], False),
    ("CVE-2024-38473", "httpd", "2.4.59", "2.4.60", 8.1, "High", "Apache HTTP Server encoded URL bypass via mod_rewrite", ["CWE-863"], False),
    ("CVE-2024-38474", "httpd", "2.4.59", "2.4.60", 8.1, "High", "Apache HTTP Server substitution bypass via mod_rewrite", ["CWE-22"], False),
    ("CVE-2024-40725", "httpd", "2.4.60", "2.4.62", 5.3, "Medium", "Apache HTTP Server source code disclosure via AddType", ["CWE-200"], False),
    # nginx
    ("CVE-2022-41741", "nginx", "1.22.0", "1.22.1", 7.8, "High", "nginx ngx_http_mp4_module memory corruption", ["CWE-787"], False),
    ("CVE-2022-41742", "nginx", "1.22.0", "1.22.1", 7.8, "High", "nginx ngx_http_mp4_module memory disclosure", ["CWE-125"], False),
    ("CVE-2024-7347", "nginx", "1.27.0", "1.27.1", 4.7, "Medium", "nginx ngx_http_mp4_module out-of-bounds read", ["CWE-125"], False),
    # SMB / Windows
    ("CVE-2017-0144", "smbd", "3.0", "3.1.1", 8.1, "High", "EternalBlue — Windows SMBv1 remote code execution", ["CWE-20"], True),
    ("CVE-2020-0796", "smbd", "10.0", "10.0.18362.720", 10.0, "Critical", "SMBGhost — Windows SMBv3 compression RCE", ["CWE-119"], True),
    ("CVE-2020-1472", "netlogon", "10.0", "10.0.17763.1457", 10.0, "Critical", "Zerologon — Windows Netlogon elevation of privilege", ["CWE-330"], True),
    ("CVE-2019-0708", "rdp", "6.1", "6.1.7601.24441", 9.8, "Critical", "BlueKeep — Windows RDP remote code execution", ["CWE-416"], True),
    ("CVE-2021-34527", "spoolsv", "10.0", "10.0.19041.1110", 8.8, "High", "PrintNightmare — Windows Print Spooler RCE", ["CWE-269"], True),
    ("CVE-2022-30190", "msdt", "10.0", "10.0.19041.1741", 7.8, "High", "Follina — Windows MSDT remote code execution", ["CWE-22"], True),
    ("CVE-2023-23397", "outlook", "16.0", "16.0.16327.20214", 9.8, "Critical", "Microsoft Outlook elevation of privilege via NTLM hash leak", ["CWE-294"], True),
    # Confluence / Atlassian
    ("CVE-2022-26134", "confluence-server", "7.18.0", "7.18.1", 9.8, "Critical", "Atlassian Confluence OGNL injection RCE", ["CWE-94"], True),
    ("CVE-2023-22515", "confluence-server", "8.5.1", "8.5.2", 10.0, "Critical", "Atlassian Confluence broken access control privilege escalation", ["CWE-863"], True),
    ("CVE-2023-22518", "confluence-server", "8.5.2", "8.5.3", 9.1, "Critical", "Atlassian Confluence improper authorization data exfiltration", ["CWE-863"], True),
    # MOVEit, GitLab, MinIO
    ("CVE-2023-34362", "moveit", "2022.1.5", "2022.1.6", 9.8, "Critical", "MOVEit Transfer SQL injection — Clop ransomware exploitation", ["CWE-89"], True),
    ("CVE-2024-0402", "gitlab-ce", "16.7.0", "16.7.4", 9.9, "Critical", "GitLab arbitrary file write via workspace creation", ["CWE-22"], False),
    ("CVE-2024-29032", "minio", "2024.3.10", "2024.3.21", 9.8, "Critical", "MinIO information disclosure via signature exploit", ["CWE-200"], False),
    # PHP
    ("CVE-2024-4577", "php", "8.3.7", "8.3.8", 9.8, "Critical", "PHP CGI argument injection on Windows", ["CWE-78"], True),
    ("CVE-2024-2756", "php", "8.3.4", "8.3.5", 5.3, "Medium", "PHP cookie filter bypass via __Host- and __Secure- prefixes", ["CWE-565"], False),
    ("CVE-2024-3096", "php", "8.3.4", "8.3.5", 5.3, "Medium", "PHP password_verify bypass via null bytes", ["CWE-287"], False),
    # MySQL / PostgreSQL
    ("CVE-2024-21171", "mysql-server", "8.0.36", "8.0.37", 6.5, "Medium", "MySQL Server DoS via Optimizer manipulation", ["CWE-770"], False),
    ("CVE-2024-10977", "postgresql", "16.4", "16.5", 3.1, "Low", "PostgreSQL libpq server messages may inject control chars", ["CWE-93"], False),
    ("CVE-2024-10976", "postgresql", "16.4", "16.5", 4.2, "Medium", "PostgreSQL row security incorrectly applied to subqueries", ["CWE-863"], False),
    # runc / containerd
    ("CVE-2024-21626", "runc", "1.1.11", "1.1.12", 8.6, "High", "Leaky Vessels — runc file descriptor leak container escape", ["CWE-403"], False),
    ("CVE-2024-23651", "buildkit", "0.12.4", "0.12.5", 8.7, "High", "BuildKit race condition with mount cache during build", ["CWE-362"], False),
    ("CVE-2024-23652", "buildkit", "0.12.4", "0.12.5", 9.1, "Critical", "BuildKit arbitrary file deletion outside container root", ["CWE-22"], False),
    ("CVE-2024-23653", "buildkit", "0.12.4", "0.12.5", 9.8, "Critical", "BuildKit interactive containers API privilege escalation", ["CWE-269"], False),
    # Kubernetes / Helm
    ("CVE-2024-7646", "ingress-nginx", "1.10.0", "1.11.2", 8.8, "High", "ingress-nginx annotation validation bypass", ["CWE-20"], False),
    ("CVE-2024-5321", "kubernetes", "1.30.0", "1.30.3", 6.1, "Medium", "Kubernetes Windows nodes incorrect default file permissions", ["CWE-276"], False),
    # Misc network
    ("CVE-2023-20198", "ios-xe", "17.9.4", "17.9.4a", 10.0, "Critical", "Cisco IOS XE web UI privilege escalation", ["CWE-269"], True),
    ("CVE-2024-3400", "globalprotect", "11.1.2", "11.1.3", 10.0, "Critical", "Palo Alto Networks PAN-OS GlobalProtect command injection", ["CWE-78"], True),
    ("CVE-2024-21887", "ivanti-connect", "22.5", "22.5.1", 9.1, "Critical", "Ivanti Connect Secure command injection in web components", ["CWE-77"], True),
    ("CVE-2024-21893", "ivanti-connect", "22.5.1", "22.5.2", 8.2, "High", "Ivanti Connect Secure SSRF in SAML component", ["CWE-918"], True),
    ("CVE-2024-1709", "screenconnect", "23.9.7", "23.9.8", 10.0, "Critical", "ConnectWise ScreenConnect authentication bypass", ["CWE-288"], True),
    ("CVE-2023-46805", "ivanti-connect", "22.5", "22.5.1", 8.2, "High", "Ivanti Connect Secure authentication bypass in web components", ["CWE-287"], True),
    ("CVE-2024-47575", "fortinet-fortimanager", "7.4.4", "7.4.5", 9.8, "Critical", "FortiManager missing authentication for critical API endpoint", ["CWE-306"], True),
    ("CVE-2024-29849", "veeam-backup", "12.1.2", "12.1.3", 9.8, "Critical", "Veeam Backup Enterprise Manager authentication bypass", ["CWE-287"], True),
    ("CVE-2023-7028", "gitlab", "16.6.0", "16.6.4", 10.0, "Critical", "GitLab account takeover via password reset to arbitrary email", ["CWE-640"], True),
]

# Web-app CWE-based findings (used by Burp + SonarQube for non-CVE issues).
WEB_CWE_FINDINGS: list[tuple] = [
    # (cwe, owasp_category, severity, cvss, title, description_short)
    ("CWE-79", "A03:2021-Injection", "High", 7.2, "Reflected Cross-Site Scripting", "User input reflected into HTML response without encoding"),
    ("CWE-79", "A03:2021-Injection", "High", 8.0, "Stored Cross-Site Scripting", "User input persisted and rendered to other users without sanitization"),
    ("CWE-89", "A03:2021-Injection", "Critical", 9.8, "SQL Injection", "User input concatenated into SQL query"),
    ("CWE-78", "A03:2021-Injection", "Critical", 9.8, "OS Command Injection", "User input passed to shell command without sanitization"),
    ("CWE-22", "A01:2021-Broken Access Control", "High", 7.5, "Path Traversal", "Application allows access to files outside the intended directory"),
    ("CWE-352", "A01:2021-Broken Access Control", "Medium", 6.5, "Cross-Site Request Forgery", "State-changing endpoint lacks anti-CSRF token"),
    ("CWE-798", "A07:2021-Identification and Auth Failures", "Critical", 9.8, "Use of Hard-coded Credentials", "Hardcoded API token / password in source code"),
    ("CWE-327", "A02:2021-Cryptographic Failures", "High", 7.5, "Use of Broken or Weak Crypto", "Application uses MD5/SHA-1/DES for security-sensitive operations"),
    ("CWE-330", "A02:2021-Cryptographic Failures", "Medium", 5.3, "Insufficient Randomness", "Use of java.util.Random for security tokens"),
    ("CWE-918", "A10:2021-SSRF", "High", 8.1, "Server-Side Request Forgery", "User-supplied URL fetched server-side without validation"),
    ("CWE-611", "A05:2021-Security Misconfiguration", "High", 7.5, "XML External Entity (XXE)", "XML parser configured to resolve external entities"),
    ("CWE-502", "A08:2021-Software and Data Integrity Failures", "Critical", 9.8, "Deserialization of Untrusted Data", "Object deserialization on user-controlled input"),
    ("CWE-601", "A01:2021-Broken Access Control", "Medium", 6.1, "Open Redirect", "User-controlled URL used in redirect without allowlist"),
    ("CWE-862", "A01:2021-Broken Access Control", "High", 7.5, "Missing Authorization", "Sensitive endpoint accessible without authorization check"),
    ("CWE-863", "A01:2021-Broken Access Control", "High", 7.5, "Incorrect Authorization", "Authorization check present but logic incorrect"),
    ("CWE-200", "A04:2021-Insecure Design", "Medium", 5.3, "Information Exposure", "Sensitive data leaked in error message or response header"),
    ("CWE-770", "A04:2021-Insecure Design", "Medium", 5.3, "Allocation of Resources Without Limits", "Endpoint lacks rate limiting or request size limits"),
    ("CWE-79", "A03:2021-Injection", "Medium", 6.1, "DOM-Based Cross-Site Scripting", "Client-side script writes user input to DOM via dangerous sink"),
    ("CWE-565", "A04:2021-Insecure Design", "Medium", 5.3, "Reliance on Untrusted Cookie", "Authorization decisions based on cookies without integrity check"),
    ("CWE-117", "A09:2021-Security Logging and Monitoring Failures", "Low", 3.7, "Improper Output Neutralization for Logs", "User input written to logs without sanitization (log forging)"),
    ("CWE-326", "A02:2021-Cryptographic Failures", "High", 7.5, "Inadequate Encryption Strength", "Use of <2048-bit RSA / <128-bit symmetric keys"),
    ("CWE-1004", "A05:2021-Security Misconfiguration", "Medium", 5.3, "Cookie Without HttpOnly Flag", "Session cookie accessible to JavaScript"),
    ("CWE-614", "A02:2021-Cryptographic Failures", "Medium", 5.3, "Cookie Without Secure Flag", "Session cookie sent over unencrypted channel"),
    ("CWE-732", "A05:2021-Security Misconfiguration", "Medium", 6.5, "Incorrect Permission Assignment", "World-readable / world-writable file permissions on sensitive file"),
    ("CWE-94", "A03:2021-Injection", "Critical", 9.8, "Code Injection", "User input evaluated as code (eval, Function constructor)"),
]


# ===========================================================================
# Asset / target inventories used by per-tool generators.
# ===========================================================================

HOSTNAMES = [
    "web-prod-01.corp.example.com", "web-prod-02.corp.example.com",
    "api-gateway-01.corp.example.com", "api-gateway-02.corp.example.com",
    "db-postgres-primary.corp.example.com", "db-postgres-replica-01.corp.example.com",
    "db-mysql-primary.corp.example.com", "redis-cache-01.corp.example.com",
    "redis-cache-02.corp.example.com", "kafka-broker-01.corp.example.com",
    "kafka-broker-02.corp.example.com", "kafka-broker-03.corp.example.com",
    "es-data-01.corp.example.com", "es-data-02.corp.example.com",
    "es-master-01.corp.example.com", "jenkins-ci.corp.example.com",
    "gitlab-runner-01.corp.example.com", "gitlab-runner-02.corp.example.com",
    "vault-prod.corp.example.com", "consul-prod-01.corp.example.com",
    "monitoring-prom.corp.example.com", "monitoring-grafana.corp.example.com",
    "logging-elk.corp.example.com", "bastion-01.corp.example.com",
    "vpn-gateway-01.corp.example.com", "vpn-gateway-02.corp.example.com",
    "auth-keycloak.corp.example.com", "smtp-relay.corp.example.com",
    "dev-workstation-042.corp.example.com", "dev-workstation-118.corp.example.com",
    "qa-runner-01.corp.example.com", "qa-runner-02.corp.example.com",
    "build-mac-mini-01.corp.example.com", "file-share-01.corp.example.com",
    "domain-controller-01.corp.example.com", "domain-controller-02.corp.example.com",
    "exchange-mailbox-01.corp.example.com", "sharepoint-prod.corp.example.com",
    "rdp-jumpbox-01.corp.example.com", "k8s-master-01.corp.example.com",
    "k8s-master-02.corp.example.com", "k8s-worker-12.corp.example.com",
    "k8s-worker-17.corp.example.com", "k8s-worker-23.corp.example.com",
    "k8s-worker-31.corp.example.com", "k8s-worker-44.corp.example.com",
    "edge-cdn-01.corp.example.com", "edge-cdn-02.corp.example.com",
    "backup-nfs-01.corp.example.com", "ad-fs-01.corp.example.com",
    "okta-agent-01.corp.example.com",
]

def _ip_for(host: str) -> str:
    h = abs(hash(host)) % 65536
    return f"10.{(h >> 8) & 0xff}.{h & 0xff}.{(abs(hash(host[::-1])) % 254) + 1}"

OS_FOR_HOST = [
    "Ubuntu 22.04.4 LTS", "Ubuntu 20.04.6 LTS", "Debian GNU/Linux 11 (bullseye)",
    "Debian GNU/Linux 12 (bookworm)", "Red Hat Enterprise Linux 8.9",
    "Red Hat Enterprise Linux 9.4", "CentOS Stream 9", "Amazon Linux 2",
    "Amazon Linux 2023", "Microsoft Windows Server 2019 Standard",
    "Microsoft Windows Server 2022 Datacenter", "macOS 14.5 (Sonoma)",
]

CONTAINER_IMAGES = [
    ("alpine", "3.18.6", "sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b"),
    ("alpine", "3.19.1", "sha256:51b67269f354137895d43f3b0a9d3bb6c9b1604b3a93b6df74d8a8db4d4f8b3f"),
    ("debian", "11-slim", "sha256:11e26e1aef38d75c5a4ed8d6a906b14ee49da1c5e2c6e5fa78a87b3a51dd2f5e"),
    ("debian", "12-slim", "sha256:bc89e425f1ec1c20ec3cce0d8edabd0e7d8c52196e9c8eecda1ac8e7c0ff5b4d"),
    ("ubuntu", "22.04", "sha256:b6b83d3c331794420340093eb706a6f152d9c1fa51b262d9bf34594887c2c7ac"),
    ("ubuntu", "20.04", "sha256:e15dd6dd6b51bff4cad4d8af1f9b9c1aae3a0d6c2c8e98c5c7d6a8b8c8e7e7e7"),
    ("python", "3.11-slim", "sha256:9a8c4f7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e"),
    ("python", "3.12-alpine", "sha256:abc4f7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e"),
    ("node", "18-alpine", "sha256:def4f7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e"),
    ("node", "20-alpine", "sha256:1234f7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e"),
    ("nginx", "1.25-alpine", "sha256:5678f7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e"),
    ("nginx", "1.27", "sha256:91abf7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e"),
    ("postgres", "15-alpine", "sha256:fedcf7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e"),
    ("postgres", "16-alpine", "sha256:cafef7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e"),
    ("redis", "7-alpine", "sha256:beeff7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e"),
    ("internal/checkout-svc", "v2.14.3", "sha256:aaaaaaa7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e"),
    ("internal/checkout-svc", "v2.14.4", "sha256:bbbbbbb7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e"),
    ("internal/payments-api", "v1.8.0", "sha256:ccccccc7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e"),
    ("internal/orders-worker", "v3.2.1", "sha256:ddddddd7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e"),
    ("internal/auth-svc", "v4.1.7", "sha256:eeeeeee7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e"),
]

REPOS_FRONTEND = [
    "frontend-web", "frontend-mobile-web", "admin-dashboard",
    "marketing-site", "support-portal", "design-system",
]
REPOS_BACKEND = [
    "api-gateway", "checkout-service", "payments-api", "orders-worker",
    "auth-service", "notifications-service", "search-service",
    "inventory-service", "fulfillment-service", "billing-engine",
    "user-profile-service", "data-warehouse-etl",
]


# ===========================================================================
# Common helpers
# ===========================================================================

SEVERITY_WEIGHTS = {"Critical": 0.25, "High": 0.35, "Medium": 0.30, "Low": 0.10}

def severity_weighted_choice() -> str:
    r = RNG.random()
    cum = 0.0
    for sev, w in SEVERITY_WEIGHTS.items():
        cum += w
        if r <= cum:
            return sev
    return "Medium"

def synthetic_cve() -> str:
    year = RNG.choice([2025, 2026])
    n = RNG.randint(10000, 99999)
    return f"CVE-{year}-{n}"

def maybe_synthetic(real_id: str, synthetic_rate: float = 0.20) -> str:
    return synthetic_cve() if RNG.random() < synthetic_rate else real_id

def iso(days_ago_max: int = 90) -> str:
    """Fake timestamps within the last 90 days. Not 'now' because the user's
    pipeline only consumes the file once and we want stable test data."""
    base = 1717113600  # 2026-05-30 epoch, deterministic
    delta = RNG.randint(0, days_ago_max * 86400)
    ts = base - delta
    import datetime
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")

def pick_cve_for(ecosystem: str) -> tuple:
    """Pick a CVE entry from the appropriate pool given an ecosystem hint."""
    if ecosystem == "npm":
        pool = NPM_CVES
    elif ecosystem == "pypi":
        pool = PYPI_CVES
    elif ecosystem == "java":
        pool = JAVA_CVES
    elif ecosystem == "os":
        pool = OS_CVES
    elif ecosystem == "any":
        pool = NPM_CVES + PYPI_CVES + JAVA_CVES + OS_CVES
    else:
        pool = OS_CVES
    return RNG.choice(pool)

def severity_to_cvss(severity: str) -> float:
    if severity == "Critical":
        return round(RNG.uniform(9.0, 10.0), 1)
    if severity == "High":
        return round(RNG.uniform(7.0, 8.9), 1)
    if severity == "Medium":
        return round(RNG.uniform(4.0, 6.9), 1)
    return round(RNG.uniform(0.1, 3.9), 1)

def cvss_vector_for(score: float) -> str:
    """Synthesize a plausible CVSS v3.1 vector string for the given score."""
    if score >= 9.0:
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    if score >= 7.0:
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    if score >= 4.0:
        return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
    return "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"


# ===========================================================================
# Tool generator: Nessus (Tenable)
# ===========================================================================

NESSUS_PLUGIN_FAMILY = {
    "openssl": "Web Servers",
    "openssh": "Misc.",
    "openssh-server": "Misc.",
    "openssh-client": "Misc.",
    "httpd": "Web Servers",
    "nginx": "Web Servers",
    "smbd": "Windows",
    "netlogon": "Windows",
    "rdp": "Windows",
    "spoolsv": "Windows",
    "msdt": "Windows",
    "outlook": "Windows",
    "confluence-server": "CGI abuses",
    "moveit": "Web Servers",
    "gitlab-ce": "Web Servers",
    "minio": "Web Servers",
    "ios-xe": "Networking",
    "globalprotect": "Firewalls",
    "ivanti-connect": "Firewalls",
    "screenconnect": "CGI abuses",
    "fortinet-fortimanager": "Firewalls",
    "veeam-backup": "Backup",
    "gitlab": "Web Servers",
    "bash": "General",
    "sudo": "General",
    "busybox": "General",
    "xz-utils": "General",
    "curl": "General",
    "glibc": "General",
    "php": "CGI abuses",
    "mysql-server": "Databases",
    "postgresql": "Databases",
    "runc": "General",
    "buildkit": "General",
    "ingress-nginx": "Web Servers",
    "kubernetes": "General",
}

def gen_nessus(n: int) -> dict:
    findings = []
    plugin_id_seq = 200000
    for _ in range(n):
        cve_entry = pick_cve_for("os")
        cve, pkg, vuln_v, fixed_v, real_cvss, real_sev, title, cwes, kev = cve_entry
        sev = severity_weighted_choice()
        cvss = severity_to_cvss(sev) if sev != real_sev else real_cvss
        cve_to_use = maybe_synthetic(cve)
        host = RNG.choice(HOSTNAMES)
        plugin_id_seq += 1
        port = RNG.choice([22, 80, 443, 445, 3389, 8080, 8443, 9090, 5432, 3306])
        findings.append({
            "scan_id": "nessus-scan-2026-q2-internal",
            "scan_policy": "Advanced Network Scan",
            "scan_completed_at": iso(7),
            "host": {
                "hostname": host,
                "ipv4": _ip_for(host),
                "operating_system": RNG.choice(OS_FOR_HOST),
                "mac_address": ":".join(f"{RNG.randint(0,255):02x}" for _ in range(6)),
                "netbios_name": host.split(".")[0].upper(),
            },
            "port": {"port": port, "protocol": "tcp", "service": {80:"www",443:"https",22:"ssh",445:"smb",3389:"rdp",3306:"mysql",5432:"postgresql",8080:"http-alt",8443:"https-alt",9090:"prometheus"}.get(port,"unknown")},
            "plugin": {
                "id": plugin_id_seq,
                "name": title,
                "family": NESSUS_PLUGIN_FAMILY.get(pkg, "General"),
                "type": "remote",
                "synopsis": title,
                "description": f"The remote host has {pkg} version {vuln_v} installed which is affected by {cve_to_use}. {title}",
                "solution": f"Upgrade {pkg} to {fixed_v or 'the latest vendor-supplied version'}.",
                "see_also": [f"https://nvd.nist.gov/vuln/detail/{cve_to_use}"],
                "cvss3_base_score": cvss,
                "cvss3_vector": cvss_vector_for(cvss),
                "cvss_base_score": cvss,
                "exploit_available": kev,
                "exploitability_ease": "Exploits are available" if kev else "No known exploits are available",
                "plugin_publication_date": iso(365),
                "plugin_modification_date": iso(30),
            },
            "severity": sev,
            "cve": [cve_to_use],
            "cwe": cwes,
            "first_found": iso(60),
            "last_found": iso(7),
            "risk_factor": sev,
            "patch_publication_date": iso(90),
        })
    return {
        "scan_name": "Daily Internal Network Scan",
        "scanner": "Tenable Nessus Professional",
        "scanner_version": "10.7.3",
        "scan_started_at": iso(7),
        "scan_completed_at": iso(7),
        "total_findings": len(findings),
        "vulnerabilities": findings,
    }


# ===========================================================================
# Tool generator: Qualys VMDR
# ===========================================================================

def gen_qualys_vuln(n: int) -> dict:
    findings = []
    for _ in range(n):
        cve_entry = pick_cve_for("os")
        cve, pkg, vuln_v, fixed_v, real_cvss, real_sev, title, cwes, kev = cve_entry
        sev = severity_weighted_choice()
        cvss = severity_to_cvss(sev) if sev != real_sev else real_cvss
        cve_to_use = maybe_synthetic(cve)
        host = RNG.choice(HOSTNAMES)
        # Qualys severity is 1-5: 5=Critical, 4=High, 3=Medium, 2=Medium-Low, 1=Low
        qualys_sev = {"Critical": "5", "High": "4", "Medium": "3", "Low": "2"}[sev]
        findings.append({
            "QID": str(RNG.randint(370000, 399999)),
            "TYPE": "Confirmed",
            "SEVERITY": qualys_sev,
            "TITLE": title,
            "CATEGORY": "Security Policy" if pkg in ("openssh-server","sudo") else "OS",
            "VENDOR_REFERENCE": cve_to_use,
            "CVSS_BASE": str(cvss),
            "CVSS3_BASE": str(cvss),
            "CVSS3_TEMPORAL": str(max(0.0, cvss - 0.4)),
            "CVE_LIST": {"CVE": [cve_to_use]},
            "BUGTRAQ_LIST": {"BUGTRAQ": [str(RNG.randint(20000, 99999))]} if RNG.random() < 0.3 else {},
            "DIAGNOSIS": f"Detected {pkg} version {vuln_v} on the target system. This version is vulnerable to {cve_to_use} ({title}).",
            "CONSEQUENCE": "Successful exploitation could lead to remote code execution, denial of service, or unauthorized access depending on the deployment.",
            "SOLUTION": f"Upgrade {pkg} to version {fixed_v or 'the vendor-supplied patched release'} or later.",
            "PCI_FLAG": "1" if sev in ("Critical","High") else "0",
            "EXPLOIT": {"SRC": [{"NAME": "Metasploit","DESC": "Module available"}]} if kev else {},
            "HOST": {
                "IP": _ip_for(host),
                "TRACKING_METHOD": "IP",
                "DNS": host,
                "OPERATING_SYSTEM": RNG.choice(OS_FOR_HOST),
                "NETBIOS_NAME": host.split(".")[0].upper(),
            },
            "PORT": str(RNG.choice([22, 80, 443, 445, 3389, 8080, 8443, 5432, 3306])),
            "PROTOCOL": "tcp",
            "SSL": "1" if RNG.random() < 0.4 else "0",
            "FIRST_FOUND_DATETIME": iso(120),
            "LAST_FOUND_DATETIME": iso(7),
            "TIMES_FOUND": str(RNG.randint(1, 12)),
            "RESULT": f"{pkg} {vuln_v} installed (vulnerable). Fixed in {fixed_v or 'vendor advisory'}.",
            "STATUS": "Active",
        })
    return {
        "ASSET_DATA_REPORT": {
            "HEADER": {
                "COMPANY": "Acme Corp",
                "USERNAME": "vuln-scanner-svc",
                "GENERATION_DATETIME": iso(1),
                "TEMPLATE": "Qualys Patch Report",
            },
            "RISK_SCORE_SUMMARY": {"AVG_SECURITY_RISK": str(round(sum(float(f["CVSS3_BASE"]) for f in findings) / max(1, len(findings)), 2))},
            "VULN_LIST": {"VULN": findings},
        },
        "total_findings": len(findings),
    }


# ===========================================================================
# Tool generator: Grype (Anchore)
# ===========================================================================

def _grype_ecosystem(image_name: str):
    # alpine -> apk, debian/ubuntu -> deb, others -> mix of pypi/npm
    if "alpine" in image_name:
        return "apk", "alpine"
    if "debian" in image_name or "ubuntu" in image_name or "nginx" in image_name or "postgres" in image_name or "redis" in image_name:
        return "deb", "debian"
    if "python" in image_name:
        return RNG.choice([("pypi","python"), ("apk","alpine")])
    if "node" in image_name:
        return RNG.choice([("npm","node"), ("apk","alpine")])
    return RNG.choice([("deb","debian"), ("apk","alpine"), ("npm","node"), ("pypi","python")])

def gen_grype(n: int) -> dict:
    matches = []
    for _ in range(n):
        img_name, img_tag, img_digest = RNG.choice(CONTAINER_IMAGES)
        eco_pair = _grype_ecosystem(img_name)
        if isinstance(eco_pair, tuple) and len(eco_pair) == 2 and isinstance(eco_pair[0], str):
            artifact_type, distro = eco_pair
        else:
            artifact_type, distro = eco_pair
        if artifact_type == "npm":
            cve_entry = pick_cve_for("npm")
        elif artifact_type == "pypi":
            cve_entry = pick_cve_for("pypi")
        else:
            cve_entry = pick_cve_for("os")
        cve, pkg, vuln_v, fixed_v, real_cvss, real_sev, title, cwes, kev = cve_entry
        sev = severity_weighted_choice()
        cvss = severity_to_cvss(sev) if sev != real_sev else real_cvss
        cve_to_use = maybe_synthetic(cve)
        # PURL for the artifact
        if artifact_type == "apk":
            purl = f"pkg:apk/alpine/{pkg}@{vuln_v}?arch=x86_64"
        elif artifact_type == "deb":
            purl = f"pkg:deb/debian/{pkg}@{vuln_v}?arch=amd64"
        elif artifact_type == "npm":
            purl = f"pkg:npm/{pkg}@{vuln_v}"
        elif artifact_type == "pypi":
            purl = f"pkg:pypi/{pkg.lower().replace('_','-')}@{vuln_v}"
        else:
            purl = f"pkg:generic/{pkg}@{vuln_v}"
        matches.append({
            "vulnerability": {
                "id": cve_to_use,
                "dataSource": f"https://nvd.nist.gov/vuln/detail/{cve_to_use}",
                "namespace": f"nvd:cpe" if not artifact_type == "apk" else "alpine:distro:alpine:3.18",
                "severity": sev,
                "urls": [f"https://nvd.nist.gov/vuln/detail/{cve_to_use}"],
                "description": f"{title}. Affects {pkg} prior to {fixed_v or 'patched version'}.",
                "cvss": [{
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "version": "3.1",
                    "vector": cvss_vector_for(cvss),
                    "metrics": {"baseScore": cvss, "exploitabilityScore": round(RNG.uniform(2.0, 3.9), 1), "impactScore": round(RNG.uniform(3.0, 5.9), 1)},
                }],
                "fix": {"versions": [fixed_v] if fixed_v else [], "state": "fixed" if fixed_v else "unknown"},
                "advisories": [],
            },
            "relatedVulnerabilities": [],
            "matchDetails": [{
                "type": "exact-direct-match",
                "matcher": f"{artifact_type}-matcher",
                "searchedBy": {"distro": {"type": distro, "version": "3.18"} if artifact_type == "apk" else None, "namespace": f"nvd:cpe", "package": {"name": pkg, "version": vuln_v}},
                "found": {"versionConstraint": f"< {fixed_v or 'unknown'} ({artifact_type})", "vulnerabilityID": cve_to_use},
            }],
            "artifact": {
                "id": "".join(RNG.choices("0123456789abcdef", k=16)),
                "name": pkg,
                "version": vuln_v,
                "type": artifact_type if artifact_type != "pypi" else "python",
                "locations": [{"path": f"/usr/lib/{pkg}/{vuln_v}/" if artifact_type in ("apk","deb") else f"/app/node_modules/{pkg}/package.json"}],
                "language": {"npm": "javascript", "pypi": "python"}.get(artifact_type, ""),
                "licenses": ["MIT"] if artifact_type in ("npm","pypi") else ["GPL-2.0-only"],
                "cpes": [f"cpe:2.3:a:{pkg.split('/')[-1]}:{pkg.split('/')[-1]}:{vuln_v}:*:*:*:*:*:*:*"],
                "purl": purl,
                "upstreams": [{"name": pkg.split("/")[-1]}],
            },
        })
    distinct_images = list({(n, t, d) for (n, t, d) in [RNG.choice(CONTAINER_IMAGES) for _ in range(min(n, 12))]})
    primary_image = distinct_images[0] if distinct_images else ("alpine","3.18.6","sha256:abc")
    return {
        "matches": matches,
        "source": {
            "type": "image",
            "target": {
                "userInput": f"{primary_image[0]}:{primary_image[1]}",
                "imageID": primary_image[2],
                "manifestDigest": primary_image[2],
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "tags": [f"{primary_image[0]}:{primary_image[1]}"],
                "imageSize": RNG.randint(50_000_000, 800_000_000),
                "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": primary_image[2], "size": RNG.randint(10_000_000, 200_000_000)}],
            },
        },
        "distro": {"name": "alpine", "version": "3.18.6", "idLike": ["alpine"]},
        "descriptor": {
            "name": "grype",
            "version": "0.79.6",
            "configuration": {"output": ["json"], "fail-on-severity": "", "exclude": []},
            "db": {"built": "2026-06-21T01:30:14Z", "schemaVersion": 5, "location": "/home/user/.cache/grype/db/5", "checksum": "sha256:" + "0"*64, "error": None},
        },
    }


# ===========================================================================
# Tool generator: Snyk Open Source / SCA
# ===========================================================================

SNYK_ECOSYSTEMS = [
    ("npm", "package-lock.json"),
    ("pypi", "requirements.txt"),
    ("maven", "pom.xml"),
]

def gen_snyk(n: int) -> dict:
    vulns = []
    for _ in range(n):
        eco, manifest = RNG.choice(SNYK_ECOSYSTEMS)
        if eco == "npm":
            cve_entry = pick_cve_for("npm")
        elif eco == "pypi":
            cve_entry = pick_cve_for("pypi")
        else:
            cve_entry = pick_cve_for("java")
        cve, pkg, vuln_v, fixed_v, real_cvss, real_sev, title, cwes, kev = cve_entry
        sev = severity_weighted_choice()
        cvss = severity_to_cvss(sev) if sev != real_sev else real_cvss
        cve_to_use = maybe_synthetic(cve)
        snyk_id_eco = {"npm":"JS","pypi":"PYTHON","maven":"JAVA"}[eco]
        snyk_id = f"SNYK-{snyk_id_eco}-{pkg.upper().replace('@','').replace('/','-').replace('.','').replace(':','')[:30]}-{RNG.randint(1000000,9999999)}"
        repo = RNG.choice(REPOS_FRONTEND if eco == "npm" else REPOS_BACKEND)
        project_name = f"acmecorp/{repo}({manifest})"
        vulns.append({
            "id": snyk_id,
            "title": title,
            "CVSSv3": cvss_vector_for(cvss),
            "credit": ["Snyk Security Research"],
            "semver": {"vulnerable": [f"<{fixed_v}" if fixed_v else f"={vuln_v}"]},
            "exploit": "Proof of Concept" if kev else "Not Defined",
            "fixedIn": [fixed_v] if fixed_v else [],
            "patches": [],
            "insights": {"triageAdvice": None},
            "language": {"npm":"js","pypi":"python","maven":"java"}[eco],
            "severity": sev.lower(),
            "cvssScore": cvss,
            "functions": [],
            "moduleName": pkg,
            "references": [
                {"url": f"https://snyk.io/vuln/{snyk_id}", "title": "Snyk Advisory"},
                {"url": f"https://nvd.nist.gov/vuln/detail/{cve_to_use}", "title": "NVD"},
            ],
            "cvssDetails": [{"assigner":"Snyk","severity":sev.lower(),"cvssV3Vector":cvss_vector_for(cvss),"cvssV3BaseScore":cvss,"modificationTime": iso(90)}],
            "description": f"## Overview\n[{pkg}](https://snyk.io/vuln/{snyk_id}) is affected by {title}.\n\n## Details\nAffected versions: <{fixed_v or 'no fix available'}. Detected version: {vuln_v}.\n\n## Remediation\nUpgrade `{pkg}` to version `{fixed_v or 'a non-vulnerable release'}` or later.",
            "epssDetails": {"percentile": str(round(RNG.uniform(0.10, 0.99), 5)), "probability": str(round(RNG.uniform(0.0001, 0.4), 5)), "modelVersion": "v2024.04.23"},
            "identifiers": {
                "CVE": [cve_to_use],
                "CWE": cwes,
                "GHSA": [f"GHSA-{''.join(RNG.choices('abcdefghijklmnop',k=4))}-{''.join(RNG.choices('abcdefghijklmnop',k=4))}-{''.join(RNG.choices('abcdefghijklmnop',k=4))}"],
            },
            "publicationTime": iso(180),
            "disclosureTime": iso(180),
            "creationTime": iso(180),
            "modificationTime": iso(30),
            "from": [
                f"{repo}@1.0.0",
                f"{pkg}@{vuln_v}",
            ],
            "upgradePath": [False, f"{pkg}@{fixed_v}" if fixed_v else False],
            "isUpgradable": bool(fixed_v),
            "isPatchable": False,
            "name": pkg,
            "version": vuln_v,
            "packageManager": eco,
            "packageName": pkg,
            "projectName": project_name,
        })
    return {
        "ok": False,
        "vulnerabilities": vulns,
        "dependencyCount": RNG.randint(200, 1800),
        "org": "acmecorp",
        "policy": "# Snyk (https://snyk.io) policy file\nversion: v1.25.0\nignore: {}\npatch: {}\n",
        "isPrivate": True,
        "licensesPolicy": {"severities": {}, "orgLicenseRules": {}},
        "packageManager": "npm",
        "summary": f"{len(vulns)} vulnerable dependency paths",
        "filesystemPolicy": False,
        "filtered": {"ignore": [], "patch": []},
        "uniqueCount": len({v["id"] for v in vulns}),
        "projectName": "acmecorp/monorepo",
        "displayTargetFile": "package-lock.json",
        "path": "/builds/acmecorp/monorepo",
    }


# ===========================================================================
# Tool generator: SonarQube (SAST)
# ===========================================================================

SONAR_RULES = [
    ("javasecurity:S2076", "java", "Command Injection", "CWE-78"),
    ("javasecurity:S3649", "java", "SQL Injection", "CWE-89"),
    ("javasecurity:S2078", "java", "LDAP Injection", "CWE-90"),
    ("javasecurity:S5131", "java", "XSS — Reflected", "CWE-79"),
    ("javasecurity:S5135", "java", "Insecure Deserialization", "CWE-502"),
    ("javasecurity:S2755", "java", "XML External Entity (XXE)", "CWE-611"),
    ("javasecurity:S5145", "java", "Log Injection", "CWE-117"),
    ("javasecurity:S6549", "java", "Path Traversal", "CWE-22"),
    ("python:S2076", "py", "Command Injection", "CWE-78"),
    ("python:S3649", "py", "SQL Injection", "CWE-89"),
    ("python:S5131", "py", "XSS — Server-side", "CWE-79"),
    ("python:S4790", "py", "Use of Insecure Hash", "CWE-327"),
    ("python:S2245", "py", "Use of Insecure Random", "CWE-330"),
    ("python:S2068", "py", "Hardcoded Credentials", "CWE-798"),
    ("python:S6437", "py", "Hardcoded Secret", "CWE-798"),
    ("python:S5443", "py", "Insecure Use of Temp File", "CWE-377"),
    ("javascript:S5247", "js", "DOM-based XSS", "CWE-79"),
    ("javascript:S5547", "js", "Use of Insecure Cipher", "CWE-327"),
    ("javascript:S2068", "js", "Hardcoded Credentials", "CWE-798"),
    ("javascript:S5852", "js", "Regex DoS", "CWE-1333"),
    ("typescript:S5247", "ts", "DOM-based XSS", "CWE-79"),
    ("typescript:S5443", "ts", "Insecure Use of Temp File", "CWE-377"),
    ("csharpsecurity:S2076", "cs", "Command Injection", "CWE-78"),
    ("csharpsecurity:S3649", "cs", "SQL Injection", "CWE-89"),
    ("csharpsecurity:S5131", "cs", "XSS — Reflected", "CWE-79"),
]

SONAR_FILES = [
    "src/main/java/com/acme/checkout/CheckoutController.java",
    "src/main/java/com/acme/auth/AuthService.java",
    "src/main/java/com/acme/payments/PaymentProcessor.java",
    "src/main/java/com/acme/orders/OrderRepository.java",
    "src/main/java/com/acme/users/UserController.java",
    "src/main/java/com/acme/admin/AdminTools.java",
    "src/main/java/com/acme/util/HttpClientFactory.java",
    "src/main/java/com/acme/integrations/SlackNotifier.java",
    "checkout-service/app/views.py",
    "checkout-service/app/models/user.py",
    "checkout-service/app/utils/crypto.py",
    "checkout-service/app/api/v2/orders.py",
    "data-warehouse-etl/etl/runner.py",
    "frontend-web/src/components/SearchBar.jsx",
    "frontend-web/src/components/OrderDetails.jsx",
    "frontend-web/src/components/admin/UserTable.jsx",
    "frontend-web/src/pages/Login.tsx",
    "frontend-web/src/lib/api.ts",
    "admin-dashboard/src/pages/Reports.tsx",
    "internal-tools/MerchantPortal/Controllers/InvoiceController.cs",
    "internal-tools/MerchantPortal/Services/EmailService.cs",
]

def gen_sonarqube(n: int) -> dict:
    issues = []
    components = set()
    for i in range(n):
        rule, lang, rule_name, cwe = RNG.choice(SONAR_RULES)
        sev = severity_weighted_choice()
        sonar_sev = {"Critical":"BLOCKER","High":"CRITICAL","Medium":"MAJOR","Low":"MINOR"}[sev]
        # Sonar findings usually don't have CVE; ~30% chance we attach one (e.g.
        # for findings about "use of vulnerable library version").
        attach_cve = RNG.random() < 0.30
        cve_to_use = None
        cwes_list = [cwe]
        if attach_cve:
            if lang == "java":
                cve_entry = pick_cve_for("java")
            elif lang in ("js","ts"):
                cve_entry = pick_cve_for("npm")
            elif lang == "py":
                cve_entry = pick_cve_for("pypi")
            else:
                cve_entry = pick_cve_for("any")
            cve, pkg, vuln_v, fixed_v, real_cvss, real_sev, title, cwes, kev = cve_entry
            cve_to_use = maybe_synthetic(cve)
            cwes_list = list({*cwes_list, *cwes})
        file_path = RNG.choice([f for f in SONAR_FILES if f.endswith(("."+lang) if lang!="ts" else ".tsx") or (lang=="js" and f.endswith((".js",".jsx"))) or (lang=="ts" and f.endswith((".ts",".tsx"))) or (lang=="py" and f.endswith(".py")) or (lang=="java" and f.endswith(".java")) or (lang=="cs" and f.endswith(".cs"))] or SONAR_FILES)
        project = file_path.split("/")[0]
        component = f"{project}:{file_path}"
        components.add((project, file_path))
        issues.append({
            "key": f"AY{''.join(RNG.choices('abcdefghijklmnopqrstuvwxyz0123456789',k=20))}",
            "rule": rule,
            "severity": sonar_sev,
            "component": component,
            "project": project,
            "line": RNG.randint(15, 480),
            "hash": "".join(RNG.choices("0123456789abcdef", k=32)),
            "textRange": {"startLine": (sl := RNG.randint(15,480)), "endLine": sl, "startOffset": RNG.randint(0,40), "endOffset": RNG.randint(40,120)},
            "flows": [],
            "status": "OPEN",
            "message": f"{rule_name}: refactor this code to eliminate the {rule_name.lower()} risk.",
            "effort": RNG.choice(["20min","30min","1h","2h","4h","1d"]),
            "debt": RNG.choice(["20min","30min","1h","2h","4h","1d"]),
            "author": RNG.choice(["alice.smith@acmecorp.com","bob.jones@acmecorp.com","charlie.lee@acmecorp.com","priya.patel@acmecorp.com"]),
            "tags": ["cwe", "owasp-top10", f"cwe-{cwe.lower().replace('cwe-','')}"],
            "creationDate": iso(180),
            "updateDate": iso(30),
            "type": "VULNERABILITY",
            "scope": "MAIN",
            "quickFixAvailable": False,
            "messageFormattings": [],
            "cleanCodeAttribute": "TRUSTWORTHY",
            "cleanCodeAttributeCategory": "RESPONSIBLE",
            "impacts": [{"softwareQuality": "SECURITY", "severity": sonar_sev}],
            "issueStatus": "OPEN",
            "prioritizedRule": False,
            "cwe": [cwe],
            **({"cve": [cve_to_use]} if cve_to_use else {}),
        })
    return {
        "total": len(issues),
        "p": 1,
        "ps": len(issues),
        "paging": {"pageIndex": 1, "pageSize": len(issues), "total": len(issues)},
        "effortTotal": len(issues) * 30,
        "debtTotal": len(issues) * 30,
        "issues": issues,
        "components": [{"key": f"{proj}:{path}", "enabled": True, "qualifier": "FIL", "name": path.split("/")[-1], "longName": path, "path": path} for proj, path in components],
        "facets": [],
    }


# ===========================================================================
# Tool generator: Burp Suite (DAST)
# ===========================================================================

BURP_HOSTS = [
    "https://app.acmecorp.com",
    "https://api.acmecorp.com",
    "https://admin.acmecorp.com",
    "https://checkout.acmecorp.com",
    "https://merchants.acmecorp.com",
    "https://staging.acmecorp.com",
]

BURP_PATHS = [
    "/login", "/api/v1/users", "/api/v1/users/{id}", "/api/v1/orders",
    "/api/v1/orders/{id}", "/api/v1/payments", "/api/v1/admin/reports",
    "/search", "/products", "/cart", "/cart/checkout", "/profile",
    "/profile/settings", "/admin", "/admin/users", "/admin/reports",
    "/static/js/main.js", "/assets/uploads/{file}", "/api/v2/graphql",
    "/api/v1/webhook/payment-callback", "/api/v1/files/upload",
    "/forgot-password", "/reset-password", "/oauth/callback", "/internal/debug",
]

def gen_burp(n: int) -> dict:
    issue_events = []
    issue_defs_seen = {}
    type_index_seq = 2097920
    for _ in range(n):
        finding = RNG.choice(WEB_CWE_FINDINGS)
        cwe, owasp, sev, real_cvss, name, desc = finding
        sev_pick = severity_weighted_choice()
        cvss = severity_to_cvss(sev_pick) if sev_pick != sev else real_cvss
        # ~40% chance the burp finding includes a CVE (e.g. detected vulnerable
        # framework version on the response server header).
        attach_cve = RNG.random() < 0.40
        cve_to_use = None
        cwes_list = [cwe]
        if attach_cve:
            cve_entry = pick_cve_for("any")
            cve, pkg, vuln_v, fixed_v, _, _, title, cwes, kev = cve_entry
            cve_to_use = maybe_synthetic(cve)
            cwes_list = list({*cwes_list, *cwes})
        host = RNG.choice(BURP_HOSTS)
        path = RNG.choice(BURP_PATHS).replace("{id}", str(RNG.randint(1, 99999))).replace("{file}", f"file_{RNG.randint(1,9999)}.pdf")
        if name not in issue_defs_seen:
            type_index_seq += 16
            issue_defs_seen[name] = type_index_seq
        type_index = issue_defs_seen[name]
        burp_sev = {"Critical":"High","High":"High","Medium":"Medium","Low":"Low"}[sev_pick]
        confidence = RNG.choice(["Certain","Firm","Tentative"])
        issue_events.append({
            "issue": {
                "name": name,
                "type_index": type_index,
                "serial_number": RNG.randint(1000000000, 9999999999),
                "severity": burp_sev,
                "confidence": confidence,
                "host": {"name": host, "ip_address": _ip_for(host.replace("https://",""))},
                "path": path,
                "location": f"{path}{'?q=' if 'XSS' in name or 'SQL' in name else ''}{'<script>alert(1)</script>' if 'XSS' in name else ''}",
                "issue_background": desc + ". Such vulnerabilities are commonly exploited to compromise user accounts, steal session data, or pivot deeper into the application.",
                "remediation_background": "Input from untrusted sources should be properly validated, encoded for the appropriate context, or rejected. Use parameterized queries / safe encoding APIs.",
                "issue_detail": f"The application appears to be vulnerable to {name.lower()}. The payload was reflected/executed in the response from {host}{path}.",
                "remediation_detail": "Apply context-appropriate output encoding and use parameterized queries / safe APIs. Validate inputs at trust boundaries.",
                "request": f"GET {path} HTTP/1.1\\r\\nHost: {host.replace('https://','')}\\r\\n\\r\\n",
                "response": "HTTP/1.1 200 OK\\r\\nServer: nginx/1.25.3\\r\\nContent-Type: text/html\\r\\n\\r\\n<html>...</html>",
                "vulnerability_classifications": cwe + (" — " + owasp if owasp else ""),
                "vulnerability_classifications_array": cwes_list,
                "owasp_category": owasp,
                "references": [
                    f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-','')}.html",
                    *([f"https://nvd.nist.gov/vuln/detail/{cve_to_use}"] if cve_to_use else []),
                ],
                **({"cve": [cve_to_use]} if cve_to_use else {}),
                "cvss_score": cvss,
                "cvss_vector": cvss_vector_for(cvss),
                "first_detected": iso(60),
                "last_detected": iso(7),
            }
        })
    return {
        "scan_metadata": {
            "scanner": "Burp Suite Professional",
            "scanner_version": "2024.6.2",
            "scan_name": "External Application Scan — Production",
            "scan_target": list({e["issue"]["host"]["name"] for e in issue_events})[:5],
            "scan_started": iso(7),
            "scan_completed": iso(7),
            "total_requests": RNG.randint(45000, 180000),
        },
        "issue_events": issue_events,
        "issue_definitions": [
            {"type_index": idx, "name": name, "description": f"Issue definition for {name}.", "remediation": "Apply context-appropriate fixes."} for name, idx in issue_defs_seen.items()
        ],
    }


# ===========================================================================
# Main — generate all six files.
# ===========================================================================

SPEC = [
    ("tenable-nessus-vuln-scan.json", gen_nessus,       375, "Tenable Nessus — host/network"),
    ("qualys-vmdr-vuln-scan.json",    gen_qualys_vuln,  330, "Qualys VMDR — host/network"),
    ("grype-scan.json",                gen_grype,        270, "Anchore Grype — container"),
    ("snyk-appsec-scan.json",          gen_snyk,         270, "Snyk Open Source — SCA"),
    ("sonarqube-appsec-scan.json",     gen_sonarqube,    180, "SonarQube — SAST"),
    ("burp-suite-scan.json",           gen_burp,         150, "Burp Suite — DAST"),
]

def main() -> None:
    total = 0
    for filename, gen, count, label in SPEC:
        out = OUT_DIR / filename
        payload = gen(count)
        out.write_text(json.dumps(payload, indent=2))
        size_kb = out.stat().st_size / 1024
        print(f"  ✓ {filename:32s} {count:>5} findings   {size_kb:>8.1f} KB   ({label})")
        total += count
    print(f"\nWrote 6 files to {OUT_DIR}")
    print(f"Total findings across all files: {total}")

if __name__ == "__main__":
    main()
