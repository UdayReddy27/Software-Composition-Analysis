import requests
import uuid
import datetime

def perform_dast_scan(url, session_id):
    scan_uuid = str(uuid.uuid4())
    vulnerabilities = []  # Initialize an empty list to store vulnerabilities

    data = {
        "uuid": scan_uuid,
        "timestamp": datetime.datetime.now().isoformat(),
        "scantype": "dast_scan",
        "session_id": session_id,  # Save session ID here
        "vulnerabilities": vulnerabilities  # Add vulnerabilities list to data
    }

    # Test 1: SQL Injection
    sql_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' OR 1=1 --",
        "' AND 1=2 UNION SELECT NULL, version(), NULL --"
    ]
    for payload in sql_payloads:
        response = requests.get(url, params={'test': payload})
        if response.status_code == 200:
            if "SQL" in response.text or "syntax" in response.text or "database" in response.text.lower():
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'url': response.url,
                    'payload': payload
                })

    # Test 2: Cross-Site Scripting (XSS)
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<body onload=alert('XSS')>"
    ]
    for payload in xss_payloads:
        response = requests.get(url, params={'test': payload})
        if response.status_code == 200 and payload in response.text:
            vulnerabilities.append({
                'type': 'Cross-Site Scripting (XSS)',
                'url': response.url,
                'payload': payload
            })

    # Test 3: Open Redirect
    open_redirect_payloads = [
        "http://evil.com",
        "//evil.com",
        "/redirect?url=http://evil.com"
    ]
    for payload in open_redirect_payloads:
        response = requests.get(url, params={'redirect': payload}, allow_redirects=False)
        if response.status_code in (301, 302) and "evil.com" in response.headers.get("Location", ""):
            vulnerabilities.append({
                'type': 'Open Redirect',
                'url': response.url,
                'payload': payload
            })

    # Test 4: Command Injection
    command_injection_payloads = [
        "|| ls",
        "; cat /etc/passwd",
        "| whoami",
        "`id`"
    ]
    for payload in command_injection_payloads:
        response = requests.get(url, params={'cmd': payload})
        if response.status_code == 200 and any(keyword in response.text.lower() for keyword in ["root", "uid=", "gid="]):
            vulnerabilities.append({
                'type': 'Command Injection',
                'url': response.url,
                'payload': payload
            })

    # Test 5: Path Traversal
    path_traversal_payloads = [
        "../../../../etc/passwd",
        "../../../../../etc/hosts",
        "/../../../../../../boot.ini"
    ]
    for payload in path_traversal_payloads:
        response = requests.get(url, params={'file': payload})
        if response.status_code == 200 and any(keyword in response.text for keyword in ["root:", "[boot loader]", "localhost"]):
            vulnerabilities.append({
                'type': 'Path Traversal',
                'url': response.url,
                'payload': payload
            })

    # Test 6: HTTP Header Manipulation
    header_injection_payloads = [
        "<script>alert('Injected!')</script>",
        "XSS-Test"
    ]

    for payload in header_injection_payloads:
        headers = {'Custom-Header': payload}
        response = requests.get(url, headers=headers)
        if payload in response.text:
            vulnerabilities.append({
                'type': 'HTTP Header Manipulation',
                'url': response.url,
                'payload': payload,
            })

    return data
