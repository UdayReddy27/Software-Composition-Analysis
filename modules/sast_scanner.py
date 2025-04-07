import re
import uuid
import datetime

def perform_sast_scan(filepath, session_id):
    scan_uuid = str(uuid.uuid4())
    vulnerabilities = []  # Initialize an empty list to store vulnerabilities

    data = {
        "uuid": scan_uuid,
        "scantype": "sast_scan",
        "timestamp": datetime.datetime.now().isoformat(),
        "session_id": session_id,  # Save session ID here
        "vulnerabilities": vulnerabilities  # Add vulnerabilities list to data
    }

    # Patterns for detecting vulnerabilities
    patterns = {
        # Hardcoded credentials (password, API key, secret)
        'hardcoded_credentials': re.compile(
            r"(?i)(['\"]?(api[_]?key|password|secret|token|access_key)['\"]?)\s*[:=]\s*['\"].+['\"]"
        ),
        # Insecure imports
        'insecure_imports': re.compile(
            r"(import\s+(os|subprocess|pickle)|from\s+(os|subprocess|pickle)\s+import)"
        ),
        # Command injection
        'command_injection': re.compile(
            r"os\.system\([^)]+|subprocess\.(call|Popen|run|check_output)\([^)]+"
        ),
        # SQL injection (unsafe queries using string interpolation or concatenation)
        'sql_injection': re.compile(
            r"(cursor\.execute\(|cursor\.executemany\().*\+.*"
        ),
        # Insecure HTTP URLs
        'insecure_http': re.compile(
            r"http://[^\s\"']+"
        ),
        # Improper exception handling
        'improper_exception_handling': re.compile(
            r"except\s*:\s*(#.*|pass)?\s*$"
        ),
    }

    # Analyze the file line by line
    with open(filepath, 'r') as file:
        lines = file.readlines()
        for i, line in enumerate(lines):
            for vuln, pattern in patterns.items():
                if pattern.search(line):
                    vulnerabilities.append({
                        'type': vuln,
                        'line': i + 1,
                        'code': line.strip(),
                    })

    return data