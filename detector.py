import re

LOG_FILE = "sample_logs/attack.log"

sqli_patterns = [
    r"or\s+\%271\%27\%3d\%271",
    r"or\s+'1'='1",
    r"union\s+select",
    r"%27\+or\+%271",
]

login_hits = {}

def detect_attacks(log_file):
    with open(log_file, "r") as f:
        for line in f:
            l = line.lower()

            # SQL Injection detection
            for pattern in sqli_patterns:
                if re.search(pattern, l):
                    print("\n[ALERT] Possible SQL Injection Detected")
                    print(line.strip())
                    break

            # Brute-force detection (many hits to login.php)
            if "login.php" in l:
                ip = l.split()[0]
                login_hits[ip] = login_hits.get(ip, 0) + 1

                if login_hits[ip] == 5:
                    print(f"\n[ALERT] Possible Brute Force from {ip}")
                    print("More than 5 login attempts detected")

detect_attacks(LOG_FILE)
