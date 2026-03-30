import random
import os
from datetime import datetime, timedelta

USERNAMES = ["root", "admin", "user", "ubuntu", "postgres", "deploy", "git", "test", "oracle", "nagios", "jenkins"]
IPS_SUSPICIOUS = ["45.33.32.156", "185.220.101.45", "198.20.69.74", "192.168.1.100", "10.0.0.99", "89.248.167.131", "194.165.16.11"]
IPS_CLEAN = ["10.0.0.5", "172.16.0.10", "192.168.0.50", "192.168.1.10"]
APACHE_PATHS = ["/index.html", "/login", "/admin", "/api/v1/users", "/.env", "/wp-login.php",
                "/phpmyadmin", "/../etc/passwd", "/api/v1/admin", "/config.php",
                "/login?user=admin'--", "/search?q=<script>alert(1)</script>"]
USER_AGENTS = ["Mozilla/5.0", "sqlmap/1.7", "curl/7.68.0", "python-requests/2.28", "Nikto/2.1.6", "masscan/1.0"]
HOSTNAME = "webserver"


def ts(offset_minutes=0):
    t = datetime.now() - timedelta(minutes=offset_minutes)
    return t.strftime("%b %d %H:%M:%S")


def apache_ts():
    return datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")


def make_failed_ssh(ip, offset=0):
    u = random.choice(USERNAMES)
    port = random.randint(40000, 65000)
    return f"{ts(offset)} {HOSTNAME} sshd[{random.randint(1000,9999)}]: Failed password for {u} from {ip} port {port} ssh2"


def make_root_ssh(ip, offset=0):
    port = random.randint(40000, 65000)
    return f"{ts(offset)} {HOSTNAME} sshd[{random.randint(1000,9999)}]: Failed password for root from {ip} port {port} ssh2"


def make_invalid_user(ip, offset=0):
    u = random.choice(["oracle", "ftpuser", "nagios", "jenkins", "hadoop", "elasticsearch"])
    return f"{ts(offset)} {HOSTNAME} sshd[{random.randint(1000,9999)}]: Invalid user {u} from {ip}"


def make_accepted_ssh(offset=0):
    ip = random.choice(IPS_CLEAN)
    port = random.randint(40000, 65000)
    return f"{ts(offset)} {HOSTNAME} sshd[{random.randint(1000,9999)}]: Accepted publickey for deploy from {ip} port {port} ssh2"


def make_sudo_failure(offset=0):
    uid = random.randint(1001, 1005)
    return f"{ts(offset)} {HOSTNAME} sudo[{random.randint(1000,9999)}]: pam_unix(sudo:auth): authentication failure; logname= uid={uid}"


def make_apache(ip, path, status, ua=None, offset=0):
    if ua is None:
        ua = random.choice(USER_AGENTS)
    size = random.randint(200, 5000)
    return f'{ip} - - [{apache_ts()}] "GET {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def make_segfault(offset=0):
    return f"{ts(offset)} {HOSTNAME} kernel: program[{random.randint(1000,9999)}]: segfault at 0 ip 00007f rsp 00007f error 4"


def make_port_scan(ip, offset=0):
    return f"{ts(offset)} {HOSTNAME} kernel: [UFW BLOCK] IN=eth0 SRC={ip} SCAN flags=S"


def generate():
    lines = []
    attack_ip = random.choice(IPS_SUSPICIOUS)
    offset = 0

    # SSH brute force burst
    burst = random.randint(4, 9)
    for _ in range(burst):
        offset += random.randint(0, 1)
        if random.random() > 0.6:
            lines.append(make_root_ssh(attack_ip, offset))
        else:
            lines.append(make_failed_ssh(attack_ip, offset))

    # Invalid user attempts
    for _ in range(random.randint(1, 3)):
        offset += 1
        lines.append(make_invalid_user(attack_ip, offset))

    # Sudo failure
    offset += random.randint(1, 4)
    lines.append(make_sudo_failure(offset))

    # Legitimate login
    offset += random.randint(1, 3)
    lines.append(make_accepted_ssh(offset))

    # Web attacks
    web_ip = random.choice(IPS_SUSPICIOUS)
    # Normal traffic
    for path in ["/index.html", "/about", "/contact"]:
        lines.append(make_apache(random.choice(IPS_CLEAN), path, 200))

    # Suspicious web traffic
    lines.append(make_apache(web_ip, "/login", 401, "Mozilla/5.0"))
    lines.append(make_apache(web_ip, "/login", 401, "Mozilla/5.0"))
    lines.append(make_apache(web_ip, "/login", 401, "Mozilla/5.0"))
    lines.append(make_apache(web_ip, "/admin", 403))
    lines.append(make_apache(web_ip, "/../etc/passwd", 400))

    # SQLmap probe
    sqli_ip = random.choice(IPS_SUSPICIOUS)
    lines.append(make_apache(sqli_ip, "/search?q=1' OR '1'='1", 200, "sqlmap/1.7"))

    # Optional segfault
    if random.random() > 0.4:
        lines.append(make_segfault())

    # Optional port scan
    if random.random() > 0.5:
        lines.append(make_port_scan(random.choice(IPS_SUSPICIOUS)))

    random.shuffle(lines)
    return "\n".join(lines) + "\n"


def main():
    output_path = os.path.join(os.path.dirname(__file__), "sample.log")
    content = generate()
    with open(output_path, "w") as f:
        f.write(content)
    line_count = len(content.splitlines())
    print(f"Generated {line_count} log lines -> {output_path}")


if __name__ == "__main__":
    main()
