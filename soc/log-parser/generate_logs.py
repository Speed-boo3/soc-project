import random
import os
from datetime import datetime, timedelta

USERNAMES = ["root", "admin", "user", "ubuntu", "postgres", "deploy", "git", "test"]
IPS_SUSPICIOUS = ["192.168.1.100", "10.0.0.99", "45.33.32.156", "185.220.101.45", "198.20.69.74"]
IPS_CLEAN = ["10.0.0.5", "172.16.0.10", "192.168.0.50"]
APACHE_PATHS = ["/index.html", "/login", "/admin", "/api/v1/users", "/.env", "/wp-login.php", "/phpmyadmin"]
HOSTNAME = "webserver"


def timestamp(offset_minutes=0):
    t = datetime.now() - timedelta(minutes=offset_minutes)
    return t.strftime("%b %d %H:%M:%S")


def random_ip(suspicious=False):
    return random.choice(IPS_SUSPICIOUS if suspicious else IPS_CLEAN)


def make_failed_ssh(ip, ts):
    user = random.choice(USERNAMES)
    port = random.randint(40000, 65000)
    return f"{ts} {HOSTNAME} sshd[{random.randint(1000,9999)}]: Failed password for {user} from {ip} port {port} ssh2"


def make_invalid_user(ip, ts):
    user = random.choice(["oracle", "ftpuser", "nagios", "jenkins", "hadoop"])
    return f"{ts} {HOSTNAME} sshd[{random.randint(1000,9999)}]: Invalid user {user} from {ip}"


def make_accepted_ssh(ts):
    ip = random_ip(suspicious=False)
    user = "alice"
    port = random.randint(40000, 65000)
    return f"{ts} {HOSTNAME} sshd[{random.randint(1000,9999)}]: Accepted password for {user} from {ip} port {port} ssh2"


def make_sudo_failure(ts):
    return f"{ts} {HOSTNAME} sudo[{random.randint(1000,9999)}]: pam_unix(sudo:auth): authentication failure; logname= uid={random.randint(1001,1005)}"


def make_apache(ip, path, status, ts):
    size = random.randint(200, 5000)
    return f'{ip} - - [{ts}] "GET {path} HTTP/1.1" {status} {size}'


def make_segfault(ts):
    return f"{ts} {HOSTNAME} kernel: program[{random.randint(1000,9999)}]: segfault at 0 ip 00007f rsp 00007f error 4"


def generate():
    lines = []
    now_offset = 0

    attack_ip = random.choice(IPS_SUSPICIOUS)

    for _ in range(random.randint(4, 8)):
        now_offset += random.randint(0, 2)
        lines.append(make_failed_ssh(attack_ip, timestamp(now_offset)))

    for _ in range(random.randint(1, 3)):
        now_offset += random.randint(0, 2)
        lines.append(make_invalid_user(attack_ip, timestamp(now_offset)))

    now_offset += random.randint(1, 5)
    lines.append(make_sudo_failure(timestamp(now_offset)))

    now_offset += random.randint(1, 3)
    lines.append(make_accepted_ssh(timestamp(now_offset)))

    web_ip = random.choice(IPS_SUSPICIOUS)
    for _ in range(random.randint(3, 6)):
        path = random.choice(APACHE_PATHS)
        status = random.choice([200, 401, 401, 403, 404])
        now_offset += random.randint(0, 1)
        lines.append(make_apache(web_ip, path, status, datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")))

    if random.random() > 0.5:
        now_offset += random.randint(1, 5)
        lines.append(make_segfault(timestamp(now_offset)))

    for _ in range(random.randint(2, 4)):
        path = random.choice(["/index.html", "/about", "/contact"])
        clean_ip = random_ip(suspicious=False)
        now_offset += random.randint(0, 1)
        lines.append(make_apache(clean_ip, path, 200, datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")))

    random.shuffle(lines)
    return "\n".join(lines) + "\n"


def main():
    output_path = os.path.join(os.path.dirname(__file__), "sample.log")
    content = generate()
    with open(output_path, "w") as f:
        f.write(content)
    print(f"Generated {len(content.splitlines())} log lines -> {output_path}")


if __name__ == "__main__":
    main()
