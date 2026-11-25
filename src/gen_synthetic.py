"""Synthetic Wazuh-style alerts with known labels (provenance = synthetic).

Every rule ID here (900xxx) is ILLUSTRATIVE. None of them is a Wazuh rule, and
no rule level or description is copied from Wazuh's ruleset.

Each family has two rules, and every rule produces both attacks (tp) and normal
activity (fp). So neither the rule ID nor the rule level alone gives the answer:
the details (who, from where, what command) decide. Commands are harmless strings.

IP ranges: 10.x = internal, 203.0.113.x / 198.51.100.x = documentation ranges
standing in for the internet.
"""
import base64
import random

from .common import ROOT, load_config, write_jsonl
from .schema import Alert

HOSTS = ["web01", "web02", "mail01", "db01", "files01", "ws-114", "ws-207", "jump01"]
STAFF = ["a.khan", "s.ali", "m.rossi", "j.lee", "t.novak", "p.silva"]
DAY = ["09:14:22", "10:41:07", "11:03:55", "14:20:31", "15:47:12"]
NIGHT = ["01:22:08", "02:51:40", "03:12:19", "04:05:33"]
PER_RULE = 7          # 12 families x 2 rules x 7 = 168 alerts


def ext(r):
    return f"{r.choice(['203.0.113', '198.51.100'])}.{r.randint(2, 250)}"


def internal(r):
    return f"10.0.{r.randint(1, 5)}.{r.randint(10, 240)}"


def encoded(text):
    """PowerShell-style encoding (UTF-16LE base64) of a harmless string."""
    return base64.b64encode(text.encode("utf-16-le")).decode()


# Each family function gets (rng, is_attack) and returns
# (data fields, log line without timestamp, technique if attack, why).
def ssh_fail(r, attack):
    if attack:
        ip, user = ext(r), r.choice(["root", "admin", "oracle", "test", "ubuntu"])
        return ({"srcip": ip, "srcuser": user},
                f"sshd[{r.randint(900, 9000)}]: Failed password for invalid user {user} from {ip} port "
                f"{r.randint(30000, 60000)} ssh2", "T1110", "external host guessing common account names")
    ip, user = internal(r), r.choice(STAFF)
    return ({"srcip": ip, "srcuser": user},
            f"sshd[{r.randint(900, 9000)}]: Failed password for {user} from {ip} port "
            f"{r.randint(30000, 60000)} ssh2", None, "single mistyped password by a staff user, internal host")


def ssh_many(r, attack):
    n = r.randint(20, 90)
    if attack:
        ip = ext(r)
        return ({"srcip": ip, "srcuser": "root"},
                f"sshd: {n} authentication failures for root from {ip} in 120 seconds",
                "T1110", "many root failures from the internet")
    ip = internal(r)
    user = r.choice(["svc-backup", "svc-monitor", "svc-deploy"])
    return ({"srcip": ip, "srcuser": user},
            f"sshd: {n} authentication failures for {user} from {ip} in 3600 seconds; key expired, "
            "job retries every minute", None, "service account with an expired key retrying on schedule")


def login_after_fail(r, attack):
    if attack:
        ip, user = ext(r), r.choice(["root", "admin", r.choice(STAFF)])
        return ({"srcip": ip, "srcuser": user},
                f"sshd: Accepted password for {user} from {ip}; {r.randint(40, 200)} failures from same source "
                "in previous 10 minutes", "T1110", "login succeeded after a burst of failures from outside")
    ip, user = internal(r), r.choice(STAFF)
    return ({"srcip": ip, "srcuser": user},
            f"sshd: Accepted password for {user} from {ip}; {r.randint(1, 2)} failure from same source "
            "in previous 10 minutes", None, "user mistyped once, then logged in from an internal host")


def powershell(r, attack):
    if attack:
        blob = encoded(f"Write-Output stage{r.randint(1, 99)}")
        parent, user = r.choice(["winword.exe", "excel.exe", "outlook.exe"]), r.choice(STAFF)
        cmd = f"powershell.exe -nop -w hidden -enc {blob}"
        why = "hidden encoded PowerShell started by an Office program"
    else:
        blob = encoded(f"Get-Service agent{r.randint(1, 99)}")
        parent, user = r.choice(["ccmexec.exe", "IntuneManagementExtension.exe"]), "SYSTEM"
        cmd = f"powershell.exe -NonInteractive -enc {blob}"
        why = "management agent running its encoded inventory script"
    return ({"srcuser": user, "command": cmd, "parent": parent},
            f"Process create: user={user} parent={parent} command={cmd}",
            "T1059.001" if attack else None, why)


def web_scan(r, attack):
    if attack:
        ip = ext(r)
        url = r.choice(["/../../../../etc/passwd", "/.git/config", "/phpmyadmin/index.php", "/wp-login.php.bak"])
        agent = r.choice(["sqlmap/1.7", "Nikto/2.5.0", "gobuster/3.6", "python-requests/2.31"])
        status, why = r.choice([403, 404]), "external client probing sensitive paths with a scanning tool"
    else:
        ip = internal(r)
        url = r.choice(["/favicon.ico", "/old/report.pdf", "/img/logo-2019.png", "/status"])
        agent = r.choice(["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "UptimeMonitor/2.1"])
        status, why = 404, "broken link or uptime check from an internal client"
    return ({"srcip": ip, "url": url, "user_agent": agent, "id": str(status)},
            f'{ip} - - "GET {url} HTTP/1.1" {status} {r.randint(150, 900)} "-" "{agent}"',
            "T1595" if attack else None, why)


def sudo_cmd(r, attack):
    if attack:
        user, cmd = r.choice(["www-data", "nobody", "postgres"]), r.choice(["/bin/bash", "/usr/bin/vi /etc/shadow"])
        why = "service account obtaining a root shell or reading credentials"
    else:
        user = r.choice(STAFF)
        cmd = r.choice(["/usr/bin/systemctl restart nginx", "/usr/bin/apt update", "/usr/bin/journalctl -u ssh"])
        why = "administrator doing routine maintenance"
    return ({"srcuser": user, "dstuser": "root", "command": cmd},
            f"sudo: {user} : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND={cmd}",
            "T1548.003" if attack else None, why)


def package(r, attack):
    if attack:
        pkg, user = r.choice(["nmap", "netcat-traditional", "hydra"]), "www-data"
        log, why = f"dpkg: status installed {pkg} requested by {user} from /tmp/.cache", "web account installing attack tools"
    else:
        pkg, user = r.choice(["openssl", "curl", "tzdata", "nginx"]), "root"
        log, why = f"dpkg: status installed {pkg} requested by unattended-upgrades", "automatic security update"
    return ({"srcuser": user, "command": f"install {pkg}"}, log, "T1588.002" if attack else None, why)


def scheduled(r, attack):
    if attack:
        user = r.choice(["www-data", "postgres"])
        cmd = r.choice(["/tmp/.x/update.sh", "/dev/shm/.k/run", "/var/tmp/.s/sync.sh"])
        why = "service account scheduling a hidden script in a temporary folder"
    else:
        user = "root"
        cmd = r.choice(["/usr/sbin/logrotate /etc/logrotate.conf", "/opt/backup/nightly.sh", "/usr/bin/certbot renew"])
        why = "routine system job"
    return ({"srcuser": user, "command": cmd}, f"crond: ({user}) REPLACE (*/5 * * * * {cmd})",
            "T1053.003" if attack else None, why)


def win_logon_fail(r, attack):
    ip = internal(r)
    if attack:
        n = r.randint(25, 60)
        return ({"srcip": ip, "srcuser": r.choice(STAFF)},
                f"Windows logon failure 4625: source {ip} failed once each for {n} different accounts in 5 minutes",
                "T1110.003", "one internal host trying one password on many accounts")
    user = r.choice(STAFF)
    return ({"srcip": ip, "srcuser": user},
            f"Windows logon failure 4625: source {ip} failed {r.randint(3, 8)} times for {user}; password changed "
            "40 minutes earlier, saved credential on workstation", None, "stale saved password after a change")


def new_account(r, attack):
    if attack:
        by, new = r.choice(["www-data", "IUSR"]), r.choice(["support$", "sysupd", "helpdesk1"])
        why = "web service account creating an administrator"
        log = f"account created: name={new} by={by} groups=administrators"
    else:
        by, new = "svc-hr-onboarding", r.choice(STAFF)
        why = "onboarding automation creating a normal user"
        log = f"account created: name={new} by={by} groups=staff ticket=HR-{r.randint(1000, 9999)}"
    return ({"srcuser": by, "dstuser": new}, log, "T1136" if attack else None, why)


def file_change(r, attack):
    if attack:
        path, user = f"/var/www/html/uploads/{r.choice(['img', 'up', 'x'])}{r.randint(1, 99)}.php", "www-data"
        why = "script file written to the web upload folder by the web server"
    else:
        path, user = r.choice(["/etc/ld.so.cache", "/etc/nginx/nginx.conf", "/usr/lib/ssl/cert.pem"]), "root"
        why = "configuration file updated by the package manager"
    by = "apache2" if attack else "dpkg"
    return ({"srcuser": user, "path": path}, f"File '{path}' modified by {user} process={by}",
            "T1505.003" if attack else None, why)


def web_param(r, attack):
    if attack:
        ip, agent = ext(r), "curl/8.4.0"
        url = r.choice(["/img/up7.php?cmd=whoami", "/up/x.php?c=id", "/s.php?exec=uname+-a"])
        why = "system command passed to a script in the URL, answered with 200"
    else:
        ip, agent = internal(r), "Mozilla/5.0 (X11; Linux x86_64)"
        url = r.choice(["/docs/search?q=cmd+shortcuts", "/wiki?title=exec+summary", "/kb?find=whoami+manual"])
        why = "documentation search that contains a command-like word"
    return ({"srcip": ip, "url": url, "user_agent": agent, "id": "200"},
            f'{ip} - - "GET {url} HTTP/1.1" 200 {r.randint(150, 900)} "-" "{agent}"',
            "T1505.003" if attack else None, why)


# (function, decoder, log file, [(level, description), (level, description)])
FAMILIES = [
    (ssh_fail, "sshd", "/var/log/auth.log", [(5, "SSH authentication failed"), (3, "SSH login rejected")]),
    (ssh_many, "sshd", "/var/log/auth.log", [(10, "Multiple SSH authentication failures"), (12, "Possible SSH brute force")]),
    (login_after_fail, "sshd", "/var/log/auth.log", [(3, "SSH login success"), (4, "Login success after earlier failure")]),
    (powershell, "windows_eventchannel", "EventChannel", [(12, "Encoded PowerShell command"), (9, "PowerShell with unusual flags")]),
    (web_scan, "web-accesslog", "/var/log/nginx/access.log", [(5, "Web server 400 error code"), (6, "Request for missing resource")]),
    (sudo_cmd, "sudo", "/var/log/auth.log", [(3, "Sudo to root executed"), (4, "Privileged command executed")]),
    (package, "dpkg-decoder", "/var/log/dpkg.log", [(7, "New package installed"), (4, "Package state changed")]),
    (scheduled, "crond", "/var/log/cron", [(5, "Crontab changed"), (8, "New scheduled job")]),
    (win_logon_fail, "windows_eventchannel", "EventChannel", [(5, "Windows logon failure"), (10, "Multiple Windows logon failures")]),
    (new_account, "account-log", "/var/log/accounts.log", [(8, "New user account created"), (5, "Account database changed")]),
    (file_change, "syscheck", "syscheck", [(7, "Integrity checksum changed"), (4, "Monitored file modified")]),
    (web_param, "web-accesslog", "/var/log/nginx/access.log", [(6, "Suspicious URL parameter"), (3, "Web request logged")]),
]


def generate(seed: int) -> list[dict]:
    rng, rows = random.Random(seed), []
    for fam_no, (make, decoder, location, rules) in enumerate(FAMILIES, 1):
        for rule_no, (level, description) in enumerate(rules, 1):
            for i in range(PER_RULE):
                attack = (i + rule_no) % 2 == 0          # 3 or 4 attacks out of 7
                data, log, technique, why = make(rng, attack)
                # Time of day is random for BOTH labels, so it is not a shortcut.
                clock = rng.choice(DAY + NIGHT)
                date = f"2026-03-{rng.randint(1, 28):02d}"
                host = rng.choice(HOSTS)
                hard = (level >= 8) if not attack else (level <= 4)
                alert = Alert(
                    id=f"s{len(rows) + 1:04d}", provenance="synthetic", label="tp" if attack else "fp",
                    technique=technique, label_note=why + (" [hard]" if hard else ""),
                    wazuh={
                        "timestamp": f"{date}T{clock}.000+0000",
                        "rule": {"id": str(900000 + fam_no * 10 + rule_no), "level": level,
                                 "description": description, "groups": [decoder], "mitre": {}},
                        "agent": {"id": f"{HOSTS.index(host) + 1:03d}", "name": host},
                        "manager": {"name": "wazuh-lab"}, "decoder": {"name": decoder},
                        "location": location, "data": data,
                        "full_log": f"{date}T{clock} {host} {log}",
                    })
                rows.append(alert.model_dump())
    return rows


if __name__ == "__main__":
    rows = generate(load_config()["seed"])
    write_jsonl(ROOT / "data/parts/synthetic.jsonl", rows)
    print(len(rows), "synthetic alerts;", sum(r["label"] == "tp" for r in rows), "tp")
