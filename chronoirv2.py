#!/usr/bin/env python3
"""
ChronoIR AuthLog Analyzer v0.4.1

Default:
  python3 chronoir.py /var/log

v0.4.1 fixes/additions:
- useradd parser now supports auth.log lines with or without trailing `, from=...`
- parse groupadd, userdel, chfn account-management events
- add deleted_users.csv, groups_created.csv, user_info_changed.csv, account_lifecycle.csv
- keeps v0.4 DFIR outputs: failed/success SSH pivots, success-after-failed, created_users, MITRE mapping, VT optional enrichment
"""
from __future__ import annotations

import argparse, csv, gzip, ipaddress, json, re, sys, time, urllib.error, urllib.request
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

DEFAULT_CASE_DIR = "Output_Analyzer"
DEFAULT_VT_KEY_FILE = "api_key_virustotal.txt"
MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
PRIV_GROUPS = {"sudo", "wheel", "admin", "root"}
WEB_USERS = {"www-data", "apache", "nginx", "httpd"}

@dataclass
class Event:
    timestamp: str
    sort_ts: str
    host: str
    source_file: str
    event_type: str
    category: str
    severity: str = "info"
    outcome: str = "unknown"
    actor_user: Optional[str] = None
    user: Optional[str] = None
    target_user: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[str] = None
    service: Optional[str] = None
    tty: Optional[str] = None
    pwd: Optional[str] = None
    run_as: Optional[str] = None
    command: Optional[str] = None
    group: Optional[str] = None
    uid: Optional[str] = None
    gid: Optional[str] = None
    home: Optional[str] = None
    shell: Optional[str] = None
    mitre: List[Dict[str, str]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    raw: str = ""
    def json(self) -> Dict: return asdict(self)

@dataclass
class Alert:
    id: str
    name: str
    severity: str
    description: str
    entities: Dict[str, str]
    mitre: List[Dict[str, str]]
    evidence: List[str]
    def json(self) -> Dict: return asdict(self)

def mitre(tactic: str, tid: str, technique: str, confidence: str = "medium") -> Dict[str, str]:
    return {"tactic": tactic, "technique_id": tid, "technique": technique, "confidence": confidence}

def sev_rank(sev: str) -> int:
    return {"info":0,"low":1,"medium":2,"high":3,"critical":4}.get(sev,0)

def score_sev(score: int) -> str:
    return "critical" if score >= 120 else "high" if score >= 70 else "medium" if score >= 30 else "low" if score > 0 else "info"

def fmt_us(iso_ts: Optional[str]) -> str:
    if not iso_ts: return ""
    try: return datetime.fromisoformat(iso_ts).strftime("%m/%d/%Y %I:%M:%S %p")
    except Exception: return iso_ts

def discover(path: Path) -> List[Path]:
    if path.is_file(): return [path]
    files: List[Path] = []
    for pat in ["auth.log", "auth.log.*", "secure", "secure-*", "secure.*"]:
        files.extend(path.glob(pat))
    return sorted({p.resolve() for p in files if p.is_file()}, key=lambda p: str(p))

def read_lines(path: Path) -> Iterator[str]:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", errors="replace") as f:
            for line in f: yield line.rstrip("\n")
    else:
        with path.open("rt", errors="replace") as f:
            for line in f: yield line.rstrip("\n")

# Prefix/process
SYSLOG = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<body>.*)$")
PROC = re.compile(r"^(?P<proc>[\w.\-/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
# SSH/auth
SSH_FAIL = re.compile(r"Failed (?P<method>\S+) for (?:(?:invalid user)\s+)?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)")
SSH_INV = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)(?: port (?P<port>\d+))?")
SSH_OK = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)")
SUDO = re.compile(r"^(?P<actor>\S+)\s+:\s+TTY=(?P<tty>[^;]+)\s+;\s+PWD=(?P<pwd>[^;]+)\s+;\s+USER=(?P<run_as>[^;]+)\s+;\s+COMMAND=(?P<cmd>.+)$")
PAM_SESSION = re.compile(r"pam_unix\((?P<svc>[^:]+):session\): session (?P<act>opened|closed) for user (?P<user>\S+)(?: by \(uid=(?P<uid>\d+)\))?")
SU_TO = re.compile(r"^\(to (?P<target>\S+)\) (?P<actor>\S+) on (?P<tty>\S+)")
AUTH_FAIL = re.compile(r"pam_unix\((?P<svc>[^:]+):auth\): authentication failure;.*?(?:ruser=(?P<ruser>\S*))?.*?(?:rhost=(?P<rhost>\S*))?.*?user=(?P<user>\S+)")
# Account management v0.4.1
GROUP_CREATED = re.compile(r"new group: name=(?P<group>[^,]+), GID=(?P<gid>\d+)")
USERADD_USER = re.compile(r"new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+), home=(?P<home>[^,]+), shell=(?P<shell>[^,\s]+)(?:, from=(?P<from>\S+))?")
PASSWD = re.compile(r"password changed for (?P<user>\S+)")
USERMOD_GROUP = re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")
USERDEL_USER = re.compile(r"delete user [`'](?P<user>[^`']+)[`']")
USERDEL_GROUP = re.compile(r"removed group [`'](?P<group>[^`']+)[`'] owned by [`'](?P<owner>[^`']+)[`']")
CHFN_CHANGED = re.compile(r"changed user [`'](?P<user>[^`']+)[`'] information")
IP_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")

def make_ts(mon: str, day: str, clock: str, year: int) -> Tuple[str,str]:
    dt = datetime(year, MONTHS.get(mon, 1), int(day), *map(int, clock.split(":")))
    return dt.isoformat(), dt.isoformat()

def base(prefix: Dict[str,str], source: Path, etype: str, cat: str, raw: str, year: int) -> Event:
    ts, sort = make_ts(prefix["mon"], prefix["day"], prefix["clock"], year)
    return Event(ts, sort, prefix["host"], str(source), etype, cat, raw=raw)

def classify_sudo(cmd: str) -> Tuple[str,str,List[Dict[str,str]],List[str]]:
    lc = cmd.lower(); et = "sudo_command"; sev = "info"; notes: List[str] = []
    tags = [mitre("Privilege Escalation", "T1548", "Abuse Elevation Control Mechanism")]
    if re.search(r"\b(useradd|adduser|newusers)\b", lc):
        et="sudo_account_create_command"; sev="high"; tags.append(mitre("Persistence","T1136.001","Create Account: Local Account","high"))
    elif re.search(r"\b(passwd|chpasswd)\b", lc):
        et="sudo_password_change_command"; sev="high"; tags.append(mitre("Persistence","T1098","Account Manipulation"))
    elif re.search(r"\b(usermod|gpasswd|groupadd|groupmod|addgroup)\b", lc):
        et="sudo_account_modify_command"; sev="high"; tags.append(mitre("Persistence","T1098","Account Manipulation","high"))
    elif re.search(r"\b(userdel|deluser)\b", lc):
        et="sudo_account_delete_command"; sev="medium"; tags.append(mitre("Persistence","T1098","Account Manipulation"))
    if "authorized_keys" in lc:
        et="ssh_authorized_keys_command"; sev="high"; notes.append("Command references authorized_keys"); tags.append(mitre("Persistence","T1098.004","Account Manipulation: SSH Authorized Keys"))
    if "/etc/ssh/sshd_config" in lc or "permitrootlogin" in lc or "pubkeyauthentication" in lc:
        et="ssh_config_modified_command"; sev="high"; notes.append("Command references SSH daemon config"); tags.append(mitre("Persistence","T1098.004","Account Manipulation: SSH Authorized Keys"))
    if re.search(r"\b(systemctl|service)\b", lc):
        if sev == "info": sev="medium"
        notes.append("systemctl/service command via sudo")
    if re.search(r"\b(websockify|vncserver|x11vnc|ngrok|socat|nc\b|ncat\b)\b", lc):
        et="remote_access_related_command"; sev="medium" if sev in {"info","low"} else sev; notes.append("Remote access/tunneling related command")
    if re.search(r"\b(vim|vi|nano|tee|sed)\b", lc) and "/etc/" in lc:
        if sev == "info": sev="medium"
        notes.append("Command edits/writes /etc")
    return et, sev, tags, notes

def parse_line(line: str, source: Path, year: int) -> Optional[Event]:
    m = SYSLOG.match(line)
    if not m: return None
    prefix = m.groupdict(); body = prefix.pop("body")
    pm = PROC.match(body)
    if not pm: return None
    proc, pid, msg = pm.group("proc"), pm.group("pid"), pm.group("msg")

    if proc == "sshd":
        if mm := SSH_INV.search(msg):
            e=base(prefix,source,"ssh_invalid_user","authentication",line,year); e.process=proc; e.pid=pid; e.service="sshd"; e.user=e.target_user=mm.group("user"); e.src_ip=mm.group("ip"); e.src_port=mm.groupdict().get("port"); e.outcome="failure"; e.severity="medium"; e.mitre=[mitre("Credential Access","T1110","Brute Force")]; return e
        if mm := SSH_FAIL.search(msg):
            e=base(prefix,source,"ssh_login_failed","authentication",line,year); e.process=proc; e.pid=pid; e.service="sshd"; e.user=e.target_user=mm.group("user"); e.src_ip=mm.group("ip"); e.src_port=mm.group("port"); e.outcome="failure"; e.severity="medium" if e.user=="root" else "low"; e.mitre=[mitre("Credential Access","T1110.001","Brute Force: Password Guessing")]; return e
        if mm := SSH_OK.search(msg):
            et = "ssh_login_success_publickey" if mm.group("method").lower()=="publickey" else "ssh_login_success_password"
            e=base(prefix,source,et,"authentication",line,year); e.process=proc; e.pid=pid; e.service="sshd"; e.user=e.actor_user=mm.group("user"); e.src_ip=mm.group("ip"); e.src_port=mm.group("port"); e.outcome="success"; e.severity="medium"; e.mitre=[mitre("Initial Access","T1021.004","Remote Services: SSH"), mitre("Initial Access","T1078","Valid Accounts")]; return e

    if proc == "sudo" and (mm := SUDO.match(msg)):
        et, sev, tags, notes = classify_sudo(mm.group("cmd"))
        e=base(prefix,source,et,"privilege_activity",line,year); e.process=proc; e.pid=pid; e.service="sudo"; e.actor_user=e.user=mm.group("actor"); e.tty=mm.group("tty").strip(); e.pwd=mm.group("pwd").strip(); e.run_as=e.target_user=mm.group("run_as").strip(); e.command=mm.group("cmd"); e.outcome="success"; e.severity=sev; e.mitre=tags; e.notes=notes
        if e.tty == "unknown": e.notes.append("TTY=unknown; possible non-interactive automation")
        return e

    if mm := PAM_SESSION.search(msg):
        e=base(prefix,source,f"session_{mm.group('act')}","session",line,year); e.process=proc; e.pid=pid; e.service=mm.group("svc"); e.user=e.target_user=mm.group("user"); e.uid=mm.groupdict().get("uid"); e.outcome="success"; return e

    if proc == "su" and (mm := SU_TO.match(msg)):
        e=base(prefix,source,"su_to_user","privilege_activity",line,year); e.process=proc; e.pid=pid; e.service="su"; e.actor_user=e.user=mm.group("actor"); e.target_user=mm.group("target"); e.tty=mm.group("tty"); e.outcome="success"; e.severity="medium" if e.target_user=="root" else "low"; e.mitre=[mitre("Privilege Escalation","T1548","Abuse Elevation Control Mechanism")]; return e

    if mm := AUTH_FAIL.search(msg):
        e=base(prefix,source,"pam_auth_failure","authentication",line,year); e.process=proc; e.pid=pid; e.service=mm.group("svc"); e.actor_user=mm.groupdict().get("ruser") or None; e.user=e.actor_user or mm.group("user"); e.target_user=mm.group("user"); e.src_ip=mm.groupdict().get("rhost") or None; e.outcome="failure"; e.severity="medium"
        if e.service and e.service.startswith("su"):
            e.event_type="su_auth_failure"; e.mitre=[mitre("Privilege Escalation","T1548","Abuse Elevation Control Mechanism")]
            if e.actor_user in WEB_USERS and e.target_user == "root": e.severity="high"; e.notes.append("Web service user attempted su to root")
        return e

    # v0.4.1 account management support
    if proc in {"useradd", "groupadd"} and (mm := GROUP_CREATED.search(msg)):
        e=base(prefix,source,"group_created","account_management",line,year); e.process=proc; e.pid=pid; e.group=mm.group("group"); e.gid=mm.group("gid"); e.outcome="success"; e.severity="medium"; e.mitre=[mitre("Persistence","T1098","Account Manipulation")]; return e

    if proc == "useradd" and (mm := USERADD_USER.search(msg)):
        e=base(prefix,source,"account_created","account_management",line,year); e.process=proc; e.pid=pid; e.user=e.target_user=mm.group("user"); e.uid=mm.group("uid"); e.gid=mm.group("gid"); e.home=mm.group("home"); e.shell=mm.group("shell"); e.outcome="success"; e.severity="high"; e.mitre=[mitre("Persistence","T1136.001","Create Account: Local Account","high")]; return e

    if proc == "passwd" and (mm := PASSWD.search(msg)):
        e=base(prefix,source,"password_changed","account_management",line,year); e.process=proc; e.pid=pid; e.user=e.target_user=mm.group("user"); e.outcome="success"; e.severity="high"; e.mitre=[mitre("Persistence","T1098","Account Manipulation")]; return e

    if proc == "usermod" and (mm := USERMOD_GROUP.search(msg)):
        group=mm.group("group"); e=base(prefix,source,"user_added_to_group","account_management",line,year); e.process=proc; e.pid=pid; e.user=e.target_user=mm.group("user"); e.group=group; e.outcome="success"; e.severity="critical" if group in PRIV_GROUPS else "high"; e.mitre=[mitre("Persistence","T1098","Account Manipulation","high")]; return e

    if proc == "userdel":
        if mm := USERDEL_USER.search(msg):
            e=base(prefix,source,"account_deleted","account_management",line,year); e.process=proc; e.pid=pid; e.user=e.target_user=mm.group("user"); e.outcome="success"; e.severity="medium"; e.mitre=[mitre("Persistence","T1098","Account Manipulation")]; return e
        if mm := USERDEL_GROUP.search(msg):
            e=base(prefix,source,"group_deleted","account_management",line,year); e.process=proc; e.pid=pid; e.group=mm.group("group"); e.user=mm.group("owner"); e.outcome="success"; e.severity="medium"; e.mitre=[mitre("Persistence","T1098","Account Manipulation")]; return e

    if proc == "chfn" and (mm := CHFN_CHANGED.search(msg)):
        e=base(prefix,source,"user_info_changed","account_management",line,year); e.process=proc; e.pid=pid; e.user=e.target_user=mm.group("user"); e.outcome="success"; e.severity="low"; e.mitre=[mitre("Persistence","T1098","Account Manipulation","low")]; return e

    return None

def parse_files(files: List[Path], year: int) -> List[Event]:
    events: List[Event] = []
    for f in files:
        print(f"[*] Parsing {f}", file=sys.stderr)
        try:
            for line in read_lines(f):
                ev = parse_line(line, f, year)
                if ev: events.append(ev)
        except Exception as ex:
            print(f"[!] Failed reading {f}: {ex}", file=sys.stderr)
    return sorted(events, key=lambda e: e.sort_ts)

def detect(events: List[Event]) -> List[Alert]:
    alerts: List[Alert] = []
    byip = defaultdict(list)
    for e in events:
        if e.src_ip: byip[e.src_ip].append(e)

    for ip, evs in byip.items():
        fails=[e for e in evs if e.event_type in {"ssh_login_failed","ssh_invalid_user"}]
        if len(fails) >= 20:
            users=sorted({e.user or e.target_user or "UNKNOWN" for e in fails})
            tid, tech = ("T1110.003", "Brute Force: Password Spraying") if len(users) >= 5 else ("T1110.001", "Brute Force: Password Guessing")
            alerts.append(Alert("AUTH-BRUTEFORCE-IP","SSH brute force/password attack from single IP","critical" if len(fails)>=100 else "high",f"{len(fails)} failed SSH auth events from {ip} targeting {len(users)} user(s).",{"src_ip":ip,"users":",".join(users[:20])},[mitre("Credential Access",tid,tech,"high")],[x.raw for x in fails[:10]]))
        root=[e for e in fails if (e.user or e.target_user)=="root"]
        if len(root) >= 5:
            alerts.append(Alert("AUTH-ROOT-TARGETING","Repeated SSH attempts against root","high",f"{len(root)} failed attempts against root from {ip}.",{"src_ip":ip,"target_user":"root"},[mitre("Credential Access","T1110.001","Brute Force: Password Guessing","high")],[x.raw for x in root[:10]]))

    pair=defaultdict(list)
    for e in events:
        if e.event_type in {"ssh_login_failed","ssh_invalid_user"} and e.src_ip and (e.user or e.target_user): pair[(e.src_ip,e.user or e.target_user)].append(e)
    alerted=set()
    for e in events:
        if e.event_type.startswith("ssh_login_success") and e.src_ip and e.user and len(pair[(e.src_ip,e.user)]) >= 10:
            pk=(e.src_ip,e.user)
            if pk in alerted: continue
            alerted.add(pk)
            fs=pair[pk]
            succ=[x for x in events if x.event_type.startswith("ssh_login_success") and x.src_ip==e.src_ip and x.user==e.user]
            alerts.append(Alert("AUTH-SUCCESS-AFTER-BRUTEFORCE","SSH success after repeated failures","critical",f"Successful SSH login for {e.user} from {e.src_ip} after {len(fs)} previous failures. Total successful logins for this pair: {len(succ)}.",{"src_ip":e.src_ip,"user":e.user,"success_count":str(len(succ))},[mitre("Credential Access","T1110.001","Brute Force: Password Guessing","high"),mitre("Initial Access","T1021.004","Remote Services: SSH","high"),mitre("Initial Access","T1078","Valid Accounts","high")],[x.raw for x in fs[:5]]+[x.raw for x in succ[:5]]))

    for e in events:
        if e.event_type == "su_auth_failure" and e.actor_user in WEB_USERS and e.target_user == "root":
            alerts.append(Alert("AUTH-WEBUSER-SU-ROOT","Web service user attempted su to root","high",f"{e.actor_user} attempted su authentication to root.",{"actor_user":e.actor_user or "","target_user":"root"},[mitre("Privilege Escalation","T1548","Abuse Elevation Control Mechanism")],[e.raw]))
        if e.event_type in {"ssh_authorized_keys_command","ssh_config_modified_command"}:
            alerts.append(Alert("AUTH-SSH-KEY-PERSISTENCE-INDICATOR","Possible SSH key/config persistence command","high","sudo command references authorized_keys or sshd_config.",{"actor_user":e.actor_user or "","command":e.command or ""},[mitre("Persistence","T1098.004","Account Manipulation: SSH Authorized Keys")],[e.raw]))

    created=defaultdict(list); pwd=defaultdict(list); priv=defaultdict(list); deleted=defaultdict(list)
    for e in events:
        if e.event_type == "account_created" and e.user: created[e.user].append(e)
        if e.event_type == "password_changed" and e.user: pwd[e.user].append(e)
        if e.event_type == "user_added_to_group" and e.user and e.group in PRIV_GROUPS: priv[e.user].append(e)
        if e.event_type == "account_deleted" and e.user: deleted[e.user].append(e)
    for u, cs in created.items():
        evidence=[x.raw for x in cs + pwd.get(u,[]) + priv.get(u,[]) + deleted.get(u,[])]
        if priv.get(u):
            alerts.append(Alert("AUTH-NEW-PRIV-ACCOUNT","New local account granted privileged group","critical",f"User {u} was created and added to privileged group(s).",{"user":u,"groups":",".join(sorted({x.group or "" for x in priv[u]}))},[mitre("Persistence","T1136.001","Create Account: Local Account","high"),mitre("Persistence","T1098","Account Manipulation","high")],evidence[:20]))
        else:
            sev = "medium" if deleted.get(u) else "high"
            desc = f"Local user account {u} was created" + (" and later deleted." if deleted.get(u) else ".")
            alerts.append(Alert("AUTH-LOCAL-ACCOUNT-CREATED","Local account created",sev,desc,{"user":u},[mitre("Persistence","T1136.001","Create Account: Local Account","high")],evidence[:10]))
    return alerts

def is_public_ip(ip: str) -> bool:
    try: return ipaddress.ip_address(ip).is_global
    except Exception: return False

def extract_ips(events: List[Event]) -> List[str]:
    ips=[]
    for e in events:
        if e.src_ip: ips.append(e.src_ip)
        ips.extend(IP_RE.findall(e.raw or ""))
    good=[]
    for ip in ips:
        try: ipaddress.ip_address(ip); good.append(ip)
        except ValueError: pass
    return sorted(set(good))

def split_ips(ips: Iterable[str]) -> Tuple[List[str],List[str]]:
    pub=[]; priv=[]
    for ip in sorted(set(ips)):
        try: obj=ipaddress.ip_address(ip)
        except ValueError: continue
        (pub if obj.is_global else priv).append(ip)
    return pub, priv

def first_ts(evs: List[Event]) -> str: return min((e.timestamp for e in evs), default="")
def last_ts(evs: List[Event]) -> str: return max((e.timestamp for e in evs), default="")
def users_join(evs: List[Event]) -> str: return ",".join(sorted({e.user or e.target_user or "UNKNOWN" for e in evs}))

def build_indicator_tables(events: List[Event]) -> Dict[str,List[Dict[str,object]]]:
    failed=[e for e in events if e.event_type == "ssh_login_failed"]
    success=[e for e in events if e.event_type.startswith("ssh_login_success")]
    created=[e for e in events if e.event_type == "account_created"]
    deleted=[e for e in events if e.event_type == "account_deleted"]
    group_created=[e for e in events if e.event_type == "group_created"]
    group_deleted=[e for e in events if e.event_type == "group_deleted"]
    user_info=[e for e in events if e.event_type == "user_info_changed"]
    passwd=[e for e in events if e.event_type == "password_changed"]
    privileged=[e for e in events if e.event_type == "user_added_to_group" and e.group in PRIV_GROUPS]

    by_user=defaultdict(list); success_by_user=defaultdict(list); failed_by_pair=defaultdict(list); success_by_pair=defaultdict(list); failed_by_ip=defaultdict(list); success_by_ip=defaultdict(list)
    for e in failed:
        user=e.user or e.target_user or "UNKNOWN"; by_user[user].append(e)
        if e.src_ip: failed_by_pair[(e.src_ip,user)].append(e); failed_by_ip[e.src_ip].append(e)
    for e in success:
        user=e.user or "UNKNOWN"; success_by_user[user].append(e)
        if e.src_ip: success_by_pair[(e.src_ip,user)].append(e); success_by_ip[e.src_ip].append(e)

    rows_failed_user=[]
    for user, evs in by_user.items():
        ips=sorted({e.src_ip for e in evs if e.src_ip}); succ=success_by_user.get(user,[])
        risk="critical" if succ and len(evs)>=10 else "high" if len(evs)>=20 or user=="root" else "medium" if len(evs)>=5 else "low"
        rows_failed_user.append({"user":user,"failed_count":len(evs),"unique_source_ips":len(ips),"source_ips":",".join(ips),"first_failed":first_ts(evs),"last_failed":last_ts(evs),"successful_login_count":len(succ),"first_success":first_ts(succ),"last_success":last_ts(succ),"last_success_us_format":fmt_us(last_ts(succ)),"root_targeted":"yes" if user=="root" else "no","risk":risk.upper()})
    rows_failed_user.sort(key=lambda r:int(r["failed_count"]), reverse=True)

    rows_failed_ip_user=[]
    for (ip,user), evs in failed_by_pair.items():
        succ=success_by_pair.get((ip,user),[])
        rows_failed_ip_user.append({"src_ip":ip,"is_public_ip":"yes" if is_public_ip(ip) else "no","user":user,"failed_count":len(evs),"success_count":len(succ),"first_failed":first_ts(evs),"last_failed":last_ts(evs),"first_success":first_ts(succ),"last_success":last_ts(succ),"last_success_us_format":fmt_us(last_ts(succ))})
    rows_failed_ip_user.sort(key=lambda r:int(r["failed_count"]), reverse=True)

    rows_success_ip=[]
    for ip, evs in success_by_ip.items():
        fails=failed_by_ip.get(ip,[]); first_success=first_ts(evs); failed_before=[f for f in fails if f.timestamp < first_success] if first_success else []
        rows_success_ip.append({"src_ip":ip,"is_public_ip":"yes" if is_public_ip(ip) else "no","success_count":len(evs),"failed_count_total":len(fails),"failed_before_first_success":len(failed_before),"users_success":users_join(evs),"users_failed":users_join(fails),"first_success":first_success,"last_success":last_ts(evs),"last_success_us_format":fmt_us(last_ts(evs)),"first_failed":first_ts(fails),"last_failed":last_ts(fails)})
    rows_success_ip.sort(key=lambda r:int(r["success_count"]), reverse=True)

    rows_success_user=[]
    for user, evs in success_by_user.items():
        fails=by_user.get(user,[])
        rows_success_user.append({"user":user,"success_count":len(evs),"unique_source_ips":len({e.src_ip for e in evs if e.src_ip}),"source_ips":",".join(sorted({e.src_ip for e in evs if e.src_ip})),"failed_count_total":len(fails),"first_success":first_ts(evs),"last_success":last_ts(evs),"last_success_us_format":fmt_us(last_ts(evs)),"first_failed":first_ts(fails),"last_failed":last_ts(fails)})
    rows_success_user.sort(key=lambda r:int(r["success_count"]), reverse=True)

    rows_success_after_failed_ip=[]
    for ip, succ in success_by_ip.items():
        fails=failed_by_ip.get(ip,[])
        if not succ or not fails: continue
        fs=first_ts(succ); failed_before=[f for f in fails if f.timestamp < fs]
        if failed_before:
            rows_success_after_failed_ip.append({"src_ip":ip,"is_public_ip":"yes" if is_public_ip(ip) else "no","failed_before_first_success":len(failed_before),"failed_count_total":len(fails),"success_count":len(succ),"users_failed":users_join(fails),"users_success":users_join(succ),"first_failed":first_ts(fails),"first_success":fs,"last_success":last_ts(succ),"last_success_us_format":fmt_us(last_ts(succ))})
    rows_success_after_failed_ip.sort(key=lambda r:(r["is_public_ip"]!="yes",-int(r["success_count"]),-int(r["failed_before_first_success"])))

    rows_success_after_failed_pair=[]
    for (ip,user), succ in success_by_pair.items():
        fails=failed_by_pair.get((ip,user),[])
        if not succ or not fails: continue
        fs=first_ts(succ); failed_before=[f for f in fails if f.timestamp < fs]
        if failed_before:
            rows_success_after_failed_pair.append({"src_ip":ip,"is_public_ip":"yes" if is_public_ip(ip) else "no","user":user,"failed_before_first_success":len(failed_before),"failed_count_total":len(fails),"success_count":len(succ),"first_failed":first_ts(fails),"first_success":fs,"last_success":last_ts(succ),"last_success_us_format":fmt_us(last_ts(succ))})
    rows_success_after_failed_pair.sort(key=lambda r:(r["is_public_ip"]!="yes",-int(r["success_count"]),-int(r["failed_before_first_success"])))

    rows_created=[{"timestamp":e.timestamp,"timestamp_us_format":fmt_us(e.timestamp),"user":e.user or "","uid":e.uid or "","gid":e.gid or "","home":e.home or "","shell":e.shell or "","host":e.host,"source_file":e.source_file,"raw":e.raw} for e in created]
    rows_created.sort(key=lambda r:r["timestamp"])
    rows_deleted=[{"timestamp":e.timestamp,"timestamp_us_format":fmt_us(e.timestamp),"user":e.user or "","host":e.host,"source_file":e.source_file,"raw":e.raw} for e in deleted]
    rows_deleted.sort(key=lambda r:r["timestamp"])
    rows_groups_created=[{"timestamp":e.timestamp,"timestamp_us_format":fmt_us(e.timestamp),"group":e.group or "","gid":e.gid or "","process":e.process or "","host":e.host,"source_file":e.source_file,"raw":e.raw} for e in group_created]
    rows_groups_created.sort(key=lambda r:r["timestamp"])
    rows_priv=[{"timestamp":e.timestamp,"timestamp_us_format":fmt_us(e.timestamp),"user":e.user or "","group":e.group or "","host":e.host,"source_file":e.source_file,"raw":e.raw} for e in privileged]
    rows_priv.sort(key=lambda r:r["timestamp"])
    rows_user_info=[{"timestamp":e.timestamp,"timestamp_us_format":fmt_us(e.timestamp),"user":e.user or "","host":e.host,"source_file":e.source_file,"raw":e.raw} for e in user_info]
    rows_user_info.sort(key=lambda r:r["timestamp"])

    # account lifecycle
    users=sorted({e.user for e in created+deleted+passwd+privileged+user_info if e.user})
    by_created=defaultdict(list); by_deleted=defaultdict(list); by_pass=defaultdict(list); by_priv=defaultdict(list); by_info=defaultdict(list)
    for e in created: by_created[e.user].append(e)
    for e in deleted: by_deleted[e.user].append(e)
    for e in passwd: by_pass[e.user].append(e)
    for e in privileged: by_priv[e.user].append(e)
    for e in user_info: by_info[e.user].append(e)
    rows_lifecycle=[]
    for u in users:
        ce=by_created.get(u,[]); de=by_deleted.get(u,[]); pe=by_pass.get(u,[]); ge=by_priv.get(u,[]); ie=by_info.get(u,[])
        first_create=ce[0] if ce else None
        shell=(first_create.shell if first_create else "") or ""; uid=(first_create.uid if first_create else "") or ""; home=(first_create.home if first_create else "") or ""
        status="deleted" if de else "active_or_unknown"
        try:
            if status != "deleted" and (shell.endswith("nologin") or shell.endswith("false") or (uid and int(uid) < 1000)):
                status="system_or_service_account"
        except Exception: pass
        rows_lifecycle.append({"user":u,"created_at":first_ts(ce),"created_at_us_format":fmt_us(first_ts(ce)),"deleted_at":first_ts(de),"deleted_at_us_format":fmt_us(first_ts(de)),"password_changed":"yes" if pe else "no","password_change_count":len(pe),"user_info_changed_count":len(ie),"privileged_groups_added":",".join(sorted({e.group or "" for e in ge if e.group})),"uid":uid,"home":home,"shell":shell,"status":status})
    rows_lifecycle.sort(key=lambda r:(r["created_at"] or r["deleted_at"], r["user"]))

    return {
        "failed_password_by_user.csv": rows_failed_user,
        "failed_password_by_ip_user.csv": rows_failed_ip_user,
        "success_login_by_ip.csv": rows_success_ip,
        "success_login_by_user.csv": rows_success_user,
        "success_after_failed_ips.csv": rows_success_after_failed_ip,
        "success_after_failed_ip_user.csv": rows_success_after_failed_pair,
        "created_users.csv": rows_created,
        "deleted_users.csv": rows_deleted,
        "groups_created.csv": rows_groups_created,
        "privileged_users_added.csv": rows_priv,
        "user_info_changed.csv": rows_user_info,
        "account_lifecycle.csv": rows_lifecycle,
    }

def vt_query(ip: str, key: str) -> Tuple[int,Dict]:
    req=urllib.request.Request(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"accept":"application/json","x-apikey":key})
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return r.getcode(), json.loads(r.read().decode("utf-8","replace"))
    except urllib.error.HTTPError as e:
        try: data=json.loads(e.read().decode("utf-8","replace"))
        except Exception: data={"error":{"message":str(e)}}
        return e.code, data
    except Exception as e: return 0, {"error":{"message":str(e)}}

def vt_norm(ip: str, status: str, code: str, data: Dict) -> Dict[str,object]:
    attrs=data.get("data",{}).get("attributes",{}) if isinstance(data,dict) else {}; stats=attrs.get("last_analysis_stats",{}) or {}; results=attrs.get("last_analysis_results",{}) or {}
    mal=int(stats.get("malicious") or 0); susp=int(stats.get("suspicious") or 0); sources=[]
    if isinstance(results,dict):
        for vendor,val in results.items():
            if isinstance(val,dict) and val.get("category") in {"malicious","suspicious"}: sources.append(vendor)
    return {"ip":ip,"country":attrs.get("country") or "UNKNOWN","organization":attrs.get("as_owner") or "UNKNOWN","malicious":mal,"suspicious":susp,"total_malicious_suspicious":mal+susp,"malicious_suspicious_sources":",".join(sources) if sources else "NONE","vt_status":status,"http_code":str(code),"error":data.get("error",{}).get("message","") if isinstance(data,dict) else ""}

def vt_enrich(public_ips: List[str], case_dir: Path, key_file: Path, sleep: int=16, cache: bool=True) -> Dict[str,Dict[str,object]]:
    key=key_file.read_text().strip(); rows={}; vt_dir=case_dir/"enrichment"/"virustotal"; vt_dir.mkdir(parents=True, exist_ok=True)
    if not key:
        print(f"[*] VirusTotal API key kosong ({key_file}); VT enrichment dilewati.", file=sys.stderr); return rows
    for ip in public_ips:
        print(f"[*] VT checking {ip}...", file=sys.stderr); cf=vt_dir/f"{ip}.json"
        if cache and cf.exists(): rows[ip]=vt_norm(ip,"CACHE","CACHE",json.loads(cf.read_text(errors="replace"))); continue
        code,data=vt_query(ip,key); status="OK" if code==200 else "RATE_LIMIT" if code==429 else "ERROR"
        (cf if code==200 else vt_dir/f"{ip}.error.json").write_text(json.dumps(data,indent=2,ensure_ascii=False), encoding="utf-8")
        rows[ip]=vt_norm(ip,status,str(code),data)
        if sleep>0: time.sleep(sleep)
    return rows

def mkdirs(case: Path) -> None:
    for d in "raw indicators ip user alerts mitre enrichment".split(): (case/d).mkdir(parents=True, exist_ok=True)

def write_list(path: Path, items: Iterable[str]) -> None:
    xs=sorted(set(items)); path.write_text("\n".join(xs)+("\n" if xs else ""), encoding="utf-8")

def write_csv(path: Path, rows: List[Dict[str,object]], fields: Optional[List[str]]=None, delimiter: str=",") -> None:
    if fields is None:
        fields=[]
        for r in rows:
            for k in r.keys():
                if k not in fields: fields.append(k)
    with path.open("w", newline="", encoding="utf-8") as f:
        w=csv.DictWriter(f, fieldnames=fields, delimiter=delimiter); w.writeheader()
        for r in rows: w.writerow({k:r.get(k,"") for k in fields})

def safe(s: str) -> str: return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:120] or "UNKNOWN"

def evline(e: Event) -> str:
    bits=[f"[{e.timestamp}]", e.event_type]
    for k in ["severity","actor_user","user","target_user","src_ip","group","command"]:
        v=getattr(e,k,None)
        if v and not (k=="severity" and v=="info"): bits.append(f"{k}={v}")
    return " | ".join(bits)

def ip_score(ip: str, events: List[Event], vt: Optional[Dict[str,object]]) -> Tuple[int,List[str]]:
    evs=[e for e in events if e.src_ip==ip]; fails=[e for e in evs if e.event_type in {"ssh_login_failed","ssh_invalid_user"}]; score=0; reasons=[]
    if len(fails)>=100: score+=40; reasons.append(f"failed SSH attempts >=100 ({len(fails)})")
    elif len(fails)>=50: score+=25; reasons.append(f"failed SSH attempts >=50 ({len(fails)})")
    elif len(fails)>=10: score+=10; reasons.append(f"failed SSH attempts >=10 ({len(fails)})")
    if any((e.user or e.target_user)=="root" for e in fails): score+=30; reasons.append("targeted root")
    if len({e.user or e.target_user for e in fails if e.user or e.target_user})>=5: score+=30; reasons.append("targeted multiple usernames")
    if any(e.event_type.startswith("ssh_login_success") for e in evs): score+=20; reasons.append("successful SSH login observed")
    if vt:
        total=int(vt.get("total_malicious_suspicious") or 0)
        if total>=6: score+=40; reasons.append(f"VT total >=6 ({total})")
        elif total>=3: score+=25; reasons.append(f"VT total >=3 ({total})")
        elif total>=1: score+=10; reasons.append(f"VT total >=1 ({total})")
    return score, reasons

def write_reports(case: Path, files: List[Path], events: List[Event], alerts: List[Alert], pub: List[str], priv: List[str], vt_rows: Dict[str,Dict[str,object]], indicators: Dict[str,List[Dict[str,object]]]) -> None:
    with (case/"raw"/"events.jsonl").open("w", encoding="utf-8") as f:
        for e in events: f.write(json.dumps(e.json(), ensure_ascii=False)+"\n")
    timeline_fields="timestamp host source_file event_type category severity outcome actor_user user target_user src_ip src_port process pid service tty pwd run_as command group uid gid home shell raw".split()
    write_csv(case/"timeline.csv", [{k:getattr(e,k,"") for k in timeline_fields} for e in events], timeline_fields)
    (case/"raw"/"source_files.txt").write_text("\n".join(map(str,files))+"\n", encoding="utf-8")
    for name, rows in indicators.items(): write_csv(case/"indicators"/name, rows, delimiter=";")

    vt_fields="ip country organization malicious suspicious total_malicious_suspicious malicious_suspicious_sources vt_status http_code error".split()
    vt_out=[{k:vt_rows[ip].get(k,"") for k in vt_fields} for ip in sorted(vt_rows)]
    for ip in priv:
        vt_out.append({"ip":ip,"country":"PRIVATE","organization":"PRIVATE","malicious":0,"suspicious":0,"total_malicious_suspicious":0,"malicious_suspicious_sources":"NONE","vt_status":"PRIVATE_SKIPPED","http_code":"SKIPPED","error":"private_or_non_global_ip"})
    write_csv(case/"indicators"/"vt_ip_enrichment.csv", vt_out, vt_fields, ";")

    # IP reports
    byip=defaultdict(list)
    for e in events:
        if e.src_ip: byip[e.src_ip].append(e)
    for ip, evs in byip.items():
        evs=sorted(evs,key=lambda e:e.sort_ts); vt=vt_rows.get(ip); score,reasons=ip_score(ip,events,vt); fails=[e for e in evs if e.event_type=="ssh_login_failed"]; ok=[e for e in evs if e.event_type.startswith("ssh_login_success")]
        users_failed=sorted({e.user or e.target_user for e in fails if e.user or e.target_user}); users_success=sorted({e.user for e in ok if e.user})
        lines=[f"IP Report: {ip}","="*(11+len(ip)),"",f"Risk: {score_sev(score).upper()} ({score})",f"First Seen: {evs[0].timestamp}",f"Last Seen : {evs[-1].timestamp}","","Successful Login Summary:",f"- Success count: {len(ok)}",f"- First success: {first_ts(ok)}",f"- Last success : {last_ts(ok)}",f"- Last success US format: {fmt_us(last_ts(ok))}",f"- Users successful: {', '.join(users_success) if users_success else 'NONE'}","","Failed Password Summary:",f"- Failed password attempts: {len(fails)}",f"- Users targeted: {', '.join(users_failed) if users_failed else 'NONE'}",f"- First failed: {first_ts(fails)}",f"- Last failed : {last_ts(fails)}","","Risk Reasons:"]
        lines += [f"- {x}" for x in (reasons or ["No major risk reason scored."])]
        lines += ["","VirusTotal Enrichment:"]
        if vt: lines += [f"- Country: {vt.get('country')}",f"- Organization: {vt.get('organization')}",f"- Malicious: {vt.get('malicious')}",f"- Suspicious: {vt.get('suspicious')}",f"- Total malicious/suspicious: {vt.get('total_malicious_suspicious')}",f"- Sources: {vt.get('malicious_suspicious_sources')}",f"- VT Status: {vt.get('vt_status')} HTTP={vt.get('http_code')}"]
        else: lines.append("- Not enriched or private/non-global IP.")
        lines += ["","Timeline:"] + [evline(e) for e in evs[:500]]
        (case/"ip"/f"{ip}.txt").write_text("\n".join(lines)+"\n", encoding="utf-8")

    # User reports
    byu=defaultdict(list)
    for e in events:
        for u in {e.user,e.actor_user,e.target_user}:
            if u: byu[u].append(e)
    for u, evs in byu.items():
        evs=sorted(evs,key=lambda e:e.sort_ts); risk=max([sev_rank(e.severity) for e in evs] or [0]); ips=sorted({e.src_ip for e in evs if e.src_ip}); fails=[e for e in evs if e.event_type=="ssh_login_failed" and (e.user or e.target_user)==u]; ok=[e for e in evs if e.event_type.startswith("ssh_login_success") and e.user==u]; failed_by_ip=Counter(e.src_ip for e in fails if e.src_ip); cnt=Counter(e.event_type for e in evs); important=[e for e in evs if sev_rank(e.severity)>=2] or evs
        lines=[f"User Report: {u}","="*(13+len(u)),"",f"Risk: {['INFO','LOW','MEDIUM','HIGH','CRITICAL'][risk]}",f"First Seen: {evs[0].timestamp}",f"Last Seen : {evs[-1].timestamp}",f"Total Events: {len(evs)}",f"Source IPs: {', '.join(ips) if ips else 'NONE'}","","Failed SSH Summary:",f"- Failed password attempts: {len(fails)}",f"- Unique failed source IPs: {len(failed_by_ip)}",f"- First failed: {first_ts(fails)}",f"- Last failed : {last_ts(fails)}","","Successful Login Summary:",f"- Success count: {len(ok)}",f"- First success: {first_ts(ok)}",f"- Last success : {last_ts(ok)}",f"- Last success US format: {fmt_us(last_ts(ok))}","","Failed Source IP Breakdown:"]
        lines += [f"- {ip}: {count}" for ip,count in failed_by_ip.most_common()] or ["- NONE"]
        lines += ["","Event Type Counts:"] + [f"- {k}: {v}" for k,v in cnt.most_common()]
        lines += ["","Important Timeline:"] + [evline(e) for e in important[:500]]
        (case/"user"/f"{safe(u)}.txt").write_text("\n".join(lines)+"\n", encoding="utf-8")

    (case/"alerts"/"alerts.json").write_text(json.dumps([a.json() for a in alerts],indent=2,ensure_ascii=False), encoding="utf-8")
    al=["Alerts","======",""]
    if not alerts: al.append("No alerts generated.")
    for a in sorted(alerts,key=lambda a:sev_rank(a.severity), reverse=True):
        al += [f"## {a.severity.upper()} - {a.name}","",f"ID: {a.id}",f"Description: {a.description}",f"Entities: {json.dumps(a.entities,ensure_ascii=False)}","MITRE:"]
        al += [f"- {m['technique_id']} {m['technique']} ({m['tactic']}, confidence={m['confidence']})" for m in a.mitre]
        al += ["Evidence:"] + [f"- {x}" for x in a.evidence[:20]] + [""]
    (case/"alerts"/"alerts.md").write_text("\n".join(al)+"\n", encoding="utf-8")

    mc=Counter()
    for e in events:
        for m in e.mitre: mc[f"{m['technique_id']} {m['technique']}"] += 1
    for a in alerts:
        for m in a.mitre: mc[f"{m['technique_id']} {m['technique']}"] += 1
    (case/"mitre"/"attack_matrix.md").write_text("MITRE ATT&CK Mapping\n====================\n\n"+"\n".join(f"- {k}: {v} evidence item(s)" for k,v in mc.most_common())+"\n", encoding="utf-8")

    es=sorted(events,key=lambda e:e.sort_ts); cnt=Counter(e.event_type for e in events); users=sorted({u for e in events for u in [e.user,e.actor_user,e.target_user] if u})
    top_failed_users=indicators.get("failed_password_by_user.csv",[])[:10]; top_success_ips=indicators.get("success_login_by_ip.csv",[])[:10]; saf=indicators.get("success_after_failed_ips.csv",[]); created=indicators.get("created_users.csv",[]); deleted=indicators.get("deleted_users.csv",[]); lifecycle=indicators.get("account_lifecycle.csv",[])
    sm=[f"Case Summary: {case.name}","="*(14+len(case.name)),"","Processed Files:"]+[f"- {x}" for x in files]+["","Time Range:"]
    sm += [f"- First event: {es[0].timestamp}", f"- Last event : {es[-1].timestamp}"] if es else ["- No parsed events."]
    sm += ["","Totals:",f"- Parsed events: {len(events)}",f"- Alerts: {len(alerts)}",f"- Users observed: {len(users)}",f"- Public IPs: {len(pub)}",f"- Private/non-global IPs: {len(priv)}",f"- IPs with success after failed attempts: {len(saf)}",f"- Created users: {len(created)}",f"- Deleted users: {len(deleted)}","","Top Event Types:"]
    sm += [f"- {k}: {v}" for k,v in cnt.most_common(20)]
    sm += ["","Top Failed Password Users:"] + ([f"- {r['user']}: {r['failed_count']} failed from {r['unique_source_ips']} IP(s), success={r['successful_login_count']}" for r in top_failed_users] or ["- NONE"])
    sm += ["","Top Successful Login IPs:"] + ([f"- {r['src_ip']}: success={r['success_count']}, failed_total={r['failed_count_total']}, last_success={r['last_success_us_format']}" for r in top_success_ips] or ["- NONE"])
    sm += ["","IPs That Failed Then Succeeded:"] + ([f"- {r['src_ip']}: failed_before_first_success={r['failed_before_first_success']}, success={r['success_count']}, users_success={r['users_success']}, last_success={r['last_success_us_format']}" for r in saf[:20]] or ["- NONE"])
    sm += ["","Created Users:"] + ([f"- {r['timestamp']} user={r['user']} uid={r['uid']} shell={r['shell']}" for r in created[:20]] or ["- NONE"])
    sm += ["","Account Lifecycle Highlights:"] + ([f"- {r['user']}: status={r['status']}, created={r['created_at']}, deleted={r['deleted_at']}, shell={r['shell']}" for r in lifecycle[:20]] or ["- NONE"])
    sm += ["","Top Alerts:"] + ([f"- {a.severity.upper()} - {a.name}: {a.description}" for a in sorted(alerts,key=lambda a:sev_rank(a.severity),reverse=True)[:20]] or ["- None"])
    if vt_rows:
        hi=[r for r in vt_rows.values() if int(r.get("total_malicious_suspicious") or 0)>0]
        sm += ["","VirusTotal High Signals:"] + ([f"- {r['ip']}: total={r['total_malicious_suspicious']} country={r['country']} org={r['organization']}" for r in sorted(hi,key=lambda r:int(r.get("total_malicious_suspicious") or 0),reverse=True)[:20]] or ["- No VT malicious/suspicious hits in enriched IPs."])
    sm += ["","Notes:","- VirusTotal enrichment auto-runs only when API key file exists.","- VirusTotal context can have false positives/false negatives.","- Account lifecycle status is inferred from auth.log events and may need validation against /etc/passwd, shadow, and filesystem artifacts."]
    (case/"summary.md").write_text("\n".join(sm)+"\n", encoding="utf-8")

def run_analyze(args: argparse.Namespace) -> None:
    inp=Path(args.input).expanduser(); case=Path(args.case).expanduser(); mkdirs(case)
    files=discover(inp)
    if not files:
        print(f"❌ No supported auth log files found in {inp}", file=sys.stderr); sys.exit(1)
    events=parse_files(files,args.year); alerts=detect(events); ips=extract_ips(events); pub,priv=split_ips(ips); indicators=build_indicator_tables(events)
    write_list(case/"indicators"/"all_ips.txt", ips); write_list(case/"indicators"/"public_ips.txt", pub); write_list(case/"indicators"/"private_ips.txt", priv)
    vt_rows={}; key=Path(args.vt_key_file).expanduser()
    if args.no_vt: print("[*] VirusTotal enrichment disabled by --no-vt", file=sys.stderr)
    elif key.exists(): vt_rows=vt_enrich(pub,case,key,args.vt_sleep,not args.no_cache)
    else:
        print(f"[*] VirusTotal API key file tidak ditemukan ({key}); VT enrichment dilewati.", file=sys.stderr)
        print(f"    Kalau mau aktifkan, buat {DEFAULT_VT_KEY_FILE} atau pakai --vt-key-file /path/key.txt", file=sys.stderr)
    write_reports(case,files,events,alerts,pub,priv,vt_rows,indicators)
    print(f"✅ Done. Case output: {case}")
    print(f"   Parsed events: {len(events)}")
    print(f"   Alerts: {len(alerts)}")
    print(f"   Public IPs: {len(pub)}")
    print(f"   Private/non-global IPs: {len(priv)}")
    print(f"   IPs failed then succeeded: {len(indicators.get('success_after_failed_ips.csv', []))}")
    print(f"   Created users: {len(indicators.get('created_users.csv', []))}")
    print(f"   Deleted users: {len(indicators.get('deleted_users.csv', []))}")

def load_events(case: Path) -> List[Event]:
    p=case/"raw"/"events.jsonl"; out=[]
    if not p.exists(): return out
    for line in p.read_text(errors="replace").splitlines(): out.append(Event(**json.loads(line)))
    return out

def load_alerts(case: Path) -> List[Alert]:
    p=case/"alerts"/"alerts.json"
    return [Alert(**x) for x in json.loads(p.read_text(errors="replace"))] if p.exists() else []

def run_enrich(args: argparse.Namespace) -> None:
    case=Path(args.case).expanduser(); pubf=case/"indicators"/"public_ips.txt"; privf=case/"indicators"/"private_ips.txt"; key=Path(args.vt_key_file).expanduser()
    if not pubf.exists(): print(f"❌ Missing {pubf}. Run analyze first.", file=sys.stderr); sys.exit(1)
    if not key.exists(): print(f"[*] VirusTotal API key file tidak ditemukan ({key}); enrichment dilewati.", file=sys.stderr); sys.exit(0)
    pub=[x.strip() for x in pubf.read_text().splitlines() if x.strip()]; priv=[x.strip() for x in privf.read_text().splitlines() if x.strip()] if privf.exists() else []
    vt_rows=vt_enrich(pub,case,key,args.vt_sleep,not args.no_cache); events=load_events(case); alerts=load_alerts(case); indicators=build_indicator_tables(events); sf=case/"raw"/"source_files.txt"; files=[Path(x) for x in sf.read_text().splitlines()] if sf.exists() else []
    write_reports(case,files,events,alerts,pub,priv,vt_rows,indicators)
    print(f"✅ VT enrichment done: {case/'indicators'/'vt_ip_enrichment.csv'}")

def main() -> None:
    known={"analyze","enrich-ip"}
    if len(sys.argv)>1 and sys.argv[1] not in known and sys.argv[1] not in {"-h","--help"}: sys.argv.insert(1,"analyze")
    ap=argparse.ArgumentParser(description="ChronoIR AuthLog Analyzer v0.4.1")
    sub=ap.add_subparsers(dest="cmd", required=True)
    a=sub.add_parser("analyze", help="Parse auth logs and generate DFIR reports")
    a.add_argument("input", help="Path file auth.log/auth.log.gz atau folder /var/log")
    a.add_argument("--case", default=DEFAULT_CASE_DIR, help=f"Output case directory (default: {DEFAULT_CASE_DIR})")
    a.add_argument("--year", type=int, default=datetime.now().year, help="Year untuk timestamp syslog/auth.log tanpa year")
    a.add_argument("--vt-key-file", default=DEFAULT_VT_KEY_FILE, help=f"File API key VirusTotal (default: {DEFAULT_VT_KEY_FILE})")
    a.add_argument("--no-vt", action="store_true", help="Disable VirusTotal enrichment")
    a.add_argument("--vt-sleep", type=int, default=16, help="Sleep seconds between VT API calls")
    a.add_argument("--no-cache", action="store_true", help="Do not use cached VT responses")
    a.set_defaults(func=run_analyze)
    e=sub.add_parser("enrich-ip", help="Run/refresh VirusTotal enrichment for existing case")
    e.add_argument("case", nargs="?", default=DEFAULT_CASE_DIR, help=f"Existing case directory (default: {DEFAULT_CASE_DIR})")
    e.add_argument("--vt-key-file", default=DEFAULT_VT_KEY_FILE, help=f"File API key VirusTotal (default: {DEFAULT_VT_KEY_FILE})")
    e.add_argument("--vt-sleep", type=int, default=16, help="Sleep seconds between VT API calls")
    e.add_argument("--no-cache", action="store_true", help="Do not use cached VT responses")
    e.set_defaults(func=run_enrich)
    args=ap.parse_args(); args.func(args)
if __name__ == "__main__": main()
