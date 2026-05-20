#!/usr/bin/env python3
"""
ChronoIR AuthLog Analyzer v0.5.6

Performance reset based on the fast v0.5.2 style, with selected lightweight improvements:
- Direct CLI help: python3 chronoir.py -h shows all options.
- Backward compatible: python3 chronoir.py analyze /var/log still works.
- Default fast mode: user_events=off, VT join=off, raw grep-like user timelines disabled.
- Host/log-host context is always preserved in timeline, summary, IP/user reports, indicators, and behavior outputs.
- hostipdb is lightweight and optional.
- VT enrichment remains a separate table by default; join VT context only with --join-vt-context.
"""
from __future__ import annotations

import argparse, csv, gzip, ipaddress, json, re, sys, time, urllib.request, urllib.error
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Iterable

VERSION = "0.5.6"
DEFAULT_CASE_DIR = "Output_Analyzer"
DEFAULT_VT_KEY_FILE = "api_key_virustotal.txt"
MONTHS = {m:i for i,m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
PRIV_GROUPS = {"sudo", "wheel", "admin", "root"}
HIGH_PRIV_KEYWORDS = ("root","admin","adm","sudo","wheel","ops","sec","security","backup","oracle","postgres","mysql","dbadmin","vmanage-admin")

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
    ip_scope: Optional[str] = None
    src_ip_name: Optional[str] = None
    src_ip_role: Optional[str] = None
    src_ip_owner: Optional[str] = None
    src_ip_display: Optional[str] = None
    vt_country: Optional[str] = None
    vt_organization: Optional[str] = None
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_total_malicious_suspicious: int = 0
    vt_status: Optional[str] = None
    ip_context_display: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[str] = None
    service: Optional[str] = None
    auth_method: Optional[str] = None
    key_type: Optional[str] = None
    key_fingerprint: Optional[str] = None
    tty: Optional[str] = None
    pwd: Optional[str] = None
    run_as: Optional[str] = None
    command: Optional[str] = None
    group: Optional[str] = None
    uid: Optional[str] = None
    gid: Optional[str] = None
    home: Optional[str] = None
    shell: Optional[str] = None
    mitre: List[Dict[str,str]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    raw: str = ""
    def json(self): return asdict(self)

@dataclass
class RawRecord:
    timestamp: str
    sort_ts: str
    host: str
    source_file: str
    process: str = ""
    pid: str = ""
    raw: str = ""

@dataclass
class Alert:
    id: str
    name: str
    severity: str
    description: str
    entities: Dict[str,str]
    mitre: List[Dict[str,str]]
    evidence: List[str]
    def json(self): return asdict(self)

def mitre(tactic, tid, technique, confidence="medium"):
    return {"tactic":tactic,"technique_id":tid,"technique":technique,"confidence":confidence}

def sev_rank(s): return {"info":0,"low":1,"medium":2,"high":3,"critical":4}.get(s,0)
def score_sev(x): return "critical" if x>=120 else "high" if x>=70 else "medium" if x>=30 else "low" if x>0 else "info"
def behavior_risk_level(x): return "CRITICAL" if x>=80 else "HIGH" if x>=55 else "MEDIUM" if x>=25 else "LOW" if x>0 else "INFO"
def parse_dt(s): return datetime.fromisoformat(s)
def fmt_us(s):
    if not s: return ""
    try: return parse_dt(s).strftime("%m/%d/%Y %I:%M:%S %p")
    except Exception: return s

def ip_scope(ip):
    if not ip: return "unknown"
    try:
        o = ipaddress.ip_address(ip)
        if o.is_loopback: return "loopback"
        if o.is_private: return "private"
        if o.is_link_local: return "link_local"
        if o.is_multicast: return "multicast"
        if o.is_reserved: return "reserved"
        if o.is_global: return "public"
        return "non_global"
    except Exception:
        return "unknown"
def is_public_ip(ip): return ip_scope(ip)=="public"
def safe(s): return re.sub(r"[^A-Za-z0-9._-]+", "_", s or "UNKNOWN")[:120] or "UNKNOWN"
def first_ts(evs): return min((e.timestamp for e in evs), default="")
def last_ts(evs): return max((e.timestamp for e in evs), default="")
def hosts_join(evs): return ",".join(sorted({e.host for e in evs if e.host}))
def users_join(evs): return ",".join(sorted({e.user or e.target_user or "UNKNOWN" for e in evs}))

def hostlog_summary(events, raws):
    parsed = Counter(e.host for e in events if e.host)
    raw = Counter(r.host for r in raws if r.host)
    hosts = sorted(set(parsed) | set(raw))
    return [{"host":h,"parsed_events":parsed.get(h,0),"raw_lines":raw.get(h,0)} for h in hosts]

SYSLOG = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<body>.*)$")
PROC = re.compile(r"^(?P<proc>[\w.\-/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
SSH_FAIL = re.compile(r"Failed (?P<method>\S+) for (?:(?:invalid user)\s+)?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)")
SSH_INV = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)(?: port (?P<port>\d+))?")
SSH_OK = re.compile(r"Accepted (?P<method>.+?) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+) ssh2(?::?\s*(?P<extra>.*))?$")
SSH_PAM_ERR = re.compile(r"error: PAM: Authentication failure for (?P<user>\S+) from (?P<src>\S+)")
SUDO = re.compile(r"^(?P<actor>\S+)\s+:\s+TTY=(?P<tty>[^;]+)\s+;\s+PWD=(?P<pwd>[^;]+)\s+;\s+USER=(?P<run_as>[^;]+)\s+;\s+COMMAND=(?P<cmd>.+)$")
PAM_SESSION = re.compile(r"pam_unix\((?P<svc>[^:]+):session\): session (?P<act>opened|closed) for user (?P<user>\S+)(?: by (?P<by>[^\(]+)?\(uid=(?P<uid>\d+)\))?")
SU_SUCCESS = re.compile(r"Successful su for (?P<target>\S+) by (?P<actor>\S+)")
SU_TTY = re.compile(r"^\+\s+(?P<tty>\S+)\s+(?P<actor>[^:]+):(?P<target>\S+)")
AUTH_FAIL = re.compile(r"pam_unix\((?P<svc>[^:]+):auth\): authentication failure;.*?(?:ruser=(?P<ruser>\S*))?.*?(?:rhost=(?P<rhost>\S*))?.*?user=(?P<user>\S+)")
GROUP_CREATED = re.compile(r"new group: name=(?P<group>[^,]+), GID=(?P<gid>\d+)")
USERADD_USER = re.compile(r"new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+), home=(?P<home>[^,]+), shell=(?P<shell>[^,\s]+)(?:, from=(?P<from>\S+))?")
PASSWD = re.compile(r"password changed for (?P<user>\S+)")
USERMOD_GROUP = re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")
USERDEL_USER = re.compile(r"delete user [`'](?P<user>[^`']+)[`']")
USERDEL_GROUP = re.compile(r"removed group [`'](?P<group>[^`']+)[`'] owned by [`'](?P<owner>[^`']+)[`']")
CHFN_CHANGED = re.compile(r"changed user [`'](?P<user>[^`']+)[`'] information")
IP_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
KEY_FP_RE = re.compile(r"(?P<key_type>RSA|DSA|ECDSA|ED25519|ssh-rsa|ssh-ed25519|ecdsa-sha2-\S+)\s+(?P<fingerprint>SHA256:[A-Za-z0-9+/=]+)", re.I)

def make_ts(mon, day, clock, year):
    x = datetime(year, MONTHS.get(mon,1), int(day), *map(int, clock.split(":")))
    return x.isoformat(), x.isoformat()

def base(pre, source, etype, cat, raw, year):
    ts, sort = make_ts(pre["mon"], pre["day"], pre["clock"], year)
    return Event(ts, sort, pre["host"], str(source), etype, cat, raw=raw)

def norm_method(m):
    m = (m or "").strip().lower()
    if m == "keyboard-interactive/pam": return m
    if "publickey" in m: return "publickey"
    if "password" in m: return "password"
    return m or "unknown"

def success_type(m):
    return {"publickey":"ssh_login_success_publickey", "password":"ssh_login_success_password", "keyboard-interactive/pam":"ssh_login_success_keyboard_interactive"}.get(norm_method(m), "ssh_login_success_other")

def discover(path:Path):
    if path.is_file(): return [path]
    out=[]
    for pat in ["auth.log","auth.log.*","secure","secure-*","secure.*"]:
        out.extend(path.glob(pat))
    return sorted({p.resolve() for p in out if p.is_file()}, key=lambda p:str(p))

def read_lines(path:Path):
    if path.suffix == ".gz":
        with gzip.open(path, "rt", errors="replace") as f:
            for line in f: yield line.rstrip("\n")
    else:
        with path.open("rt", errors="replace") as f:
            for line in f: yield line.rstrip("\n")

def parse_raw_record(line, source, year):
    m = SYSLOG.match(line)
    if not m: return None
    pre = m.groupdict(); body = pre.pop("body")
    ts, sort = make_ts(pre["mon"], pre["day"], pre["clock"], year)
    pm = PROC.match(body); proc = pid = ""
    if pm:
        proc = pm.group("proc") or ""; pid = pm.group("pid") or ""
    return RawRecord(ts, sort, pre["host"], str(source), proc, pid, line)

def classify_sudo(cmd):
    lc=cmd.lower(); et="sudo_command"; sev="info"; notes=[]; tags=[mitre("Privilege Escalation","T1548","Abuse Elevation Control Mechanism")]
    if re.search(r"\b(useradd|adduser|newusers)\b",lc): et="sudo_account_create_command"; sev="high"; tags.append(mitre("Persistence","T1136.001","Create Account: Local Account","high"))
    elif re.search(r"\b(passwd|chpasswd)\b",lc): et="sudo_password_change_command"; sev="high"; tags.append(mitre("Persistence","T1098","Account Manipulation"))
    elif re.search(r"\b(usermod|gpasswd|groupadd|groupmod|addgroup)\b",lc): et="sudo_account_modify_command"; sev="high"; tags.append(mitre("Persistence","T1098","Account Manipulation","high"))
    elif re.search(r"\b(userdel|deluser)\b",lc): et="sudo_account_delete_command"; sev="medium"; tags.append(mitre("Persistence","T1098","Account Manipulation"))
    if "authorized_keys" in lc: et="ssh_authorized_keys_command"; sev="high"; notes.append("Command references authorized_keys"); tags.append(mitre("Persistence","T1098.004","Account Manipulation: SSH Authorized Keys"))
    return et, sev, tags, notes

def parse_line(line, source, year):
    m=SYSLOG.match(line)
    if not m: return None
    pre=m.groupdict(); body=pre.pop("body")
    pm=PROC.match(body)
    if not pm: return None
    proc,pid,msg=pm.group("proc"),pm.group("pid"),pm.group("msg")
    if proc=="sshd":
        if mm:=SSH_PAM_ERR.search(msg):
            e=base(pre,source,"ssh_pam_auth_failure","authentication",line,year); e.process=proc; e.pid=pid; e.service="sshd"; e.user=e.target_user=mm.group("user"); src=mm.group("src"); e.src_ip=src if re.match(r"^[0-9a-fA-F:.]+$",src) else None; e.ip_scope=ip_scope(e.src_ip); e.outcome="failure"; e.severity="medium"; e.mitre=[mitre("Credential Access","T1110","Brute Force")]; return e
        if mm:=SSH_INV.search(msg):
            e=base(pre,source,"ssh_invalid_user","authentication",line,year); e.process=proc; e.pid=pid; e.service="sshd"; e.user=e.target_user=mm.group("user"); e.src_ip=mm.group("ip"); e.ip_scope=ip_scope(e.src_ip); e.src_port=mm.groupdict().get("port"); e.outcome="failure"; e.severity="medium"; e.mitre=[mitre("Credential Access","T1110","Brute Force")]; return e
        if mm:=SSH_FAIL.search(msg):
            e=base(pre,source,"ssh_login_failed","authentication",line,year); e.process=proc; e.pid=pid; e.service="sshd"; e.auth_method=norm_method(mm.group("method")); e.user=e.target_user=mm.group("user"); e.src_ip=mm.group("ip"); e.ip_scope=ip_scope(e.src_ip); e.src_port=mm.group("port"); e.outcome="failure"; e.severity="medium" if e.user=="root" else "low"; e.mitre=[mitre("Credential Access","T1110.001","Brute Force: Password Guessing")]; return e
        if mm:=SSH_OK.search(msg):
            method=norm_method(mm.group("method")); e=base(pre,source,success_type(method),"authentication",line,year); e.process=proc; e.pid=pid; e.service="sshd"; e.auth_method=method; e.user=e.actor_user=mm.group("user"); e.src_ip=mm.group("ip"); e.ip_scope=ip_scope(e.src_ip); e.src_port=mm.group("port"); e.outcome="success"; e.severity="medium"; e.mitre=[mitre("Initial Access","T1021.004","Remote Services: SSH"),mitre("Initial Access","T1078","Valid Accounts")]
            extra=mm.groupdict().get("extra") or ""
            if extra and (km:=KEY_FP_RE.search(extra)): e.key_type=km.group("key_type"); e.key_fingerprint=km.group("fingerprint")
            return e
    if proc=="sudo" and (mm:=SUDO.match(msg)):
        et,sev,tags,notes=classify_sudo(mm.group("cmd")); e=base(pre,source,et,"privilege_activity",line,year); e.process=proc; e.pid=pid; e.service="sudo"; e.actor_user=e.user=mm.group("actor"); e.tty=mm.group("tty").strip(); e.pwd=mm.group("pwd").strip(); e.run_as=e.target_user=mm.group("run_as").strip(); e.command=mm.group("cmd"); e.outcome="success"; e.severity=sev; e.mitre=tags; e.notes=notes; return e
    if mm:=PAM_SESSION.search(msg):
        e=base(pre,source,f"session_{mm.group('act')}","session",line,year); e.process=proc; e.pid=pid; e.service=mm.group("svc"); e.user=e.target_user=mm.group("user"); by=(mm.groupdict().get("by") or "").strip(); e.actor_user=by if by else None; e.uid=mm.groupdict().get("uid"); e.outcome="success"; return e
    if proc=="su":
        if mm:=SU_SUCCESS.search(msg):
            e=base(pre,source,"su_success","privilege_activity",line,year); e.process=proc; e.pid=pid; e.service="su"; e.actor_user=mm.group("actor"); e.user=e.actor_user; e.target_user=mm.group("target"); e.outcome="success"; e.severity="high" if e.target_user=="root" else "medium"; e.mitre=[mitre("Privilege Escalation","T1548","Abuse Elevation Control Mechanism")]; return e
        if mm:=SU_TTY.search(msg):
            e=base(pre,source,"su_tty_activity","privilege_activity",line,year); e.process=proc; e.pid=pid; e.service="su"; e.tty=mm.group("tty"); e.actor_user=mm.group("actor"); e.user=e.actor_user; e.target_user=mm.group("target"); e.outcome="success"; e.severity="medium"; return e
    if mm:=AUTH_FAIL.search(msg):
        e=base(pre,source,"pam_auth_failure","authentication",line,year); e.process=proc; e.pid=pid; e.service=mm.group("svc"); e.actor_user=mm.groupdict().get("ruser") or None; e.user=e.actor_user or mm.group("user"); e.target_user=mm.group("user"); e.src_ip=mm.groupdict().get("rhost") or None; e.ip_scope=ip_scope(e.src_ip); e.outcome="failure"; e.severity="medium"; return e
    if proc in {"useradd","groupadd"} and (mm:=GROUP_CREATED.search(msg)):
        e=base(pre,source,"group_created","account_management",line,year); e.process=proc; e.pid=pid; e.group=mm.group("group"); e.gid=mm.group("gid"); e.outcome="success"; e.severity="medium"; e.mitre=[mitre("Persistence","T1098","Account Manipulation")]; return e
    if proc=="useradd" and (mm:=USERADD_USER.search(msg)):
        e=base(pre,source,"account_created","account_management",line,year); e.process=proc; e.pid=pid; e.user=e.target_user=mm.group("user"); e.uid=mm.group("uid"); e.gid=mm.group("gid"); e.home=mm.group("home"); e.shell=mm.group("shell"); e.outcome="success"; e.severity="high"; e.mitre=[mitre("Persistence","T1136.001","Create Account: Local Account","high")]; return e
    if proc=="passwd" and (mm:=PASSWD.search(msg)):
        e=base(pre,source,"password_changed","account_management",line,year); e.process=proc; e.pid=pid; e.user=e.target_user=mm.group("user"); e.outcome="success"; e.severity="high"; e.mitre=[mitre("Persistence","T1098","Account Manipulation")]; return e
    if proc=="usermod" and (mm:=USERMOD_GROUP.search(msg)):
        e=base(pre,source,"user_added_to_group","account_management",line,year); e.process=proc; e.pid=pid; e.user=e.target_user=mm.group("user"); e.group=mm.group("group"); e.outcome="success"; e.severity="critical" if e.group in PRIV_GROUPS else "high"; e.mitre=[mitre("Persistence","T1098","Account Manipulation","high")]; return e
    if proc=="userdel":
        if mm:=USERDEL_USER.search(msg):
            e=base(pre,source,"account_deleted","account_management",line,year); e.process=proc; e.pid=pid; e.user=e.target_user=mm.group("user"); e.outcome="success"; e.severity="medium"; e.mitre=[mitre("Persistence","T1098","Account Manipulation")]; return e
        if mm:=USERDEL_GROUP.search(msg):
            e=base(pre,source,"group_deleted","account_management",line,year); e.process=proc; e.pid=pid; e.group=mm.group("group"); e.user=mm.group("owner"); e.outcome="success"; e.severity="medium"; e.mitre=[mitre("Persistence","T1098","Account Manipulation")]; return e
    if proc=="chfn" and (mm:=CHFN_CHANGED.search(msg)):
        e=base(pre,source,"user_info_changed","account_management",line,year); e.process=proc; e.pid=pid; e.user=e.target_user=mm.group("user"); e.outcome="success"; e.severity="low"; e.mitre=[mitre("Persistence","T1098","Account Manipulation","low")]; return e
    return None

def parse_files(files,year):
    events=[]; raws=[]
    for f in files:
        print(f"[*] Parsing {f}", file=sys.stderr, flush=True)
        try:
            for line in read_lines(f):
                rr=parse_raw_record(line,f,year)
                if rr: raws.append(rr)
                ev=parse_line(line,f,year)
                if ev: events.append(ev)
        except Exception as ex: print(f"[!] Failed reading {f}: {ex}", file=sys.stderr, flush=True)
    return sorted(events,key=lambda e:e.sort_ts), sorted(raws,key=lambda r:r.sort_ts)

def extract_ips(events):
    ips=[]
    for e in events:
        if e.src_ip: ips.append(e.src_ip)
        ips.extend(IP_RE.findall(e.raw or ""))
    out=[]
    for ip in ips:
        try: ipaddress.ip_address(ip); out.append(ip)
        except ValueError: pass
    return sorted(set(out))
def split_ips(ips):
    pub=[]; priv=[]
    for ip in sorted(set(ips)): (pub if is_public_ip(ip) else priv).append(ip)
    return pub,priv

def load_hostipdb(path):
    db={}
    if not path: return db
    p=Path(path).expanduser()
    if not p.exists(): print(f"[!] hostipdb file not found: {p}", file=sys.stderr, flush=True); return db
    with p.open("r", encoding="utf-8", errors="replace") as f:
        sample=f.read(4096); f.seek(0)
        if sample and "," in sample.splitlines()[0]:
            for r in csv.DictReader(f):
                ip=(r.get("ip") or r.get("IP") or "").strip()
                if ip: db[ip]={"hostname":(r.get("hostname") or r.get("name") or "").strip(),"role":(r.get("role") or "").strip(),"owner":(r.get("owner") or "").strip(),"notes":(r.get("notes") or "").strip()}
        else:
            for line in f:
                parts=line.strip().split()
                if len(parts)>=2 and not parts[0].startswith("#"): db[parts[0]]={"hostname":parts[1],"role":parts[2] if len(parts)>2 else "","owner":parts[3] if len(parts)>3 else "","notes":" ".join(parts[4:]) if len(parts)>4 else ""}
    return db

def vt_query(ip,key):
    req=urllib.request.Request(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"accept":"application/json","x-apikey":key})
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return r.getcode(), json.loads(r.read().decode("utf-8","replace"))
    except urllib.error.HTTPError as e:
        try: data=json.loads(e.read().decode("utf-8","replace"))
        except Exception: data={"error":{"message":str(e)}}
        return e.code,data
    except Exception as e: return 0,{"error":{"message":str(e)}}
def vt_norm(ip,status,code,data):
    attrs=data.get("data",{}).get("attributes",{}) if isinstance(data,dict) else {}; stats=attrs.get("last_analysis_stats",{}) or {}; results=attrs.get("last_analysis_results",{}) or {}; mal=int(stats.get("malicious") or 0); susp=int(stats.get("suspicious") or 0); sources=[]
    if isinstance(results,dict):
        for vendor,val in results.items():
            if isinstance(val,dict) and val.get("category") in {"malicious","suspicious"}: sources.append(vendor)
    return {"ip":ip,"country":attrs.get("country") or "UNKNOWN","organization":attrs.get("as_owner") or "UNKNOWN","malicious":mal,"suspicious":susp,"total_malicious_suspicious":mal+susp,"malicious_suspicious_sources":",".join(sources) if sources else "NONE","vt_status":status,"http_code":str(code),"error":data.get("error",{}).get("message","") if isinstance(data,dict) else ""}
def vt_enrich(public_ips,case,key_file,sleep=16,cache=True):
    key=key_file.read_text().strip(); rows={}; d=case/"enrichment"/"virustotal"; d.mkdir(parents=True,exist_ok=True)
    if not key: print(f"[*] VirusTotal API key kosong ({key_file}); VT enrichment dilewati.",file=sys.stderr, flush=True); return rows
    for ip in public_ips:
        print(f"[*] VT checking {ip}...",file=sys.stderr, flush=True); cf=d/f"{ip}.json"
        if cache and cf.exists(): rows[ip]=vt_norm(ip,"CACHE","CACHE",json.loads(cf.read_text(errors="replace"))); continue
        code,data=vt_query(ip,key); status="OK" if code==200 else "RATE_LIMIT" if code==429 else "ERROR"; rows[ip]=vt_norm(ip,status,str(code),data)
        (cf if code==200 else d/f"{ip}.error.json").write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding="utf-8")
        if sleep>0: time.sleep(sleep)
    return rows

def apply_context(events,hostdb,vt_rows,join_vt=False):
    for e in events:
        if not e.src_ip: continue
        rec=hostdb.get(e.src_ip,{})
        e.src_ip_name=rec.get("hostname") or ""; e.src_ip_role=rec.get("role") or ""; e.src_ip_owner=rec.get("owner") or ""; e.src_ip_display=f"{e.src_ip} ({e.src_ip_name})" if e.src_ip_name else e.src_ip
        if join_vt:
            vt=vt_rows.get(e.src_ip)
            if vt:
                e.vt_country=vt.get("country"); e.vt_organization=vt.get("organization"); e.vt_malicious=int(vt.get("malicious") or 0); e.vt_suspicious=int(vt.get("suspicious") or 0); e.vt_total_malicious_suspicious=int(vt.get("total_malicious_suspicious") or 0); e.vt_status=vt.get("vt_status")
            else:
                e.vt_status="PRIVATE_SKIPPED" if not is_public_ip(e.src_ip) else "NOT_ENRICHED"; e.vt_total_malicious_suspicious=0
            vt_part=f"VT org={e.vt_organization or 'UNKNOWN'} country={e.vt_country or 'UNKNOWN'} total={e.vt_total_malicious_suspicious or 0} status={e.vt_status or ''}"
            e.ip_context_display=f"{e.src_ip_display or e.src_ip} | {vt_part}"
        else:
            e.vt_status="VT_JOIN_DISABLED"
            e.ip_context_display=e.src_ip_display or e.src_ip

def detect(events):
    alerts=[]; byip=defaultdict(list)
    for e in events:
        if e.src_ip: byip[e.src_ip].append(e)
    for ip,evs in byip.items():
        fails=[e for e in evs if e.event_type in {"ssh_login_failed","ssh_invalid_user","ssh_pam_auth_failure"}]
        if len(fails)>=20: alerts.append(Alert("AUTH-BRUTEFORCE-IP","SSH brute force/password attack from single IP","high",f"{len(fails)} failed SSH auth events from {ip}.",{"src_ip":ip},[mitre("Credential Access","T1110","Brute Force")],[x.raw for x in fails[:10]]))
    for e in events:
        if e.event_type=="account_created" and e.user: alerts.append(Alert("AUTH-LOCAL-ACCOUNT-CREATED","Local account created","high",f"Local user account {e.user} was created.",{"user":e.user},[mitre("Persistence","T1136.001","Create Account: Local Account")],[e.raw]))
    return alerts

def is_high_priv_user(user,life=None):
    if not user: return False,""
    u=user.lower(); reasons=[]
    if u=="root": reasons.append("user_is_root")
    for kw in HIGH_PRIV_KEYWORDS:
        if kw!="root" and kw in u: reasons.append(f"user_contains_{kw}"); break
    if life and user in life and life[user].get("privileged_groups_added"): reasons.append("user_added_to_privileged_group")
    return bool(reasons),",".join(sorted(set(reasons)))

def build_indicator_tables(events):
    failed=[e for e in events if e.event_type in {"ssh_login_failed","ssh_pam_auth_failure"}]; success=[e for e in events if e.event_type.startswith("ssh_login_success")]
    created=[e for e in events if e.event_type=="account_created"]; deleted=[e for e in events if e.event_type=="account_deleted"]; groups=[e for e in events if e.event_type=="group_created"]; info=[e for e in events if e.event_type=="user_info_changed"]; passwd=[e for e in events if e.event_type=="password_changed"]; priv=[e for e in events if e.event_type=="user_added_to_group" and e.group in PRIV_GROUPS]
    by_user=defaultdict(list); succ_user=defaultdict(list); fail_pair=defaultdict(list); succ_pair=defaultdict(list); fail_ip=defaultdict(list); succ_ip=defaultdict(list)
    for e in failed:
        u=e.user or e.target_user or "UNKNOWN"; by_user[u].append(e)
        if e.src_ip: fail_pair[(e.src_ip,u)].append(e); fail_ip[e.src_ip].append(e)
    for e in success:
        u=e.user or "UNKNOWN"; succ_user[u].append(e)
        if e.src_ip: succ_pair[(e.src_ip,u)].append(e); succ_ip[e.src_ip].append(e)
    rows_failed=[]
    for u,evs in by_user.items():
        succ=succ_user.get(u,[]); rows_failed.append({"user":u,"hosts":hosts_join(evs+succ),"failed_count":len(evs),"unique_source_ips":len({e.src_ip for e in evs if e.src_ip}),"source_ips":",".join(sorted({e.src_ip for e in evs if e.src_ip})),"first_failed":first_ts(evs),"last_failed":last_ts(evs),"successful_login_count":len(succ),"first_success":first_ts(succ),"last_success":last_ts(succ),"last_success_us_format":fmt_us(last_ts(succ)),"root_targeted":"yes" if u=="root" else "no","risk":"HIGH" if u=="root" or len(evs)>=20 else "LOW"})
    rows_failed.sort(key=lambda r:int(r["failed_count"]), reverse=True)
    rows_fail_pair=[]
    for (ip,u),evs in fail_pair.items():
        succ=succ_pair.get((ip,u),[]); e0=evs[0]; rows_fail_pair.append({"src_ip":ip,"src_ip_display":e0.src_ip_display or ip,"ip_context_display":e0.ip_context_display or ip,"vt_status":e0.vt_status or "","ip_scope":ip_scope(ip),"hosts":hosts_join(evs+succ),"user":u,"failed_count":len(evs),"success_count":len(succ),"first_failed":first_ts(evs),"last_failed":last_ts(evs),"first_success":first_ts(succ),"last_success":last_ts(succ),"last_success_us_format":fmt_us(last_ts(succ))})
    rows_fail_pair.sort(key=lambda r:int(r["failed_count"]), reverse=True)
    rows_succ_ip=[]
    for ip,evs in succ_ip.items():
        fails=fail_ip.get(ip,[]); fs=first_ts(evs); before=[f for f in fails if f.timestamp<fs] if fs else []; e0=evs[0]
        rows_succ_ip.append({"src_ip":ip,"src_ip_display":e0.src_ip_display or ip,"ip_context_display":e0.ip_context_display or ip,"src_ip_name":e0.src_ip_name or "","src_ip_role":e0.src_ip_role or "","vt_status":e0.vt_status or "","ip_scope":ip_scope(ip),"is_public_ip":"yes" if is_public_ip(ip) else "no","hosts":hosts_join(evs+fails),"success_count":len(evs),"failed_count_total":len(fails),"failed_before_first_success":len(before),"users_success":users_join(evs),"users_failed":users_join(fails),"auth_methods":",".join(sorted({e.auth_method or "unknown" for e in evs})),"first_success":fs,"last_success":last_ts(evs),"last_success_us_format":fmt_us(last_ts(evs)),"first_failed":first_ts(fails),"last_failed":last_ts(fails)})
    rows_succ_ip.sort(key=lambda r:int(r["success_count"]), reverse=True)
    rows_succ_user=[]
    for u,evs in succ_user.items():
        fails=by_user.get(u,[]); rows_succ_user.append({"user":u,"hosts":hosts_join(evs+fails),"success_count":len(evs),"unique_source_ips":len({e.src_ip for e in evs if e.src_ip}),"source_ips":",".join(sorted({e.src_ip for e in evs if e.src_ip})),"auth_methods":",".join(sorted({e.auth_method or "unknown" for e in evs})),"failed_count_total":len(fails),"first_success":first_ts(evs),"last_success":last_ts(evs),"last_success_us_format":fmt_us(last_ts(evs)),"first_failed":first_ts(fails),"last_failed":last_ts(fails)})
    rows_succ_user.sort(key=lambda r:int(r["success_count"]), reverse=True)
    rows_saf=[]; rows_saf_pair=[]
    for ip,succ in succ_ip.items():
        fails=fail_ip.get(ip,[]); fs=first_ts(succ); before=[f for f in fails if f.timestamp<fs] if fs else []; e0=succ[0]
        if before: rows_saf.append({"src_ip":ip,"src_ip_display":e0.src_ip_display or ip,"ip_context_display":e0.ip_context_display or ip,"vt_status":e0.vt_status or "","ip_scope":ip_scope(ip),"hosts":hosts_join(succ+fails),"failed_before_first_success":len(before),"failed_count_total":len(fails),"success_count":len(succ),"users_failed":users_join(fails),"users_success":users_join(succ),"auth_methods":",".join(sorted({e.auth_method or "unknown" for e in succ})),"first_failed":first_ts(fails),"first_success":fs,"last_success":last_ts(succ),"last_success_us_format":fmt_us(last_ts(succ))})
    for (ip,u),succ in succ_pair.items():
        fails=fail_pair.get((ip,u),[]); fs=first_ts(succ); before=[f for f in fails if f.timestamp<fs] if fs else []; e0=succ[0]
        if before: rows_saf_pair.append({"src_ip":ip,"src_ip_display":e0.src_ip_display or ip,"ip_context_display":e0.ip_context_display or ip,"vt_status":e0.vt_status or "","ip_scope":ip_scope(ip),"hosts":hosts_join(succ+fails),"user":u,"failed_before_first_success":len(before),"failed_count_total":len(fails),"success_count":len(succ),"auth_methods":",".join(sorted({e.auth_method or "unknown" for e in succ})),"first_failed":first_ts(fails),"first_success":fs,"last_success":last_ts(succ),"last_success_us_format":fmt_us(last_ts(succ))})
    rows_created=[{"timestamp":e.timestamp,"timestamp_us_format":fmt_us(e.timestamp),"host":e.host,"user":e.user or "","uid":e.uid or "","gid":e.gid or "","home":e.home or "","shell":e.shell or "","source_file":e.source_file,"raw":e.raw} for e in created]
    rows_deleted=[{"timestamp":e.timestamp,"timestamp_us_format":fmt_us(e.timestamp),"host":e.host,"user":e.user or "","source_file":e.source_file,"raw":e.raw} for e in deleted]
    rows_groups=[{"timestamp":e.timestamp,"timestamp_us_format":fmt_us(e.timestamp),"host":e.host,"group":e.group or "","gid":e.gid or "","process":e.process or "","source_file":e.source_file,"raw":e.raw} for e in groups]
    rows_priv=[{"timestamp":e.timestamp,"timestamp_us_format":fmt_us(e.timestamp),"host":e.host,"user":e.user or "","group":e.group or "","source_file":e.source_file,"raw":e.raw} for e in priv]
    rows_info=[{"timestamp":e.timestamp,"timestamp_us_format":fmt_us(e.timestamp),"host":e.host,"user":e.user or "","source_file":e.source_file,"raw":e.raw} for e in info]
    users=sorted({e.user for e in created+deleted+passwd+priv+info if e.user}); rows_life=[]
    for u in users:
        ce=[e for e in created if e.user==u]; de=[e for e in deleted if e.user==u]; pe=[e for e in passwd if e.user==u]; ge=[e for e in priv if e.user==u]; ie=[e for e in info if e.user==u]; fc=ce[0] if ce else None; shell=(fc.shell if fc else "") or ""; uid=(fc.uid if fc else "") or ""; home=(fc.home if fc else "") or ""; status="deleted" if de else "active_or_unknown"
        rows_life.append({"user":u,"hosts":hosts_join(ce+de+pe+ge+ie),"created_at":first_ts(ce),"created_at_us_format":fmt_us(first_ts(ce)),"deleted_at":first_ts(de),"deleted_at_us_format":fmt_us(first_ts(de)),"password_changed":"yes" if pe else "no","password_change_count":len(pe),"user_info_changed_count":len(ie),"privileged_groups_added":",".join(sorted({e.group or "" for e in ge if e.group})),"uid":uid,"home":home,"shell":shell,"status":status})
    return {"failed_password_by_user.csv":rows_failed,"failed_password_by_ip_user.csv":rows_fail_pair,"success_login_by_ip.csv":rows_succ_ip,"success_login_by_user.csv":rows_succ_user,"success_after_failed_ips.csv":rows_saf,"success_after_failed_ip_user.csv":rows_saf_pair,"created_users.csv":rows_created,"deleted_users.csv":rows_deleted,"groups_created.csv":rows_groups,"privileged_users_added.csv":rows_priv,"user_info_changed.csv":rows_info,"account_lifecycle.csv":rows_life}

def lifecycle_index(ind): return {str(r.get("user")):{str(k):str(v) for k,v in r.items()} for r in ind.get("account_lifecycle.csv",[]) if r.get("user")}
def active_days(evs): return len({parse_dt(e.timestamp).date().isoformat() for e in evs})
def hour_distribution(evs):
    c=Counter(parse_dt(e.timestamp).hour for e in evs); return ",".join(f"{h:02d}:{c[h]}" for h in sorted(c))
def compute_near_risk(bucket,life):
    users={x.user for x in bucket if x.user}; methods={x.auth_method or "unknown" for x in bucket}; scopes={x.ip_scope or ip_scope(x.src_ip) for x in bucket if x.src_ip}; hp=[u for u in users if is_high_priv_user(u,life)[0]]
    score=0; insights=[]; reasons=[]; pwd=sum(1 for x in bucket if x.auth_method=="password"); ip_users=defaultdict(set)
    for x in bucket:
        if x.src_ip and x.user: ip_users[x.src_ip].add(x.user)
    def add(p,n):
        nonlocal score; score+=p; insights.append(n); reasons.append(n)
    if len(users)>=2: add(10,"multiple_users_near_login")
    if any(len(v)>=2 for v in ip_users.values()): add(20,"same_ip_multiple_users")
    if len(methods)>1: add(10,"mixed_auth_method_burst")
    if hp and len(users)>=2: add(25,"multiple_users_near_login_with_high_priv")
    if len(hp)>=2: add(35,"multiple_high_priv_users_near_login")
    if "public" in scopes and len(users)>=2: add(20,"multiple_users_near_login_from_public_ip")
    if pwd>=2: add(15,"password_success_burst")
    return score,behavior_risk_level(score),sorted(set(insights)),sorted(set(reasons)),sorted(hp)

def behavior_tables(events,indicators,near_minutes=10,no_near_login=False):
    success=[e for e in events if e.event_type.startswith("ssh_login_success")]; life=lifecycle_index(indicators)
    rows_method=[]; bm=defaultdict(list)
    for e in success: bm[e.auth_method or "unknown"].append(e)
    for m,evs in bm.items(): rows_method.append({"auth_method":m,"hosts":hosts_join(evs),"success_count":len(evs),"unique_users":len({e.user for e in evs if e.user}),"unique_source_ips":len({e.src_ip for e in evs if e.src_ip}),"users":",".join(sorted({e.user for e in evs if e.user})),"source_ips":",".join(sorted({e.src_ip for e in evs if e.src_ip})),"first_success":first_ts(evs),"last_success":last_ts(evs)})
    rows_high=[]
    for e in success:
        ok,reason=is_high_priv_user(e.user,life)
        if ok: rows_high.append({"timestamp":e.timestamp,"timestamp_us_format":fmt_us(e.timestamp),"host":e.host,"user":e.user or "","src_ip":e.src_ip or "","src_ip_display":e.src_ip_display or e.src_ip or "","ip_context_display":e.ip_context_display or e.src_ip or "","vt_status":e.vt_status or "","ip_scope":e.ip_scope or ip_scope(e.src_ip),"auth_method":e.auth_method or "unknown","key_type":e.key_type or "","key_fingerprint":e.key_fingerprint or "","reason":reason,"source_file":e.source_file,"raw":e.raw})
    by_user=defaultdict(list); by_ip=defaultdict(list)
    for e in success:
        by_user[e.user or "UNKNOWN"].append(e)
        if e.src_ip: by_ip[e.src_ip].append(e)
    rows_user=[]
    for u,evs in by_user.items():
        c=Counter(parse_dt(e.timestamp).hour for e in evs).most_common(1); rows_user.append({"user":u,"hosts":hosts_join(evs),"login_count":len(evs),"active_days":active_days(evs),"unique_source_ips":len({e.src_ip for e in evs if e.src_ip}),"auth_methods":",".join(sorted({e.auth_method or "unknown" for e in evs})),"first_login":first_ts(evs),"last_login":last_ts(evs),"most_common_hour":f"{c[0][0]:02d}" if c else "","hour_distribution":hour_distribution(evs),"pattern_note":f"regular_login_hour_{c[0][0]:02d}" if c and active_days(evs)>=3 and c[0][1]/len(evs)>=0.5 else ""})
    rows_ip=[]
    for ip,evs in by_ip.items():
        c=Counter(parse_dt(e.timestamp).hour for e in evs).most_common(1); e0=evs[0]; rows_ip.append({"src_ip":ip,"src_ip_display":e0.src_ip_display or ip,"ip_context_display":e0.ip_context_display or ip,"vt_status":e0.vt_status or "","ip_scope":ip_scope(ip),"hosts":hosts_join(evs),"login_count":len(evs),"active_days":active_days(evs),"unique_users":len({e.user for e in evs if e.user}),"users":",".join(sorted({e.user for e in evs if e.user})),"auth_methods":",".join(sorted({e.auth_method or "unknown" for e in evs})),"first_login":first_ts(evs),"last_login":last_ts(evs),"most_common_hour":f"{c[0][0]:02d}" if c else "","hour_distribution":hour_distribution(evs),"pattern_note":f"regular_login_hour_{c[0][0]:02d}" if c and active_days(evs)>=3 and c[0][1]/len(evs)>=0.5 else ""})
    rows_near=[]
    if not no_near_login:
        succ=sorted(success,key=lambda e:e.sort_ts); win=timedelta(minutes=near_minutes); seen=set()
        for i,e in enumerate(succ):
            bucket=[e]; j=i+1
            while j<len(succ) and parse_dt(succ[j].timestamp)-parse_dt(e.timestamp)<=win: bucket.append(succ[j]); j+=1
            if len(bucket)<2: continue
            users={x.user for x in bucket if x.user}; ips={x.src_ip for x in bucket if x.src_ip}; methods={x.auth_method or "unknown" for x in bucket}; score,level,insights,reasons,hp=compute_near_risk(bucket,life)
            if not insights: continue
            key=(bucket[0].timestamp,bucket[-1].timestamp,tuple(sorted(users)),tuple(sorted(ips)),tuple(sorted(methods)))
            if key in seen: continue
            seen.add(key); rows_near.append({"window_start":bucket[0].timestamp,"window_end":bucket[-1].timestamp,"window_minutes":near_minutes,"hosts":hosts_join(bucket),"users":",".join(sorted(users)),"src_ips":",".join(sorted(ips)),"src_ip_displays":",".join(sorted({x.src_ip_display or x.src_ip for x in bucket if x.src_ip})),"ip_context_displays":",".join(sorted({x.ip_context_display or x.src_ip for x in bucket if x.src_ip})),"auth_methods":",".join(sorted(methods)),"high_priv_users":",".join(hp),"success_count":len(bucket),"insight":"|".join(insights),"risk_score":score,"risk_level":level,"risk_reasons":"|".join(reasons),"raw_examples":" || ".join(x.raw for x in bucket[:5])})
    rows_first=[]; seen_u=set(); seen_ip=set(); seen_pair=set(); seen_method=set()
    for e in sorted(success,key=lambda x:x.sort_ts):
        pair=(e.user,e.src_ip); method=(e.user,e.auth_method); flags=[]
        if e.user not in seen_u: flags.append("first_success_for_user"); seen_u.add(e.user)
        if e.src_ip not in seen_ip: flags.append("first_success_from_ip"); seen_ip.add(e.src_ip)
        if pair not in seen_pair: flags.append("first_success_for_user_ip_pair"); seen_pair.add(pair)
        if method not in seen_method: flags.append("first_success_for_user_auth_method"); seen_method.add(method)
        if flags: rows_first.append({"timestamp":e.timestamp,"timestamp_us_format":fmt_us(e.timestamp),"host":e.host,"user":e.user or "","src_ip":e.src_ip or "","src_ip_display":e.src_ip_display or e.src_ip or "","ip_context_display":e.ip_context_display or e.src_ip or "","ip_scope":e.ip_scope or ip_scope(e.src_ip),"auth_method":e.auth_method or "unknown","first_seen_flags":",".join(flags),"raw":e.raw})
    return {"auth_success_by_method.csv":rows_method,"high_priv_user_access.csv":rows_high,"login_patterns_by_user.csv":rows_user,"login_patterns_by_ip.csv":rows_ip,"near_login_events.csv":rows_near,"auth_method_transitions.csv":[],"first_seen_logins.csv":rows_first}

def lifecycle_index(ind): return {str(r.get("user")):{str(k):str(v) for k,v in r.items()} for r in ind.get("account_lifecycle.csv",[]) if r.get("user")}
def active_days(evs): return len({parse_dt(e.timestamp).date().isoformat() for e in evs})
def hour_distribution(evs):
    c=Counter(parse_dt(e.timestamp).hour for e in evs); return ",".join(f"{h:02d}:{c[h]}" for h in sorted(c))

def token_re(user): return re.compile(rf"(?<![A-Za-z0-9_.-]){re.escape(user)}(?![A-Za-z0-9_.-])")
def user_universe(events):
    users=set()
    for e in events:
        for u in [e.user,e.actor_user,e.target_user,e.run_as]:
            if u and u not in {"UNKNOWN","none"}: users.add(u)
    return sorted(users)
def matched_fields(e,u):
    fs=[]
    if not e: return fs
    for f in ["user","actor_user","target_user","run_as"]:
        if getattr(e,f,None)==u: fs.append(f)
    if e.command and token_re(u).search(e.command): fs.append("command")
    return fs

def build_user_events(case,users,raws,events,mode="off"):
    d=case/"user_events"; d.mkdir(exist_ok=True); stats={}
    if mode=="off": return stats
    if mode=="parsed":
        byuser=defaultdict(list)
        for e in events:
            related={x for x in [e.user,e.actor_user,e.target_user,e.run_as] if x}
            for u in related: byuser[u].append(e)
            # command matching is intentionally omitted in fast parsed mode for performance.
        for u in sorted(set(users) | set(byuser)):
            rows=[]; logs=[]
            for e in sorted(byuser.get(u,[]), key=lambda x:x.sort_ts):
                mf=",".join(matched_fields(e,u)) or "parsed_related"
                row={"timestamp":e.timestamp,"host":e.host,"process":e.process or "","pid":e.pid or "","event_type":e.event_type,"severity":e.severity,"matched_user":u,"matched_field":mf,"actor_user":e.actor_user or "","user":e.user or "","target_user":e.target_user or "","run_as":e.run_as or "","src_ip":e.src_ip or "","src_ip_display":e.src_ip_display or "","ip_context_display":e.ip_context_display or "","ip_scope":e.ip_scope or "","auth_method":e.auth_method or "","command":e.command or "","raw":e.raw}
                rows.append(row); logs.append(e.raw)
            write_csv(d/f"{safe(u)}.events.csv",rows,delimiter=";"); (d/f"{safe(u)}.events.log").write_text("\n".join(logs)+("\n" if logs else ""),encoding="utf-8")
            stats[u]={"total":len(rows),"parsed":len(rows),"unparsed":0,"hosts":",".join(sorted({r["host"] for r in rows if r["host"]}))}
        return stats
    byraw={e.raw:e for e in events}
    for u in users:
        rx=token_re(u); rows=[]; logs=[]
        for rr in raws:
            if not rx.search(rr.raw): continue
            e=byraw.get(rr.raw); mf=",".join(matched_fields(e,u)) if e and matched_fields(e,u) else "raw_boundary"
            row={"timestamp":rr.timestamp,"host":rr.host,"process":rr.process,"pid":rr.pid,"event_type":e.event_type if e else "unparsed_user_related","severity":e.severity if e else "info","matched_user":u,"matched_field":mf,"actor_user":e.actor_user if e else "","user":e.user if e else "","target_user":e.target_user if e else "","run_as":e.run_as if e else "","src_ip":e.src_ip if e else "","src_ip_display":e.src_ip_display if e else "","ip_context_display":e.ip_context_display if e else "","ip_scope":e.ip_scope if e else "","auth_method":e.auth_method if e else "","command":e.command if e else "","raw":rr.raw}
            rows.append(row); logs.append(rr.raw)
        write_csv(d/f"{safe(u)}.events.csv",rows,delimiter=";"); (d/f"{safe(u)}.events.log").write_text("\n".join(logs)+("\n" if logs else ""),encoding="utf-8")
        stats[u]={"total":len(rows),"parsed":sum(1 for r in rows if r["event_type"]!="unparsed_user_related"),"unparsed":sum(1 for r in rows if r["event_type"]=="unparsed_user_related"),"hosts":",".join(sorted({r["host"] for r in rows if r["host"]}))}
    return stats

def mkdirs(case):
    for d in "raw indicators behavior ip user user_events alerts mitre enrichment".split(): (case/d).mkdir(parents=True,exist_ok=True)
def write_list(path,items):
    xs=sorted(set(items)); path.write_text("\n".join(xs)+("\n" if xs else ""),encoding="utf-8")
def write_csv(path,rows,fields=None,delimiter=","):
    if fields is None:
        fields=[]
        for r in rows:
            for k in r.keys():
                if k not in fields: fields.append(k)
    with path.open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=fields,delimiter=delimiter); w.writeheader()
        for r in rows: w.writerow({k:r.get(k,"") for k in fields})
def evline(e):
    bits=[f"[{e.timestamp}]",f"host={e.host}",e.event_type]
    for k in ["severity","process","pid","actor_user","user","target_user","src_ip_display","ip_context_display","ip_scope","auth_method","group","command"]:
        v=getattr(e,k,None)
        if v and not (k=="severity" and v=="info"): bits.append(f"{k}={v}")
    return " | ".join(bits)
def ip_score(ip,events):
    evs=[e for e in events if e.src_ip==ip]; fails=[e for e in evs if e.event_type in {"ssh_login_failed","ssh_invalid_user","ssh_pam_auth_failure"}]; score=0; reasons=[]
    if len(fails)>=10: score+=10; reasons.append(f"failed SSH/PAM attempts >=10 ({len(fails)})")
    if any(e.event_type.startswith("ssh_login_success") for e in evs): score+=20; reasons.append("successful SSH login observed")
    vt=max([e.vt_total_malicious_suspicious or 0 for e in evs] or [0])
    if vt>=3: score+=25; reasons.append(f"VT malicious/suspicious total >=3 ({vt})")
    elif vt>=1: score+=10; reasons.append(f"VT malicious/suspicious total >=1 ({vt})")
    return score,reasons

def navigation_text(mode, join_vt):
    return f"""Investigation Navigation
========================

Core files:
- Full parsed timeline: `timeline.csv`
- Parsed raw events JSONL: `raw/events.jsonl`
- Source files processed: `raw/source_files.txt`
- Output guide: `README_OUTPUT.md`

Entity reports:
- Per-IP reports: `ip/<src_ip>.txt`
- Per-user summary reports: `user/<username>.txt`
- User events mode: `{mode}`
- VT context join: `{join_vt}`

Key tables:
- Successful login per IP: `indicators/success_login_by_ip.csv`
- Failed password/PAM per user: `indicators/failed_password_by_user.csv`
- Near login behavior: `behavior/near_login_events.csv`
- High privilege access: `behavior/high_priv_user_access.csv`
- VirusTotal enrichment: `indicators/vt_ip_enrichment.csv`
"""
def readme_output_text(mode, join_vt):
    return f"""# ChronoIR Output Guide

Generated by ChronoIR v{VERSION}.

## Performance defaults

- User events mode: `{mode}`
- VT context join: `{join_vt}`

Default v0.5.6 is intentionally fast:

- `--user-events-mode off` by default.
- VT enrichment is written to `indicators/vt_ip_enrichment.csv` by default, but VT context is not joined into every event unless `--join-vt-context` is used.
- Raw grep-like user timelines are available only with `--user-events-mode raw` or `--raw-user-events`.

## Recommended raw review

For complete raw manual review, use the original logs listed in `raw/source_files.txt` with EmEditor, grep, ripgrep, lnav, or similar tools.
"""

def write_reports(case,files,raws,events,alerts,pub,priv,vt_rows,indicators,behavior,user_stats,user_events_mode,join_vt):
    with (case/"raw"/"events.jsonl").open("w",encoding="utf-8") as f:
        for e in events: f.write(json.dumps(e.json(),ensure_ascii=False)+"\n")
    timeline_fields="timestamp host source_file event_type category severity outcome actor_user user target_user src_ip src_ip_display ip_context_display src_ip_name src_ip_role src_ip_owner vt_country vt_organization vt_malicious vt_suspicious vt_total_malicious_suspicious vt_status src_port ip_scope process pid service auth_method key_type key_fingerprint tty pwd run_as command group uid gid home shell raw".split()
    write_csv(case/"timeline.csv",[{k:getattr(e,k,"") for k in timeline_fields} for e in events],timeline_fields)
    (case/"raw"/"source_files.txt").write_text("\n".join(map(str,files))+"\n",encoding="utf-8")
    for name,rows in indicators.items(): write_csv(case/"indicators"/name,rows,delimiter=";")
    for name,rows in behavior.items(): write_csv(case/"behavior"/name,rows,delimiter=";")
    vt_fields="ip country organization malicious suspicious total_malicious_suspicious malicious_suspicious_sources vt_status http_code error".split(); vt_out=[{k:vt_rows[ip].get(k,"") for k in vt_fields} for ip in sorted(vt_rows)]
    for ip in priv: vt_out.append({"ip":ip,"country":"PRIVATE","organization":"PRIVATE","malicious":0,"suspicious":0,"total_malicious_suspicious":0,"malicious_suspicious_sources":"NONE","vt_status":"PRIVATE_SKIPPED","http_code":"SKIPPED","error":"private_or_non_global_ip"})
    write_csv(case/"indicators"/"vt_ip_enrichment.csv",vt_out,vt_fields,";")
    byip=defaultdict(list)
    for e in events:
        if e.src_ip: byip[e.src_ip].append(e)
    for ip,evs in byip.items():
        evs=sorted(evs,key=lambda e:e.sort_ts); score,reasons=ip_score(ip,events); ok=[e for e in evs if e.event_type.startswith("ssh_login_success")]; fails=[e for e in evs if e.event_type in {"ssh_login_failed","ssh_pam_auth_failure","ssh_invalid_user"}]; e0=evs[0]
        lines=[f"IP Report: {e0.src_ip_display or ip}","="*(11+len(ip)),"",f"Source IP: {ip}",f"IP Context: {e0.ip_context_display or ip}",f"IP Scope: {ip_scope(ip)}",f"Hosts Observed: {hosts_join(evs)}","","VirusTotal Context:",f"- VT status: {e0.vt_status or ''}",f"- Country: {e0.vt_country or 'UNKNOWN'}",f"- Organization: {e0.vt_organization or 'UNKNOWN'}",f"- Malicious: {e0.vt_malicious or 0}",f"- Suspicious: {e0.vt_suspicious or 0}",f"- Total malicious/suspicious: {e0.vt_total_malicious_suspicious or 0}","",f"Risk: {score_sev(score).upper()} ({score})","","Pointers:","- Source table: `indicators/success_login_by_ip.csv`","- VT table: `indicators/vt_ip_enrichment.csv`","- Global timeline: `timeline.csv`","","Successful Login Summary:",f"- Success count: {len(ok)}",f"- First success: {first_ts(ok)}",f"- Last success : {last_ts(ok)}",f"- Last success US format: {fmt_us(last_ts(ok))}","","Failed Auth Summary:",f"- Failed attempts: {len(fails)}",f"- First failed: {first_ts(fails)}",f"- Last failed : {last_ts(fails)}","","Risk Reasons:"] + [f"- {x}" for x in (reasons or ["No major risk reason scored."])] + ["","Timeline:"] + [evline(e) for e in evs[:500]]
        (case/"ip"/f"{ip}.txt").write_text("\n".join(lines)+"\n",encoding="utf-8")
    life=lifecycle_index(indicators); byu=defaultdict(list)
    for e in events:
        for u in {e.user,e.actor_user,e.target_user,e.run_as}:
            if u: byu[u].append(e)
    for u in sorted(set(list(byu.keys())+list(user_stats.keys()))):
        evs=sorted(byu.get(u,[]),key=lambda e:e.sort_ts); st=user_stats.get(u,{"total":0,"parsed":0,"unparsed":0,"hosts":""}); ok=[e for e in evs if e.event_type.startswith("ssh_login_success") and e.user==u]; fails=[e for e in evs if e.event_type in {"ssh_login_failed","ssh_pam_auth_failure"} and (e.user or e.target_user)==u]; hp,reason=is_high_priv_user(u,life); methods=Counter(e.auth_method or "unknown" for e in ok)
        lines=[f"User Report: {u}","="*(13+len(u)),"",f"Sensitive/High Privilege Heuristic: {'YES' if hp else 'NO'} {reason}",f"Hosts Observed: {st.get('hosts') or hosts_join(evs)}",f"User Events Mode: {user_events_mode}",f"Total related events in user_events: {st.get('total',0)}",f"Parsed related events: {st.get('parsed',0)}",f"Unparsed raw-boundary events: {st.get('unparsed',0)}","","Pointers:",f"- User events timeline: `user_events/{safe(u)}.events.csv`",f"- User events raw lines: `user_events/{safe(u)}.events.log`","- Global parsed timeline: `timeline.csv`","- Original raw logs: see `raw/source_files.txt`","","Successful Login Summary:",f"- Success count: {len(ok)}",f"- Auth methods: {', '.join(f'{k}:{v}' for k,v in methods.most_common()) if methods else 'NONE'}",f"- First success: {first_ts(ok)}",f"- Last success : {last_ts(ok)}","","Failed Auth Summary:",f"- Failed attempts: {len(fails)}","","Important Parsed Timeline:"] + [evline(e) for e in evs[:300]]
        (case/"user"/f"{safe(u)}.txt").write_text("\n".join(lines)+"\n",encoding="utf-8")
    (case/"alerts"/"alerts.json").write_text(json.dumps([a.json() for a in alerts],indent=2,ensure_ascii=False),encoding="utf-8")
    (case/"alerts"/"alerts.md").write_text("Alerts\n======\n\n"+"\n".join(f"- {a.severity.upper()} {a.name}: {a.description}" for a in alerts)+"\n",encoding="utf-8")
    mc=Counter()
    for e in events:
        for m in e.mitre: mc[f"{m['technique_id']} {m['technique']}"]+=1
    (case/"mitre"/"attack_matrix.md").write_text("MITRE ATT&CK Mapping\n====================\n\n"+"\n".join(f"- {k}: {v}" for k,v in mc.most_common())+"\n",encoding="utf-8")
    (case/"README_OUTPUT.md").write_text(readme_output_text(user_events_mode,join_vt),encoding="utf-8")
    host_rows=hostlog_summary(events,raws); cnt=Counter(e.event_type for e in events); near=behavior.get("near_login_events.csv",[]); hp=behavior.get("high_priv_user_access.csv",[]); top_ips=indicators.get("success_login_by_ip.csv",[])[:10]; top_failed=indicators.get("failed_password_by_user.csv",[])[:10]
    vt_hits=[r for r in vt_out if int(r.get("total_malicious_suspicious") or 0)>0]
    sm=[f"Case Summary: {case.name}","="*(14+len(case.name)),"",f"Tool Version: {VERSION}","",navigation_text(user_events_mode,join_vt),"Processed Files:"]+[f"- {x}" for x in files]+["","Host Logs Observed:","Source tables: `timeline.csv`, `raw/source_files.txt`"]+[f"- {r['host']}: {r['parsed_events']} parsed event(s), {r['raw_lines']} raw syslog line(s)" for r in host_rows]+["","Totals:",f"- Parsed events: {len(events)}",f"- Raw syslog lines observed: {len(raws)}",f"- User events mode: {user_events_mode}",f"- VT context join: {join_vt}",f"- Alerts: {len(alerts)}",f"- Public IPs: {len(pub)}",f"- Private/non-global IPs: {len(priv)}",f"- High privilege access events: {len(hp)}",f"- Near login behavior findings: {len(near)}","","VirusTotal Signals:","Source table: `indicators/vt_ip_enrichment.csv`","Note: VT is context only, not proof of maliciousness."]
    sm += ([f"- {r['ip']}: total={r['total_malicious_suspicious']} org={r['organization']} country={r['country']} status={r['vt_status']}" for r in vt_hits[:10]] or ["- No malicious/suspicious VT hits or VT not run."])
    sm += ["","Top Event Types:","Source table: `timeline.csv`"]+[f"- {k}: {v}" for k,v in cnt.most_common(20)]
    sm += ["","Top Failed Password/PAM Users:","Source table: `indicators/failed_password_by_user.csv`","Detail: `user/<username>.txt`, `user_events/<username>.events.csv`"] + ([f"- {r['user']}: {r['failed_count']} failed, hosts={r.get('hosts','')}, success={r['successful_login_count']}" for r in top_failed] or ["- NONE"])
    sm += ["","Top Successful Login IPs:","Source table: `indicators/success_login_by_ip.csv`","Detail: `ip/<src_ip>.txt`"] + ([f"- {r['ip_context_display']}: success={r['success_count']}, hosts={r.get('hosts','')}, methods={r.get('auth_methods','')}, last_success={r['last_success_us_format']}" for r in top_ips] or ["- NONE"])
    sm += ["","High Privilege Access Samples:","Source table: `behavior/high_priv_user_access.csv`","Detail: `user/<username>.txt`, `ip/<src_ip>.txt`"] + ([f"- {r['timestamp']} host={r.get('host','')} user={r['user']} ip={r.get('ip_context_display',r.get('src_ip',''))} method={r['auth_method']} reason={r['reason']}" for r in hp[:10]] or ["- NONE"])
    sm += ["","Near Login Findings:","Source table: `behavior/near_login_events.csv`","Detail: `ip/<src_ip>.txt`, `timeline.csv`","Note: risk is heuristic and should be validated with environment context."] + ([f"- {r['window_start']}..{r['window_end']} risk={r.get('risk_level','')} score={r.get('risk_score','')} hosts={r.get('hosts','')} insight={r['insight']} users={r['users']} ips={r.get('ip_context_displays',r.get('src_ip_displays',''))}" for r in near[:10]] or ["- NONE"])
    sm += ["","Notes:","- `host` is the syslog/logging host, not necessarily the remote source IP.","- PID is preserved in `timeline.csv` and optional `user_events/*.events.csv` for process/session correlation.","- v0.5.6 default is fast: `--user-events-mode off` and VT context join disabled.","- Use `--user-events-mode parsed` for fast parsed user timelines.","- Use `--user-events-mode raw` only for deep grep-like raw user timelines; it can be slow and large.","- For complete raw manual review, use original logs listed in `raw/source_files.txt`.","- `--hostipdb` and VirusTotal enrich IP context but never replace the original `src_ip`."]
    (case/"summary.md").write_text("\n".join(sm)+"\n",encoding="utf-8")

def run_analyze(args):
    inp=Path(args.input).expanduser(); case=Path(args.case).expanduser(); mkdirs(case); files=discover(inp)
    if not files: print(f"❌ No supported auth log files found in {inp}",file=sys.stderr); sys.exit(1)
    if args.fast:
        args.no_vt=True; args.user_events_mode="off"; args.no_near_login=True; args.join_vt_context=False
    mode="raw" if args.raw_user_events else args.user_events_mode
    t0=time.time(); print("[*] Stage: parse logs", file=sys.stderr, flush=True); events,raws=parse_files(files,args.year); t_parse=time.time()
    ips=extract_ips(events); pub,priv=split_ips(ips); hostdb=load_hostipdb(args.hostipdb)
    print("[*] Stage: VT/context", file=sys.stderr, flush=True)
    vt_rows={}; key=Path(args.vt_key_file).expanduser()
    if args.no_vt: print("[*] VirusTotal enrichment disabled by --no-vt",file=sys.stderr,flush=True)
    elif key.exists(): vt_rows=vt_enrich(pub,case,key,args.vt_sleep,not args.no_cache)
    else: print(f"[*] VirusTotal API key file tidak ditemukan ({key}); VT enrichment dilewati.",file=sys.stderr,flush=True)
    apply_context(events,hostdb,vt_rows,args.join_vt_context); t_context=time.time()
    print("[*] Stage: indicators and behavior", file=sys.stderr, flush=True)
    alerts=detect(events); indicators=build_indicator_tables(events); behavior=behavior_tables(events,indicators,args.near_minutes,args.no_near_login); users=user_universe(events); t_tables=time.time()
    print(f"[*] Stage: user_events mode={mode}", file=sys.stderr, flush=True)
    user_stats=build_user_events(case,users,raws,events,mode); t_users=time.time()
    print("[*] Stage: write reports", file=sys.stderr, flush=True)
    write_list(case/"indicators"/"all_ips.txt",ips); write_list(case/"indicators"/"public_ips.txt",pub); write_list(case/"indicators"/"private_ips.txt",priv)
    write_reports(case,files,raws,events,alerts,pub,priv,vt_rows,indicators,behavior,user_stats,mode,args.join_vt_context); t_reports=time.time()
    print(f"✅ Done. Case output: {case}"); print(f"   Tool version: {VERSION}"); print(f"   Parsed events: {len(events)}"); print(f"   Raw syslog lines observed: {len(raws)}"); print(f"   Hosts: {len({e.host for e in events})}"); print(f"   User events mode: {mode}"); print(f"   VT context join: {args.join_vt_context}"); print(f"   User evidence files: {len(user_stats)}")
    print(f"   Timing: parse={t_parse-t0:.2f}s context={t_context-t_parse:.2f}s tables={t_tables-t_context:.2f}s user_events={t_users-t_tables:.2f}s reports={t_reports-t_users:.2f}s total={t_reports-t0:.2f}s")

def build_parser():
    desc = f"""ChronoIR AuthLog Analyzer v{VERSION}

Default usage:
  python3 chronoir.py /var/log
  python3 chronoir.py /var/log --year 2026
  python3 chronoir.py /var/log --fast
  python3 chronoir.py /var/log --no-vt
  python3 chronoir.py /var/log --hostipdb hostipdb.csv
  python3 chronoir.py /var/log --user-events-mode parsed
  python3 chronoir.py /var/log --user-events-mode raw

Backward compatible:
  python3 chronoir.py analyze /var/log

Defaults in v0.5.6:
  - user_events mode: off
  - VT context join: off
  - host/log-host context: on
  - VT enrichment table: auto if API key file exists, unless --no-vt
"""
    epilog = """Examples:
  Fast triage:
    python3 chronoir.py /var/log --fast

  Normal parse without VT:
    python3 chronoir.py /var/log --year 2026 --no-vt

  Add host/IP context:
    python3 chronoir.py /var/log --hostipdb hostipdb.csv

  Generate parsed user_events:
    python3 chronoir.py /var/log --user-events-mode parsed

  Deep raw user_events, can be slow/large:
    python3 chronoir.py /var/log --user-events-mode raw
"""
    p=argparse.ArgumentParser(description=desc, epilog=epilog, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("input", help="Path to auth.log/auth.log.gz/secure file or folder, e.g. /var/log or ./evidence/var/log")
    p.add_argument("--case", default=DEFAULT_CASE_DIR, help=f"Output case directory. Default: {DEFAULT_CASE_DIR}")
    p.add_argument("--year", type=int, default=datetime.now().year, help="Year for syslog/auth.log timestamps without year. Example: --year 2026")
    p.add_argument("--hostipdb", default=None, help="CSV/whitespace file mapping source IP to hostname/role/owner/notes")
    p.add_argument("--vt-key-file", default=DEFAULT_VT_KEY_FILE, help=f"VirusTotal API key file. Default: {DEFAULT_VT_KEY_FILE}")
    p.add_argument("--no-vt", action="store_true", help="Disable VirusTotal enrichment even if API key exists")
    p.add_argument("--vt-sleep", type=int, default=16, help="Sleep seconds between VT API calls. Default: 16")
    p.add_argument("--no-cache", action="store_true", help="Do not use cached VT responses")
    p.add_argument("--join-vt-context", action="store_true", help="Join VT context into timeline/key tables. Default off for speed")
    p.add_argument("--near-minutes", type=int, default=10, help="Window minutes for near-login analytics. Default: 10")
    p.add_argument("--no-near-login", action="store_true", help="Skip near-login analytics for faster processing")
    p.add_argument("--user-events-mode", choices=["off","parsed","raw"], default="off", help="user_events mode. off=default/fast, parsed=parsed events only, raw=grep-like raw mode and can be slow/large")
    p.add_argument("--raw-user-events", action="store_true", help="Alias for --user-events-mode raw; can be slow and large")
    p.add_argument("--fast", action="store_true", help="Fast triage mode: --no-vt --user-events-mode off --no-near-login and no VT join")
    p.add_argument("--version", action="version", version=f"ChronoIR AuthLog Analyzer v{VERSION}")
    p.set_defaults(func=run_analyze)
    return p

def main():
    if len(sys.argv)>1 and sys.argv[1]=="analyze":
        del sys.argv[1]
    parser=build_parser()
    args=parser.parse_args()
    args.func(args)

if __name__=="__main__": main()
