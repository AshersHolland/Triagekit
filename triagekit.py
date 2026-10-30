#!/usr/bin/env python3
"""
TRIAGEKIT - sourced, explainable triage of extracted digital evidence.

WHAT IT DOES
  Walks a folder of extracted evidence (read-only), hashes every file, and ranks
  what an examiner should look at first. Wherever possible the rating comes from
  a published source rather than from this tool:

    Sigma rules (SigmaHQ)        priority taken from the rule's own `level`
    CISA KEV catalog             CVE references; raises CVE-tagged detections one step
    Indicator feeds              hash / IP / URL / domain matches (abuse.ch, CISA/FBI
                                 advisory indicators, MISP exports, ...)
    NIST NSRL or any known-      lowers the priority of matched files one step
    software hash set            (known software is NOT the same as safe)
    MITRE ATT&CK                 technique labels only (ATT&CK assigns no severity)
    Local rules                  fill gaps; always labelled LOCAL in every output

  Priorities are TRIAGE PRIORITIES (info < low < medium < high): an order in which
  to review, never a conclusion. Every finding states the rule, the source that
  rated it, the reason, the innocent explanations to rule out, and the evidence
  (path, state, inode, SHA-256, line numbers). Correlation rules may raise a
  priority by ONE step, only when their requirements are met, and show the chain.

  Same evidence + same rules + same feeds + same version = same findings.json
  (its SHA-256 is printed in the report as the result digest).

USAGE
  triagekit.py scan EVIDENCE_DIR [EVIDENCE_DIR ...] -o OUT [-c triage.toml] [--force]
  triagekit.py scan --tracekit CASE_DIR -o OUT [-c triage.toml]
  triagekit.py review OUT FINDING_ID {confirmed,dismissed,needs-followup,unreviewed} [--note TEXT] [--examiner NAME]
  triagekit.py report OUT
  triagekit.py rules [-c triage.toml] [--verbose]
  triagekit.py fetch [--dest feeds]

Requires Python 3.11+ (standard library only). Loading Sigma rules additionally
requires PyYAML (pip install pyyaml).
"""
import argparse, collections, csv, datetime as dt, fnmatch, hashlib, ipaddress, json, os
import platform, re, shutil, sqlite3, sys, urllib.request

__version__ = "0.1.0"

try:
    import tomllib
except ImportError:                                   # Python < 3.11
    try:
        import tomli as tomllib
    except ImportError:
        sys.exit("triagekit needs Python 3.11+ (or `pip install tomli` on older versions).")

HERE = os.path.dirname(os.path.abspath(__file__))
PRIORITIES = ("info", "low", "medium", "high")
PRANK = {p: i for i, p in enumerate(PRIORITIES)}
SIGMA_LEVEL = {"informational": "info", "low": "low", "medium": "medium", "high": "high", "critical": "high"}
STATUSES = ("unreviewed", "confirmed", "dismissed", "needs-followup")

IP_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.]*\d)")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>`]+", re.I)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b")
HEX_RE = {32: "md5", 40: "sha1", 64: "sha256"}
ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}")
SYS_RE = re.compile(r"\b([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\b")
MONTHS = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}
KV_RE = re.compile(r"(?<![\w.-])([A-Za-z_][\w.-]*)=(?:\"([^\"]*)\"|'([^']*)'|(\S+))")
USER_RES = [re.compile(r"(?:^|\s)([A-Za-z_][\w.-]*)\s*:\s*TTY="),          # sudo
            re.compile(r"\bfor (?:invalid user )?([\w.-]+) from\b"),      # sshd
            re.compile(r"\bacct=\"?([\w.@-]+)"),                          # auditd
            re.compile(r"\buser[= ]\"?([\w.@-]+)", re.I)]
HOME_RE = re.compile(r"^/(?:home|Users)/([^/]+)/|^/(root)/")

SIGMA_SERVICES = {                                      # Sigma logsource service -> log file names
    "auth": r"/(auth\.log|secure)(\.\d+)?$", "sshd": r"/(auth\.log|secure)(\.\d+)?$",
    "sudo": r"/(auth\.log|secure|sudo\.log)(\.\d+)?$", "syslog": r"/(syslog|messages)(\.\d+)?$",
    "auditd": r"/audit\.log(\.\d+)?$", "cron": r"/(cron|syslog|messages)(\.log)?(\.\d+)?$",
    "vsftpd": r"/vsftpd\.log(\.\d+)?$", "clamav": r"/(clamav|clamd|freshclam)[^/]*$",
    "guacamole": r"/(guacamole|guacd)[^/]*$"}

FEEDS = {"cisa_kev.json": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
         "enterprise-attack.json": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
                                   "enterprise-attack/enterprise-attack.json"}

DEFAULTS = {
    "case": {"name": "", "examiner": ""},
    "sources": {"local_rules": [], "sigma": [], "kev": "", "attack": "", "known_software": [], "ioc": []},
    "scan": {"log_path_regex": r"(^/var/log/|\.log(\.\d+)?$|/\.?[a-z]*sh_history$|/\.history$)",
             "syslog_year": dt.date.today().year, "max_samples": 5, "kev_mention_priority": "low",
             "kev_exclude_regex": r"^/usr/share/(doc|man|info|common-licenses)/|/changelog[^/]*$|/NEWS[^/]*$"},
    "thresholds": {"large_archive_bytes": 50_000_000, "failed_login_burst": 5},
    "allow": {"ips": [], "users": [], "paths": [], "hashes": []},
    "override": {},
}


class ConfigError(Exception):
    pass


class Unsupported(Exception):
    pass


# ------------------------------------------------------------------ helpers
def now_utc():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def sha256_tree(paths):
    """One digest for a set of rule files: SHA-256 over sorted 'relative-path  file-sha256' lines."""
    h = hashlib.sha256()
    for p in sorted(paths):
        h.update(("%s  %s\n" % (os.path.basename(p), sha256_file(p))).encode())
    return h.hexdigest()

def raise_one(p):
    return PRIORITIES[min(PRANK[p] + 1, len(PRIORITIES) - 1)]

def lower_one(p):
    return PRIORITIES[max(PRANK[p] - 1, 0)]

def parse_ts(line, year):
    m = ISO_RE.search(line)
    if m:
        return m.group(0).replace("T", " ")
    m = SYS_RE.search(line)
    if m and m.group(1) in MONTHS:
        return "%04d-%02d-%02d %s" % (year, MONTHS[m.group(1)], int(m.group(2)), m.group(3))
    return None

def parse_window(s):
    m = re.fullmatch(r"\s*(\d+)\s*([smhd])\s*", str(s))
    if not m:
        raise ConfigError("bad window %r (use e.g. 30m, 2h, 1d)" % s)
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]

def users_in(line, path):
    out = set()
    for rx in USER_RES:
        m = rx.search(line)
        if m:
            out.add(m.group(1))
            break
    h = HOME_RE.match(path)
    if h:
        out.add(h.group(1) or h.group(2))
    return out

def files_under(p, exts):
    if os.path.isfile(p):
        return [p]
    out = []
    for dp, dns, fns in os.walk(p):
        dns.sort()
        for fn in sorted(fns):
            if fn.lower().endswith(exts):
                out.append(os.path.join(dp, fn))
    return out

def md_escape(x):
    return str(x).replace("|", "\\|").replace("\n", " ").replace("`", "'")

def md_table(heads, rows):
    out = ["| " + " | ".join(heads) + " |", "|" + "---|" * len(heads)]
    for r in rows:
        out.append("| " + " | ".join(md_escape(c) for c in r) + " |")
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------- config
def load_config(path):
    cfg = json.loads(json.dumps(DEFAULTS))
    base = os.getcwd()
    if path:
        base = os.path.dirname(os.path.abspath(path))
        with open(path, "rb") as f:
            user = tomllib.load(f)
        for k, v in user.items():
            if k not in cfg:
                raise ConfigError("unknown section [%s] in %s" % (k, path))
            if isinstance(v, dict) and k != "override":
                for kk in v:
                    if k in ("case", "sources", "scan", "allow") and kk not in cfg[k]:
                        raise ConfigError("unknown key %s.%s in %s" % (k, kk, path))
                cfg[k].update(v)
            else:
                cfg[k] = v
    elif os.path.isdir(os.path.join(HERE, "rules")):
        cfg["sources"]["local_rules"] = [os.path.join(HERE, "rules")]
    src = cfg["sources"]
    absol = lambda p: p if not p or os.path.isabs(p) else os.path.normpath(os.path.join(base, p))
    for k in ("local_rules", "sigma", "known_software"):
        if isinstance(src[k], str):
            src[k] = [src[k]] if src[k] else []
        src[k] = [absol(p) for p in src[k]]
    src["kev"], src["attack"] = absol(src["kev"]), absol(src["attack"])
    for feed in src["ioc"]:
        for req in ("name", "org", "path"):
            if req not in feed:
                raise ConfigError("every [[sources.ioc]] needs name, org and path (missing %s)" % req)
        feed["path"] = absol(feed["path"])
        feed.setdefault("priority", "high")
        feed.setdefault("types", ["md5", "sha1", "sha256", "ip", "url"])
        feed.setdefault("snapshot_date", "")
        if feed["priority"] not in PRIORITIES:
            raise ConfigError("IOC feed %s: priority must be one of %s" % (feed["name"], PRIORITIES))
    for rid, ov in cfg["override"].items():
        if "priority" in ov and ov["priority"] not in PRIORITIES:
            raise ConfigError("override %s: priority must be one of %s" % (rid, PRIORITIES))
    cfg["_path"] = os.path.abspath(path) if path else ""
    return cfg


# -------------------------------------------------------------- local rules
FILE_KEYS = {"path_regex", "not_path_regex", "name_regex", "content_regex", "executable", "size_gt", "size_lt",
             "state", "any_of"}
LINE_KEYS = {"path_regex", "not_path_regex", "line_regex", "not_line_regex", "state", "any_of"}
RULE_KEYS = {"id", "title", "priority", "target", "reason", "false_positives", "attack", "references", "match",
             "min_hits", "enabled"}
CORR_KEYS = {"id", "title", "scope", "requires", "min_artifacts", "min_sources", "window", "reason", "enabled"}

def resolve(v, cfg):
    if isinstance(v, str) and v.startswith("${thresholds.") and v.endswith("}"):
        k = v[len("${thresholds."):-1]
        if k not in cfg["thresholds"]:
            raise ConfigError("threshold %r is not defined in [thresholds]" % k)
        return cfg["thresholds"][k]
    return v

def compile_cond(d, target, cfg, content_pool, where, top=True):
    allowed = FILE_KEYS if target == "file" else LINE_KEYS
    if not top:
        allowed = allowed - {"any_of"} if target == "file" else {"line_regex", "not_line_regex"}
    bad = set(d) - allowed
    if bad:
        raise ConfigError("%s: unknown match key(s) %s for target=%s" % (where, sorted(bad), target))
    c = {}
    for k, v in d.items():
        v = resolve(v, cfg)
        try:
            if k in ("path_regex", "not_path_regex", "name_regex", "line_regex", "not_line_regex"):
                c[k] = re.compile(v, re.I if k in ("line_regex", "not_line_regex", "name_regex") else 0)
            elif k == "content_regex":
                rx = re.compile(v, re.I)
                c[k] = content_pool.setdefault(v, (len(content_pool), rx))[0]
            elif k in ("size_gt", "size_lt"):
                c[k] = int(v)
            elif k == "executable":
                c[k] = bool(v)
            elif k == "state":
                c[k] = str(v)
            elif k == "any_of":
                c[k] = [compile_cond(x, target, cfg, content_pool, where, top=False) for x in v]
        except re.error as e:
            raise ConfigError("%s: bad regex in %s: %s" % (where, k, e))
    return c

def load_local(paths, cfg):
    rules, corrs, files, content_pool, seen = [], [], [], {}, set()
    for p in paths:
        if not os.path.exists(p):
            raise ConfigError("local rules path not found: %s" % p)
        files += files_under(p, (".toml",))
    for f in files:
        with open(f, "rb") as fh:
            doc = tomllib.load(fh)
        fsha = sha256_file(f)
        for r in doc.get("rule", []):
            where = "%s rule %s" % (os.path.basename(f), r.get("id", "?"))
            missing = {"id", "title", "priority", "target", "reason", "match"} - set(r)
            if missing:
                raise ConfigError("%s: missing %s" % (where, sorted(missing)))
            if set(r) - RULE_KEYS:
                raise ConfigError("%s: unknown key(s) %s" % (where, sorted(set(r) - RULE_KEYS)))
            if r["priority"] not in PRIORITIES or r["target"] not in ("file", "line"):
                raise ConfigError("%s: priority must be %s and target file|line" % (where, PRIORITIES))
            if r["id"] in seen:
                raise ConfigError("%s: duplicate rule id" % where)
            seen.add(r["id"])
            if not r.get("enabled", True):
                continue
            rules.append({"id": r["id"], "title": r["title"], "priority": r["priority"], "target": r["target"],
                          "reason": r["reason"], "false_positives": r.get("false_positives", ""),
                          "attack": [a.upper() for a in r.get("attack", [])], "references": r.get("references", []),
                          "min_hits": int(resolve(r.get("min_hits", 1), cfg)), "cves": [],
                          "match": compile_cond(r["match"], r["target"], cfg, content_pool, where),
                          "source": {"kind": "local", "org": "Local rule (examiner-defined)",
                                     "name": os.path.basename(f), "sha256": fsha}})
        for c in doc.get("correlate", []):
            where = "%s correlate %s" % (os.path.basename(f), c.get("id", "?"))
            missing = {"id", "title", "scope", "requires", "reason"} - set(c)
            if missing or set(c) - CORR_KEYS:
                raise ConfigError("%s: missing %s / unknown %s" % (where, sorted(missing), sorted(set(c) - CORR_KEYS)))
            if c["scope"] not in ("same_file", "same_ip", "same_user"):
                raise ConfigError("%s: scope must be same_file, same_ip or same_user" % where)
            if c["id"] in seen:
                raise ConfigError("%s: duplicate id" % where)
            seen.add(c["id"])
            req = c["requires"]
            if not (req.get("all") or req.get("any")):
                raise ConfigError("%s: requires needs `all` and/or `any`" % where)
            if not c.get("enabled", True):
                continue
            corrs.append({"id": c["id"], "title": c["title"], "scope": c["scope"], "reason": c["reason"],
                          "all": list(req.get("all", [])), "any": list(req.get("any", [])),
                          "min_artifacts": int(c.get("min_artifacts", 1)), "min_sources": int(c.get("min_sources", 1)),
                          "window": parse_window(c["window"]) if c.get("window") else None,
                          "source": {"kind": "correlation", "org": "Local correlation rule (examiner-defined)",
                                     "name": os.path.basename(f), "sha256": fsha}})
    pool = [None] * len(content_pool)
    for pat, (i, rx) in content_pool.items():
        pool[i] = rx
    return rules, corrs, files, pool


# -------------------------------------------------------------------- sigma
def wild_to_re(s):
    out, i = [], 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s) and s[i + 1] in "*?\\":
            out.append(re.escape(s[i + 1])); i += 2; continue
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    return "".join(out)

SIGMA_MODS = {"contains", "startswith", "endswith", "all", "re", "cidr", "exists"}

def _pattern(val, mods):
    """Sigma value -> (regex source, how to apply it). Case-insensitive, wildcards * and ?."""
    if isinstance(val, bool):
        val = str(val).lower()
    pat = wild_to_re(str(val))
    if "contains" in mods:
        # Outer wildcards add nothing to an unanchored search but cost quadratic backtracking.
        while pat.startswith(".*"):
            pat = pat[2:]
        while pat.endswith(".*") and not pat.endswith("\\.*"):
            pat = pat[:-2]
        return pat, "search"
    if "startswith" in mods:
        while pat.endswith(".*") and not pat.endswith("\\.*"):
            pat = pat[:-2]
        return pat, "match"
    if "endswith" in mods:
        while pat.startswith(".*"):
            pat = pat[2:]
        return "(?:%s)\\Z" % pat, "search"
    return pat, "fullmatch"

def value_matcher(val, mods):
    if "re" in mods:
        try:
            rx = re.compile(str(val))
        except re.error as e:
            raise Unsupported("regex not valid in Python: %s" % e)
        return lambda x: rx.search(x) is not None
    if "cidr" in mods:
        try:
            net = ipaddress.ip_network(str(val), strict=False)
        except ValueError:
            raise Unsupported("bad CIDR %r" % val)
        def cidr(x):
            try:
                return ipaddress.ip_address(x) in net
            except ValueError:
                return False
        return cidr
    pat, how = _pattern(val, mods)
    fn = getattr(re.compile(pat, re.I | re.S), how)
    return lambda x: fn(x) is not None

def any_matcher(vals, mods):
    """OR over several values. Plain string matching is folded into ONE regex for speed."""
    if "re" in mods or "cidr" in mods or len(vals) == 1:
        ms = [value_matcher(v, mods) for v in vals]
        return lambda x: any(m(x) for m in ms)
    parts = [_pattern(v, mods) for v in vals]
    how = parts[0][1]
    alt = "|".join("(?:%s)" % p for p, _ in parts)
    fn = getattr(re.compile(alt if how != "fullmatch" else "(?:%s)" % alt, re.I | re.S), how)
    return lambda x: fn(x) is not None

def compile_search(obj):
    if isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
        obj = [obj]
    if isinstance(obj, list) and obj and all(isinstance(x, (str, int, float)) for x in obj):
        m = any_matcher(obj, {"contains"})                           # keywords: anywhere on the line
        return lambda ev: m(ev.line), False
    if isinstance(obj, list) and obj and all(isinstance(x, dict) for x in obj):
        parts = [compile_map(x) for x in obj]
        return lambda ev: any(p(ev) for p in parts), True
    if isinstance(obj, dict):
        return compile_map(obj), True
    raise Unsupported("detection item of unsupported shape")

def compile_map(d):
    parts = []
    for key, val in d.items():
        field, *mods = str(key).split("|")
        mods = set(mods)
        unknown = mods - SIGMA_MODS
        if unknown:
            raise Unsupported("modifier(s) %s" % ",".join(sorted(unknown)))
        fld = field.lower()
        if "exists" in mods:
            want = bool(val)
            parts.append(lambda ev, f=fld, w=want: (f in ev.fields) == w)
            continue
        vals = val if isinstance(val, list) else [val]
        if any(isinstance(v, (dict, list)) for v in vals):
            raise Unsupported("nested value in field %s" % field)
        want_null = any(v is None for v in vals)
        vals = [v for v in vals if v is not None]
        if "all" in mods:
            ms = [value_matcher(v, mods) for v in vals]
            test = (lambda ms: lambda x: all(m(x) for m in ms))(ms)
        elif vals:
            test = any_matcher(vals, mods)
        else:
            test = None
        if not fld:                                                   # '|contains': [...] keyword map
            parts.append(lambda ev, t=test: t(ev.line) if t else False)
            continue
        def fm(ev, f=fld, t=test, null=want_null):
            v = ev.fields.get(f)
            if v is None or v == "":
                return null
            return t(v) if t else False
        parts.append(fm)
    return lambda ev: all(p(ev) for p in parts)

def compile_condition(cond, searches):
    if isinstance(cond, list):
        fns = [compile_condition(c, searches) for c in cond]
        return lambda ev: any(f(ev) for f in fns)
    cond = str(cond)
    if "|" in cond or re.search(r"\b(count|near|min|max|avg|sum)\s*\(", cond):
        raise Unsupported("aggregation/correlation condition")
    toks = re.findall(r"\(|\)|[^\s()]+", cond)
    pos = [0]
    peek = lambda: toks[pos[0]] if pos[0] < len(toks) else None
    def take():
        t = peek(); pos[0] += 1; return t
    def expr():
        left = term()
        while peek() == "or":
            take(); r = term(); left = (lambda a, b: lambda ev: a(ev) or b(ev))(left, r)
        return left
    def term():
        left = factor()
        while peek() == "and":
            take(); r = factor(); left = (lambda a, b: lambda ev: a(ev) and b(ev))(left, r)
        return left
    def factor():
        t = take()
        if t is None:
            raise Unsupported("incomplete condition")
        if t == "not":
            f = factor(); return lambda ev: not f(ev)
        if t == "(":
            e = expr()
            if take() != ")":
                raise Unsupported("unbalanced parentheses")
            return e
        if t in ("1", "all", "any") and peek() == "of":
            take(); target = take()
            if target == "them":
                names = [n for n in searches if not n.startswith("_")]
            else:
                names = [n for n in searches if fnmatch.fnmatchcase(n, target or "")]
            if not names:
                raise Unsupported("quantifier matches no detection names")
            fs = [searches[n] for n in names]
            return (lambda ev: all(f(ev) for f in fs)) if t == "all" else (lambda ev: any(f(ev) for f in fs))
        if t in searches:
            return searches[t]
        raise Unsupported("unknown identifier %r in condition" % t)
    fn = expr()
    if peek() is not None:
        raise Unsupported("trailing tokens in condition")
    return fn

class Event:
    __slots__ = ("line", "_f")
    def __init__(self, line):
        self.line, self._f = line, None
    @property
    def fields(self):
        if self._f is None:
            self._f = {}
            for m in KV_RE.finditer(self.line):
                k = m.group(1).lower()
                if k not in self._f:
                    self._f[k] = next(g for g in m.groups()[1:] if g is not None)
        return self._f

def load_sigma(paths):
    rules, skipped, files = [], [], []
    if not paths:
        return rules, skipped, files
    try:
        import yaml
    except ImportError:
        raise ConfigError("Sigma rules are configured but PyYAML is not installed (pip install pyyaml).")
    for p in paths:
        if not os.path.exists(p):
            raise ConfigError("Sigma path not found: %s" % p)
        files += files_under(p, (".yml", ".yaml"))
    for f in files:
        rel = os.path.basename(f)
        try:
            with open(f, encoding="utf-8") as fh:
                docs = [d for d in yaml.safe_load_all(fh) if d is not None]
        except yaml.YAMLError as e:
            skipped.append((rel, "", "YAML error: %s" % str(e).splitlines()[0])); continue
        if len(docs) != 1 or not isinstance(docs[0], dict):
            skipped.append((rel, "", "multi-document rule collection")); continue
        r = docs[0]
        title = str(r.get("title", rel))
        if "detection" not in r or "correlation" in r:
            skipped.append((rel, title, "not a detection rule")); continue
        if r.get("status") in ("deprecated", "unsupported"):
            skipped.append((rel, title, "status: %s" % r.get("status"))); continue
        ls = r.get("logsource") or {}
        prod, svc, cat = ls.get("product"), ls.get("service"), ls.get("category")
        if prod and prod != "linux":
            skipped.append((rel, title, "product %s (not linux)" % prod)); continue
        if cat:
            skipped.append((rel, title, "category %s needs live telemetry not present in log files" % cat)); continue
        if svc and svc not in SIGMA_SERVICES:
            skipped.append((rel, title, "service %s has no log-file mapping" % svc)); continue
        lvl = str(r.get("level", "")).lower()
        if lvl not in SIGMA_LEVEL:
            skipped.append((rel, title, "no valid level")); continue
        try:
            det = dict(r["detection"])
            cond = det.pop("condition", None)
            det.pop("timeframe", None)
            if cond is None:
                raise Unsupported("no condition")
            searches, uses_fields = {}, False
            for name, obj in det.items():
                searches[name], uf = compile_search(obj)
                uses_fields = uses_fields or uf
            fn = compile_condition(cond, searches)
        except Unsupported as e:
            skipped.append((rel, title, "unsupported: %s" % e)); continue
        tags = [str(t).lower() for t in r.get("tags") or []]
        attack = sorted({t.split(".", 1)[1].upper() for t in tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)})
        cves = sorted({"CVE-" + t.split(".", 1)[1].upper() for t in tags if re.fullmatch(r"cve\.\d{4}-\d{4,7}", t)})
        rid = str(r.get("id") or hashlib.sha1(rel.encode()).hexdigest())
        fps = r.get("falsepositives") or []
        rules.append({"id": "SIGMA:" + rid, "title": title, "priority": SIGMA_LEVEL[lvl], "sigma_level": lvl,
                      "target": "line", "fn": fn, "uses_fields": uses_fields,
                      "path_rx": re.compile(SIGMA_SERVICES[svc]) if svc else None,
                      "reason": " ".join(str(r.get("description", title)).split()),
                      "false_positives": "; ".join(str(x) for x in fps) if isinstance(fps, list) else str(fps),
                      "attack": attack, "cves": cves, "references": [str(x) for x in r.get("references") or []][:5],
                      "min_hits": 1,
                      "source": {"kind": "sigma", "org": "SigmaHQ community rule (level: %s)" % lvl,
                                 "name": rel, "sha256": sha256_file(f), "author": str(r.get("author", ""))}})
    return rules, skipped, files


# -------------------------------------------------------------------- feeds
def load_kev(path):
    if not path:
        return {}, {}
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    vulns = {v["cveID"].upper(): v for v in data.get("vulnerabilities", []) if "cveID" in v}
    meta = {"kind": "kev", "org": "CISA Known Exploited Vulnerabilities catalog", "name": os.path.basename(path),
            "sha256": sha256_file(path), "version": "%s (released %s)" % (data.get("catalogVersion", "?"),
                                                                          data.get("dateReleased", "?")),
            "loaded": len(vulns)}
    return vulns, meta

def load_attack(path):
    if not path:
        return {}, {}
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    tech, version, by_stix, revoked = {}, "", {}, {}
    ext_id = lambda o: next((r["external_id"].upper() for r in o.get("external_references", [])
                             if r.get("source_name") == "mitre-attack" and r.get("external_id")), None)
    for o in data.get("objects", []):
        if o.get("type") == "x-mitre-collection":
            version = o.get("x_mitre_version", "")
        if o.get("type") != "attack-pattern" or not ext_id(o):
            continue
        by_stix[o.get("id")] = ext_id(o)
        if o.get("revoked"):
            revoked[o.get("id")] = ext_id(o)
            continue
        tech[ext_id(o)] = {"name": o.get("name", ""), "deprecated": bool(o.get("x_mitre_deprecated")),
                           "tactics": sorted({k["phase_name"] for k in o.get("kill_chain_phases", [])
                                              if k.get("kill_chain_name") == "mitre-attack"})}
    for o in data.get("objects", []):                    # revoked technique -> its replacement
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by" \
                and o.get("source_ref") in revoked and by_stix.get(o.get("target_ref")) in tech:
            new = by_stix[o["target_ref"]]
            tech[revoked[o["source_ref"]]] = dict(tech[new], replaced_by=new)
    meta = {"kind": "attack", "org": "MITRE ATT&CK (labels only, no severity)", "name": os.path.basename(path),
            "sha256": sha256_file(path), "version": version or "?", "loaded": len(tech)}
    return tech, meta

def classify(cell, types):
    c = cell.strip().strip("\"'").strip().lower()
    if not c or c.startswith("#"):
        return None, None
    if re.fullmatch(r"[0-9a-f]+", c) and len(c) in HEX_RE:
        t = HEX_RE[len(c)]
        return (t, c) if t in types else (None, None)
    if c.startswith(("http://", "https://")):
        return ("url", c.rstrip("/")) if "url" in types else (None, None)
    m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?", c)
    if m:
        try:
            ipaddress.ip_address(m.group(1))
            return ("ip", m.group(1)) if "ip" in types else (None, None)
        except ValueError:
            return None, None
    if "domain" in types and DOMAIN_RE.fullmatch(c):
        return "domain", c
    return None, None

def load_ioc(feed):
    sets = collections.defaultdict(set)
    with open(feed["path"], encoding="utf-8", errors="replace", newline="") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            cells = next(csv.reader([s])) if ("," in s or "\t" in s) else s.split()
            if "\t" in s and len(cells) == 1:
                cells = s.split("\t")
            for cell in cells:
                t, v = classify(cell, feed["types"])
                if t:
                    sets[t].add(v)
    meta = {"kind": "ioc", "org": feed["org"], "name": feed["name"], "sha256": sha256_file(feed["path"]),
            "version": "snapshot %s" % (feed["snapshot_date"] or "(date not recorded)"),
            "loaded": sum(len(v) for v in sets.values()), "priority": feed["priority"]}
    return dict(sets), meta

def known_software_matches(path, wanted):
    """Stream a known-software hash set and return the subset of `wanted` hashes found in it."""
    found = set()
    with open(path, "rb") as f:
        sqlite_db = f.read(16) == b"SQLite format 3\x00"
    if sqlite_db:
        con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
        try:
            tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            for t in tables:
                cols = [r[1] for r in con.execute('PRAGMA table_info("%s")' % t.replace('"', '""'))]
                for c in cols:
                    if c.lower() in ("sha256", "sha1", "md5", "sha-1", "sha-256"):
                        q = 'SELECT "%s" FROM "%s"' % (c.replace('"', '""'), t.replace('"', '""'))
                        for (v,) in con.execute(q):
                            if v and str(v).lower() in wanted:
                                found.add(str(v).lower())
        finally:
            con.close()
        return found
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            for tok in re.findall(r"[0-9A-Fa-f]{32,64}", line):
                t = tok.lower()
                if len(t) in HEX_RE and t in wanted:
                    found.add(t)
    return found


# ----------------------------------------------------------------- evidence
class Item:
    __slots__ = ("path", "real", "state", "inode", "size", "md5", "sha1", "sha256", "text", "executable",
                 "known", "allowed", "ips", "is_log")

def collect(roots, ledger):
    items, warnings = [], []
    for root, state in roots:
        for dp, dns, fns in os.walk(root):
            dns.sort()
            for fn in sorted(fns):
                real = os.path.join(dp, fn)
                if os.path.islink(real) or not os.path.isfile(real):
                    continue
                it = Item()
                it.path = "/" + os.path.relpath(real, root).replace(os.sep, "/")
                it.real, it.state = real, state
                m, s1, s2 = hashlib.md5(usedforsecurity=False), hashlib.sha1(), hashlib.sha256()
                with open(real, "rb") as f:
                    head = f.read(8192)
                    for h in (m, s1, s2):
                        h.update(head)
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        m.update(chunk); s1.update(chunk); s2.update(chunk)
                it.md5, it.sha1, it.sha256 = m.hexdigest(), s1.hexdigest(), s2.hexdigest()
                it.size = os.path.getsize(real)
                it.text = b"\0" not in head
                it.executable = head.startswith(b"\x7fELF") or head.startswith(b"#!")
                it.known, it.allowed, it.ips, it.is_log = "", False, set(), False
                led = ledger.get(it.path)
                it.inode = led.get("inode", "") if led else ""
                if led and led.get("sha256") and led["sha256"] != it.sha256 and state == led.get("_state", state):
                    warnings.append("%s: SHA-256 differs from the tracekit ledger (%s...) - verify integrity"
                                    % (it.path, led["sha256"][:12]))
                items.append(it)
    return items, warnings

def tracekit_roots(case):
    roots = []
    for sub, state in (("allocated", "allocated"), ("deleted", "deleted")):
        p = os.path.join(case, "recovered", sub)
        if os.path.isdir(p):
            roots.append((os.path.abspath(p), state))
    if not roots:
        raise ConfigError("no recovered/allocated or recovered/deleted folder in %s (run tracekit init/deleted)" % case)
    ledger = {}
    st = os.path.join(case, "findings", "tracekit_state.json")
    if os.path.exists(st):
        with open(st) as f:
            for e in json.load(f).get("ledger", []):
                if "!" not in e.get("path", ""):
                    ledger[e["path"]] = {"inode": e.get("inode", ""), "sha256": e.get("sha256", ""),
                                         "_state": "deleted" if e.get("state") == "deleted" else "allocated"}
    return roots, ledger


# --------------------------------------------------------------------- scan
def build_sources(cfg):
    local, corrs, local_files, content_pool = load_local(cfg["sources"]["local_rules"], cfg)
    sigma, sigma_skipped, sigma_files = load_sigma(cfg["sources"]["sigma"])
    kev, kev_meta = load_kev(cfg["sources"]["kev"])
    attack, attack_meta = load_attack(cfg["sources"]["attack"])
    iocs = []
    for feed in cfg["sources"]["ioc"]:
        sets, meta = load_ioc(feed)
        iocs.append((feed, sets, meta))
    sources = []
    if local_files:
        sources.append({"kind": "local", "org": "Local rules (examiner-defined)", "name": ", ".join(
            os.path.basename(f) for f in local_files), "sha256": sha256_tree(local_files), "version": __version__,
            "loaded": len(local) + len(corrs)})
    if sigma_files:
        sources.append({"kind": "sigma", "org": "SigmaHQ community rules", "name": ", ".join(
            os.path.basename(p.rstrip("/")) for p in cfg["sources"]["sigma"]), "sha256": sha256_tree(sigma_files),
            "version": "%d rule files" % len(sigma_files), "loaded": len(sigma), "skipped": len(sigma_skipped)})
    for meta in (kev_meta, attack_meta):
        if meta:
            sources.append(meta)
    for _, _, meta in iocs:
        sources.append(meta)
    return dict(local=local, corrs=corrs, content_pool=content_pool, sigma=sigma, sigma_skipped=sigma_skipped,
                kev=kev, attack=attack, iocs=iocs, sources=sources)

def file_cond(c, it, content_hits):
    if "path_regex" in c and not c["path_regex"].search(it.path): return False
    if "not_path_regex" in c and c["not_path_regex"].search(it.path): return False
    if "name_regex" in c and not c["name_regex"].search(it.path.rsplit("/", 1)[-1]): return False
    if "executable" in c and it.executable != c["executable"]: return False
    if "size_gt" in c and not it.size > c["size_gt"]: return False
    if "size_lt" in c and not it.size < c["size_lt"]: return False
    if "state" in c and it.state != c["state"]: return False
    if "content_regex" in c and c["content_regex"] not in content_hits: return False
    if "any_of" in c and not any(file_cond(x, it, content_hits) for x in c["any_of"]): return False
    return True

def content_ids(c):
    out = set()
    if "content_regex" in c:
        out.add(c["content_regex"])
    for x in c.get("any_of", []):
        out |= content_ids(x)
    return out

def line_cond(c, line):
    if "line_regex" in c and not c["line_regex"].search(line): return False
    if "not_line_regex" in c and c["not_line_regex"].search(line): return False
    if "any_of" in c and not any(line_cond(x, line) for x in c["any_of"]): return False
    return True

def line_rule_applies(r, it):
    c = r["match"]
    if "path_regex" in c and not c["path_regex"].search(it.path): return False
    if "not_path_regex" in c and c["not_path_regex"].search(it.path): return False
    if "state" in c and it.state != c["state"]: return False
    return True

def new_hit():
    return {"count": 0, "samples": [], "ips": set(), "users": set(), "first_ts": None, "last_ts": None,
            "ip_counts": collections.Counter(), "user_counts": collections.Counter()}

def add_hit(h, n, line, ips, users, ts, max_samples):
    h["count"] += 1
    if len(h["samples"]) < max_samples:
        h["samples"].append([n, line[:300]])
    h["ips"] |= set(ips); h["users"] |= users
    h["ip_counts"].update(set(ips)); h["user_counts"].update(users)
    if ts:
        h["first_ts"] = min(h["first_ts"] or ts, ts); h["last_ts"] = max(h["last_ts"] or ts, ts)

def scan(roots, ledger, cfg, S):
    sc, allow = cfg["scan"], cfg["allow"]
    year, maxs = int(sc["syslog_year"]), int(sc["max_samples"])
    log_rx, kev_ex = re.compile(sc["log_path_regex"]), re.compile(sc["kev_exclude_regex"])
    allow_paths = [re.compile(p) for p in allow["paths"]]
    allow_hashes = {h.lower() for h in allow["hashes"]}
    allow_users = set(allow["users"])
    allow_nets = [ipaddress.ip_network(x, strict=False) for x in allow["ips"]]
    def ip_allowed(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in allow_nets)

    items, warnings = collect(roots, ledger)
    stats = collections.Counter(files=len(items), bytes=sum(i.size for i in items))
    suppressed = collections.Counter()

    # known-software sets (NSRL or similar)
    wanted = {h for it in items for h in (it.md5, it.sha1, it.sha256)}
    known_meta = []
    for ks in cfg["sources"]["known_software"]:
        found = known_software_matches(ks, wanted)
        for it in items:
            if not it.known and (it.md5 in found or it.sha1 in found or it.sha256 in found):
                it.known = os.path.basename(ks)
        known_meta.append({"kind": "known_software", "org": "Known-software hash set (e.g. NIST NSRL)",
                           "name": os.path.basename(ks), "sha256": sha256_file(ks), "version": "-",
                           "loaded": len(found), "note": "evidence files matched: %d" % len(found)})
    stats["known_software_files"] = sum(1 for i in items if i.known)
    for it in items:
        if any(rx.search(it.path) for rx in allow_paths) or it.sha256 in allow_hashes or it.md5 in allow_hashes \
                or it.sha1 in allow_hashes:
            it.allowed = True
            stats["allowlisted_files"] += 1

    file_rules = [r for r in S["local"] if r["target"] == "file"]
    line_rules = [r for r in S["local"] if r["target"] == "line"]
    pool = S["content_pool"]
    ioc_net = [(feed, sets, meta) for feed, sets, meta in S["iocs"] if sets.get("ip") or sets.get("url") or sets.get("domain")]
    raw = []                                                    # (rule, item, hit, extra)

    for it in items:
        if it.allowed:
            continue
        content_hits = {}
        line_hits = collections.defaultdict(new_hit)
        ioc_hits = collections.defaultdict(new_hit)
        kev_hits = collections.defaultdict(new_hit)
        if it.text:
            stats["text_files"] += 1
            it.is_log = bool(log_rx.search(it.path))
            stats["log_files"] += it.is_log
            lrules = [r for r in line_rules if line_rule_applies(r, it)]
            srules = [r for r in S["sigma"] if it.is_log and (r["path_rx"] is None or r["path_rx"].search(it.path))]
            pending = set(range(len(pool)))
            check_kev = bool(S["kev"]) and not kev_ex.search(it.path)
            with open(it.real, "r", encoding="utf-8", errors="replace", newline="") as f:
                for n, rawline in enumerate(f, 1):
                    line = rawline.rstrip("\r\n")
                    stats["lines"] += 1
                    for i in list(pending):
                        if pool[i].search(line):
                            content_hits[i] = (n, line[:300]); pending.discard(i)
                    ips = IP_RE.findall(line)
                    if len(it.ips) < 1000:
                        it.ips.update(ips)
                    matched = []
                    for r in lrules:
                        if line_cond(r["match"], line):
                            matched.append(r)
                    if srules:
                        ev = Event(line)
                        for r in srules:
                            if r["fn"](ev):
                                matched.append(r)
                    if matched:
                        users = users_in(line, it.path)
                        blocked = any(ip_allowed(ip) for ip in ips) or bool(users & allow_users)
                        ts = parse_ts(line, year)
                        for r in matched:
                            if blocked:
                                suppressed[r["id"]] += 1
                            else:
                                add_hit(line_hits[r["id"]], n, line, ips, users, ts, maxs)
                    for feed, sets, meta in ioc_net:
                        hits = [ip for ip in ips if ip in sets.get("ip", ())]
                        if sets.get("url"):
                            hits += [u.lower().rstrip("/.,;)") for u in URL_RE.findall(line)
                                     if u.lower().rstrip("/.,;)") in sets["url"]]
                        if sets.get("domain"):
                            hits += [d for d in DOMAIN_RE.findall(line.lower()) if d in sets["domain"]]
                        if hits:
                            users = users_in(line, it.path)
                            if any(ip_allowed(ip) for ip in ips) or users & allow_users:
                                suppressed["IOC:" + feed["name"]] += 1
                                continue
                            h = ioc_hits[feed["name"]]
                            add_hit(h, n, line, ips, users, parse_ts(line, year), maxs)
                            h.setdefault("indicators", set()).update(hits)
                    if check_kev:
                        for c in CVE_RE.findall(line):
                            c = c.upper()
                            if c in S["kev"]:
                                add_hit(kev_hits[c], n, line, ips, users_in(line, it.path), parse_ts(line, year), maxs)
        for r in file_rules:
            if file_cond(r["match"], it, content_hits):
                lines = [list(content_hits[i]) for i in sorted(content_ids(r["match"])) if i in content_hits]
                raw.append((r, it, {"count": 1, "samples": lines, "ips": set(), "users": users_in("", it.path),
                                    "first_ts": None, "last_ts": None}, {"file_rule": True}))
        all_rules = {r["id"]: r for r in line_rules + S["sigma"]}
        for rid, h in line_hits.items():
            r = all_rules[rid]
            if h["count"] >= r["min_hits"]:
                raw.append((r, it, h, {}))
            else:
                suppressed[rid + " (below min_hits)"] += h["count"]
        for feed, sets, meta in S["iocs"]:
            hashes = [(t, getattr(it, t)) for t in ("md5", "sha1", "sha256") if getattr(it, t) in sets.get(t, ())]
            if hashes:
                raw.append(({"id": "IOC:" + feed["name"], "title": "File hash listed by %s" % feed["name"],
                             "priority": feed["priority"], "reason": "The file's %s appears in the indicator feed '%s', "
                             "published by %s." % (hashes[0][0].upper(), feed["name"], feed["org"]),
                             "false_positives": "Feed errors, or a dual-use file legitimately present; confirm the "
                             "entry's context in the feed and its date against the evidence timeline.",
                             "attack": [], "cves": [], "references": [], "source": meta},
                            it, {"count": 1, "samples": [], "ips": set(), "users": users_in("", it.path),
                                 "first_ts": None, "last_ts": None}, {"file_rule": True,
                                                                      "indicators": [h[1] for h in hashes]}))
            h = ioc_hits.get(feed["name"])
            if h:
                raw.append(({"id": "IOC:" + feed["name"], "title": "Network indicator listed by %s" % feed["name"],
                             "priority": feed["priority"], "reason": "The file references indicator(s) that appear "
                             "in the indicator feed '%s', published by %s." % (feed["name"], feed["org"]),
                             "false_positives": "Indicators go stale (addresses and domains are reassigned); compare "
                             "the feed snapshot date with when the evidence was created.",
                             "attack": [], "cves": [], "references": [], "source": meta},
                            it, h, {"indicators": sorted(h.pop("indicators", set()))}))
        for cve, h in kev_hits.items():
            v = S["kev"][cve]
            raw.append(({"id": "KEV:" + cve, "title": "Reference to %s (CISA Known Exploited Vulnerability)" % cve,
                         "priority": sc["kev_mention_priority"],
                         "reason": "%s - %s %s: %s. Listed by CISA as exploited in the wild (added %s). A mention is "
                                   "not evidence of exploitation." % (cve, v.get("vendorProject", ""), v.get("product", ""),
                                                                      v.get("vulnerabilityName", ""), v.get("dateAdded", "?")),
                         "false_positives": "Package changelogs, advisories, scanner output and documentation mention CVEs routinely.",
                         "attack": [], "cves": [cve], "references": ["https://nvd.nist.gov/vuln/detail/" + cve],
                         "source": {"kind": "kev", "org": "CISA Known Exploited Vulnerabilities catalog",
                                    "name": "KEV", "sha256": ""}}, it, h, {}))
    return items, raw, stats, suppressed, warnings, known_meta

def make_finding(r, it, h, extra, S, cfg):
    pr, adj = r["priority"], []
    if r.get("sigma_level") == "critical":
        adj.append("Sigma level 'critical' maps to triagekit 'high' (the top of the scale)")
    kev_cves = [c for c in r.get("cves", []) if c in S["kev"]]
    if r["source"]["kind"] == "sigma" and kev_cves:
        new = raise_one(pr)
        if new != pr:
            adj.append("raised %s -> %s: rule is tagged %s, listed in the CISA KEV catalog" % (pr, new, ", ".join(kev_cves)))
            pr = new
    if it.known and extra.get("file_rule") and r["source"]["kind"] in ("local", "sigma"):
        new = lower_one(pr)
        adj.append("lowered %s -> %s: file hash is in known-software set %s (known software is not necessarily safe)"
                   % (pr, new, it.known))
        pr = new
    techs = []
    for t in r.get("attack", []):
        a = S["attack"].get(t, {})
        e = {"id": t, "name": a.get("name", ""), "tactics": a.get("tactics", [])}
        if a.get("replaced_by"):
            e["note"] = "revoked in this ATT&CK version; replaced by %s" % a["replaced_by"]
        elif a.get("deprecated"):
            e["note"] = "deprecated in this ATT&CK version"
        elif S["attack"] and not a:
            e["note"] = "not found in the loaded ATT&CK version"
        techs.append(e)
    ev = {"artifact": it.path, "state": it.state, "inode": it.inode, "sha256": it.sha256, "size": it.size,
          "hits": h["count"], "lines": h["samples"]}
    if extra.get("indicators"):
        ev["indicators"] = extra["indicators"]
    ips = set(h["ips"]) | (set(it.ips) if extra.get("file_rule") else set())
    fp = hashlib.sha1(("%s|%s|%s|%s" % (r["id"], r["title"], it.state, it.path)).encode()).hexdigest()[:16]
    src = {k: r["source"].get(k, "") for k in ("kind", "org", "name")}
    return {"fingerprint": fp, "rule_id": r["id"], "title": r["title"], "priority": pr, "base_priority": r["priority"],
            "adjustments": adj, "source": src, "subject": it.path, "state": it.state, "reason": r["reason"],
            "false_positives": r.get("false_positives", ""), "attack": techs, "references": r.get("references", []),
            "evidence": [ev], "entities": {"ips": sorted(ips)[:50], "users": sorted(h["users"]),
                                           "cves": sorted(set(r.get("cves", [])))},
            "first_ts": h["first_ts"], "last_ts": h["last_ts"], "contributors": [],
            "min_hits": r.get("min_hits", 1),
            "entity_counts": {"ips": {k: h.get("ip_counts", {}).get(k, 1) for k in sorted(ips)[:200]},
                              "users": {k: h.get("user_counts", {}).get(k, 1) for k in sorted(h["users"])[:200]}}}

def apply_overrides(findings, cfg):
    out, log = [], collections.Counter()
    for f in findings:
        ov = cfg["override"].get(f["rule_id"])
        if ov:
            if ov.get("enabled") is False:
                log["%s: disabled by case settings" % f["rule_id"]] += 1
                continue
            if "priority" in ov and ov["priority"] != f["priority"]:
                f["adjustments"].append("priority overridden by case settings: %s -> %s" % (f["priority"], ov["priority"]))
                log["%s: priority set to %s" % (f["rule_id"], ov["priority"])] += 1
                f["priority"] = ov["priority"]
        out.append(f)
    return out, log

def pat_match(pat, f):
    if pat.lower().startswith("attack:"):
        p = pat[7:].upper()
        return any(fnmatch.fnmatchcase(t["id"], p) for t in f["attack"])
    return fnmatch.fnmatchcase(f["rule_id"], pat)

def correlate(findings, corrs):
    groups = {"same_file": collections.defaultdict(list), "same_ip": collections.defaultdict(list),
              "same_user": collections.defaultdict(list)}
    for f in findings:
        groups["same_file"][(f["state"], f["subject"])].append(f)
        ec, need = f.get("entity_counts", {}), f.get("min_hits", 1)
        for ip in f["entities"]["ips"]:
            if ec.get("ips", {}).get(ip, 1) >= need:          # a threshold rule must meet it for THIS address
                groups["same_ip"][ip].append(f)
        for u in f["entities"]["users"]:
            if ec.get("users", {}).get(u, 1) >= need:
                groups["same_user"][u].append(f)
    out, seen = [], set()
    for c in corrs:
        for key in sorted(groups[c["scope"]], key=str):
            fs = groups[c["scope"]][key]
            contrib, ok = [], True
            for pat in c["all"]:
                m = [f for f in fs if pat_match(pat, f)]
                if not m:
                    ok = False; break
                contrib += m
            if ok and c["any"]:
                m = [f for f in fs if any(pat_match(p, f) for p in c["any"])]
                ok = bool(m); contrib += m
            if not ok:
                continue
            contrib = sorted({f["fingerprint"]: f for f in contrib}.values(), key=lambda f: f["fingerprint"])
            if len({(f["state"], f["subject"]) for f in contrib}) < c["min_artifacts"]:
                continue
            if len({f["source"]["kind"] for f in contrib}) < c["min_sources"]:
                continue
            if c["window"]:
                ts = [f["first_ts"] for f in contrib]
                if None in ts:
                    continue
                dts = [dt.datetime.fromisoformat(t) for t in ts]
                if (max(dts) - min(dts)).total_seconds() > c["window"]:
                    continue
            sig = (c["id"], tuple(f["fingerprint"] for f in contrib))
            if sig in seen:
                continue
            seen.add(sig)
            base = max((f["priority"] for f in contrib), key=PRANK.get)
            pr = raise_one(base)
            label = key[1] if c["scope"] == "same_file" else key
            subject = "%s %s" % (c["scope"].replace("_", " "), label)
            fp = hashlib.sha1(("%s|%s" % (c["id"], "|".join(s for s in sig[1]))).encode()).hexdigest()[:16]
            out.append({"fingerprint": fp, "rule_id": c["id"], "title": c["title"], "priority": pr, "base_priority": base,
                        "adjustments": [("raised one step %s -> %s: the highest contributing finding was %s and all "
                                         "requirements of %s were met" % (base, pr, base, c["id"])) if pr != base else
                                        ("kept at %s (already the top of the scale): all requirements of %s were met"
                                         % (pr, c["id"]))],
                        "source": {k: c["source"][k] for k in ("kind", "org", "name")}, "subject": subject,
                        "state": "", "reason": c["reason"], "false_positives":
                            "Each contributing finding's own innocent explanations apply; correlation shows "
                            "co-occurrence, not causation.",
                        "attack": sorted({json.dumps(t, sort_keys=True) for f in contrib for t in f["attack"]}),
                        "references": [], "evidence": [focus(e, f, c["scope"], key) for f in contrib for e in f["evidence"]],
                        "entities": focus_entities(contrib, c["scope"], key),
                        "first_ts": min((f["first_ts"] for f in contrib if f["first_ts"]), default=None),
                        "last_ts": max((f["last_ts"] for f in contrib if f["last_ts"]), default=None),
                        "contributors": [f["fingerprint"] for f in contrib],
                        "requirements": {"scope": c["scope"], "all": c["all"], "any": c["any"],
                                         "min_artifacts": c["min_artifacts"], "min_sources": c["min_sources"],
                                         "window_seconds": c["window"]}})
            out[-1]["attack"] = [json.loads(t) for t in out[-1]["attack"]]
    return out

def entity_rx(scope, key):
    if scope == "same_ip":
        return re.compile(r"(?<![\d.])%s(?![\d]|\.\d)" % re.escape(key))
    if scope == "same_user":
        return re.compile(r"(?<![\w.-])%s(?![\w-])" % re.escape(key))
    return None

def focus(e, f, scope, key):
    """Contributor evidence narrowed to the shared IP/user, with the hit count for that entity."""
    e = dict(e)
    rx = entity_rx(scope, key)
    if rx is None:
        return e
    kind = "ips" if scope == "same_ip" else "users"
    e["hits"] = f.get("entity_counts", {}).get(kind, {}).get(key, e["hits"])
    home = HOME_RE.match(e["artifact"])
    if not (scope == "same_user" and home and key in home.groups()):
        kept = [ln for ln in e["lines"] if rx.search(ln[1])]
        e["lines"] = kept or e["lines"]
    e["focus"] = "%s %s" % (kind[:-1], key)
    return e

def focus_entities(contrib, scope, key):
    out = {k: sorted({x for f in contrib for x in f["entities"][k]})[:50] for k in ("ips", "users", "cves")}
    if scope == "same_ip":
        out["ips"] = [key]
        out["users"] = sorted({u for f in contrib for e in f["evidence"] for n, ln in e["lines"]
                               if entity_rx(scope, key).search(ln) for u in users_in(ln, e["artifact"])})
    elif scope == "same_user":
        out["users"] = [key]
    return out

def cmd_scan(a):
    cfg = load_config(a.config)
    if a.year:
        cfg["scan"]["syslog_year"] = a.year
    if a.tracekit:
        roots, ledger = tracekit_roots(a.tracekit)
    else:
        if not a.evidence:
            sys.exit("give at least one EVIDENCE_DIR, or --tracekit CASE_DIR")
        roots, ledger = [(os.path.abspath(p), "file") for p in a.evidence], {}
    for r, _ in roots:
        if not os.path.isdir(r):
            sys.exit("evidence folder not found: %s" % r)
    out = os.path.abspath(a.out)
    for r, _ in roots:
        if out == r or out.startswith(r + os.sep) or r.startswith(out + os.sep):
            sys.exit("refusing: the output folder must not be inside the evidence (or contain it)")
    if os.path.isdir(out) and os.listdir(out) and not os.path.exists(os.path.join(out, "findings.json")) and not a.force:
        sys.exit("output folder %s is not empty and is not a previous triagekit run (use --force)" % out)
    os.makedirs(out, exist_ok=True)

    started = now_utc()
    S = build_sources(cfg)
    items, raw, stats, suppressed, warnings, known_meta = scan(roots, ledger, cfg, S)
    findings = [make_finding(r, it, h, extra, S, cfg) for r, it, h, extra in raw]
    findings, ov_log = apply_overrides(findings, cfg)
    findings += correlate(findings, S["corrs"])
    findings.sort(key=lambda f: (-PRANK[f["priority"]], f["rule_id"], f["state"], f["subject"]))
    for i, f in enumerate(findings, 1):
        f["id"] = "F-%04d" % i
    byfp = {f["fingerprint"]: f["id"] for f in findings}
    for f in findings:
        f["contributors"] = [{"fingerprint": c, "id": byfp.get(c, "")} for c in f["contributors"]]

    blob = json.dumps({"tool": "triagekit", "version": __version__, "findings": findings},
                      sort_keys=True, indent=1, ensure_ascii=False)
    with open(os.path.join(out, "findings.json"), "w", encoding="utf-8") as f:
        f.write(blob)
    with open(os.path.join(out, "manifest.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["path", "state", "inode", "size", "sha256", "sha1", "md5", "text", "known_software", "allowlisted"])
        for it in sorted(items, key=lambda i: (i.state, i.path)):
            w.writerow([it.path, it.state, it.inode, it.size, it.sha256, it.sha1, it.md5, int(it.text), it.known,
                        int(it.allowed)])
    sk = collections.Counter(" ".join(reason.split()[:2]) if reason.startswith(("product", "service", "category"))
                             else reason.split(":")[0] for _, _, reason in S["sigma_skipped"])
    with open(os.path.join(out, "sigma_skipped.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["rule_file", "title", "reason"]); w.writerows(S["sigma_skipped"])
    tool_sha = sha256_file(os.path.abspath(__file__))
    run = {"tool": "triagekit", "version": __version__, "tool_sha256": tool_sha, "started_utc": started,
           "finished_utc": now_utc(), "python": platform.python_version(),
           "platform": "%s %s" % (platform.system(), platform.release()), "argv": sys.argv[1:],
           "config": cfg["_path"], "config_sha256": sha256_file(cfg["_path"]) if cfg["_path"] else "",
           "case": cfg["case"], "syslog_year": cfg["scan"]["syslog_year"], "evidence_roots": [{"path": r, "state": s} for r, s in roots],
           "tracekit_case": os.path.abspath(a.tracekit) if a.tracekit else "",
           "stats": dict(stats), "suppressed": dict(sorted(suppressed.items())), "overrides": dict(ov_log),
           "allow": cfg["allow"], "case_overrides": cfg["override"], "integrity_warnings": warnings,
           "sources": S["sources"] + known_meta, "sigma_skipped_summary": dict(sk.most_common()),
           "rules_loaded": {"local": len(S["local"]), "correlation": len(S["corrs"]), "sigma": len(S["sigma"])},
           "result_digest": hashlib.sha256(blob.encode("utf-8")).hexdigest()}
    with open(os.path.join(out, "run.json"), "w", encoding="utf-8") as f:
        json.dump(run, f, indent=1, ensure_ascii=False)
    render(out)
    c = collections.Counter(f["priority"] for f in findings)
    print("scanned %d files (%d log files, %d lines) | findings: high %d, medium %d, low %d, info %d"
          % (stats["files"], stats["log_files"], stats["lines"], c["high"], c["medium"], c["low"], c["info"]))
    print("result digest:", run["result_digest"])
    for w_ in warnings:
        print("  WARNING:", w_)
    print("report:", os.path.join(out, "report.md"))


# ------------------------------------------------------------------- report
def load_reviews(out):
    p = os.path.join(out, "reviews.json")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    return {}

def finding_md(f, rv):
    st = rv.get(f["fingerprint"], {})
    L = ["### %s - %s - %s\n" % (f["id"], f["priority"].upper(), f["title"]),
         "- **Subject:** `%s`%s" % (f["subject"], " (%s)" % f["state"] if f["state"] else ""),
         "- **Rule:** `%s`" % f["rule_id"],
         "- **Rated by:** %s (`%s`)" % (f["source"]["org"], f["source"]["name"]),
         "- **Triage priority:** %s (rule's own rating: %s)" % (f["priority"], f["base_priority"])]
    for adj in f["adjustments"]:
        L.append("  - %s" % adj)
    if f["attack"]:
        L.append("- **MITRE ATT&CK:** " + "; ".join(
            ("%s %s%s%s" % (t["id"], t["name"], " (%s)" % ", ".join(t["tactics"]) if t["tactics"] else "",
                            " [%s]" % t["note"] if t.get("note") else "")).replace("  ", " ") for t in f["attack"]))
    L.append("- **Why flagged:** %s" % f["reason"])
    if f["false_positives"]:
        L.append("- **Innocent explanations to rule out:** %s" % f["false_positives"])
    if f["first_ts"]:
        L.append("- **Time span in evidence:** %s to %s" % (f["first_ts"], f["last_ts"] or f["first_ts"]))
    ent = f["entities"]
    if ent["ips"] or ent["users"] or ent["cves"]:
        L.append("- **Entities:** " + "; ".join("%s: %s" % (k, ", ".join(v[:10])) for k, v in ent.items() if v))
    if f["contributors"]:
        L.append("- **Contributing findings:** " + ", ".join(c["id"] or c["fingerprint"] for c in f["contributors"]))
    L.append("- **Review:** %s%s%s" % (st.get("status", "unreviewed"),
                                       " by %s" % st["examiner"] if st.get("examiner") else "",
                                       " - %s" % st["note"] if st.get("note") else ""))
    L.append("\n**Evidence**\n")
    rows = []
    for e in f["evidence"][:20]:
        rows.append([e["artifact"], e["state"], e["inode"] or "-", e["sha256"], e["hits"]])
    L.append(md_table(["Artifact", "State", "Inode", "SHA-256", "Hits"], rows))
    if any(e.get("focus") for e in f["evidence"]):
        L.append("Hits and sample lines are narrowed to the shared %s.\n" % f["evidence"][0].get("focus", ""))
    for e in f["evidence"][:20]:
        if e.get("indicators"):
            L.append("Indicators matched in `%s`: %s\n" % (e["artifact"], ", ".join("`%s`" % i for i in e["indicators"][:20])))
        if e["lines"]:
            L.append("Sample lines from `%s`:\n" % e["artifact"])
            L.extend("    %6d: %s" % (n, t) for n, t in e["lines"])
            L.append("")
    if f["references"]:
        L.append("References: " + ", ".join(f["references"][:5]) + "\n")
    return "\n".join(L) + "\n"

def render(out):
    with open(os.path.join(out, "findings.json"), encoding="utf-8") as f:
        findings = json.load(f)["findings"]
    with open(os.path.join(out, "run.json"), encoding="utf-8") as f:
        run = json.load(f)
    rv = load_reviews(out)
    fdir = os.path.join(out, "findings")
    if os.path.isdir(fdir):
        shutil.rmtree(fdir)
    for p in PRIORITIES:
        os.makedirs(os.path.join(fdir, p), exist_ok=True)
    for f in findings:
        with open(os.path.join(fdir, f["priority"], "%s.md" % f["id"]), "w", encoding="utf-8") as fh:
            fh.write("# %s\n\n" % f["id"] + finding_md(f, rv))
    c = collections.Counter(f["priority"] for f in findings)
    rs = collections.Counter(rv.get(f["fingerprint"], {}).get("status", "unreviewed") for f in findings)
    st = run["stats"]
    case = run["case"]
    L = ["# Triage report%s\n" % (" - " + case["name"] if case.get("name") else ""),
         "> **Triage priorities are an order of review, not conclusions.** Each finding records which rule and which "
         "published source rated it, why, and what innocent explanations must be ruled out. Nothing here is a finding "
         "of fact until an examiner has verified it against the evidence.\n",
         md_table(["Item", "Value"], [
             ["Examiner", case.get("examiner") or "(not set)"],
             ["Tool", "triagekit %s (SHA-256 %s)" % (run["version"], run["tool_sha256"])],
             ["Run", "%s to %s" % (run["started_utc"], run["finished_utc"])],
             ["Evidence", "; ".join("%s [%s]" % (r["path"], r["state"]) for r in run["evidence_roots"])],
             ["Config", "%s (SHA-256 %s)" % (run["config"] or "(defaults)", run["config_sha256"] or "-")],
             ["Result digest", "%s (SHA-256 of findings.json)" % run["result_digest"]]]),
         "## Summary\n",
         md_table(["Priority", "Findings"], [[p.upper(), c[p]] for p in reversed(PRIORITIES)]),
         "Review status: " + ", ".join("%s %d" % (s, rs[s]) for s in STATUSES) + "\n"]
    top = [f for f in findings if f["priority"] in ("high", "medium")]
    if top:
        L += ["### High and medium findings\n", md_table(["ID", "Priority", "Title", "Subject", "Rated by", "ATT&CK", "Review"],
              [[f["id"], f["priority"], f["title"], f["subject"], f["source"]["org"],
                " ".join(t["id"] for t in f["attack"]) or "-",
                rv.get(f["fingerprint"], {}).get("status", "unreviewed")] for f in top])]
    if run["integrity_warnings"]:
        L += ["## Integrity warnings\n"] + ["- %s" % w for w in run["integrity_warnings"]] + [""]
    L += ["## Sources used\n",
          md_table(["Source", "Organisation", "Version / snapshot", "Loaded", "SHA-256"],
                   [[s.get("name", ""), s.get("org", ""), s.get("version", "-"),
                     "%s%s" % (s.get("loaded", ""), " (+%s skipped)" % s["skipped"] if s.get("skipped") else ""),
                     s.get("sha256", "")] for s in run["sources"]]) if run["sources"] else "No rule sources loaded.\n"]
    if run["sigma_skipped_summary"]:
        L += ["Sigma rules not applied (full list in `sigma_skipped.csv`): " +
              "; ".join("%s x%d" % (k, v) for k, v in run["sigma_skipped_summary"].items()) + "\n"]
    L += ["## Coverage\n", md_table(["Measure", "Count"], [
        ["Files examined (all hashed)", st.get("files", 0)], ["Bytes", st.get("bytes", 0)],
        ["Text files scanned", st.get("text_files", 0)], ["Log/history files (Sigma applied)", st.get("log_files", 0)],
        ["Lines scanned", st.get("lines", 0)], ["Files in known-software set", st.get("known_software_files", 0)],
        ["Allowlisted files (not evaluated)", st.get("allowlisted_files", 0)]])]
    if run["suppressed"] or run["overrides"] or any(run["allow"].values()) or run["case_overrides"]:
        L += ["## Suppressions and overrides\n",
              "Everything below changed what the tool reported. It is listed so that no result is tuned away silently.\n"]
        if any(run["allow"].values()):
            L.append("Allowlist: " + "; ".join("%s: %s" % (k, ", ".join(map(str, v))) for k, v in run["allow"].items() if v) + "\n")
        if run["suppressed"]:
            L.append(md_table(["Rule", "Hits suppressed"], sorted(run["suppressed"].items())))
        if run["overrides"]:
            L.append(md_table(["Override", "Findings affected"], sorted(run["overrides"].items())))
    for p in reversed(PRIORITIES):
        fs = [f for f in findings if f["priority"] == p]
        if not fs:
            continue
        L.append("## %s priority (%d)\n" % (p.upper(), len(fs)))
        if p == "info":
            L.append("Context items, listed briefly (details in `findings/info/`).\n")
            L.append(md_table(["ID", "Title", "Subject", "Rated by"],
                              [[f["id"], f["title"], f["subject"], f["source"]["org"]] for f in fs]))
        else:
            L.extend(finding_md(f, rv) for f in fs)
    L += ["## Limitations\n",
          "- Only rules that fit plain files and log lines are applied. Sigma rules needing live telemetry "
          "(process creation, network connections, file events) cannot be evaluated on a disk image and are listed as skipped.",
          "- Sigma field matching uses key=value pairs found on the line (e.g. auditd). Encoded or differently formatted "
          "fields will not match. Keyword rules match anywhere on the line.",
          "- Indicator feeds and the KEV catalog are point-in-time snapshots; indicators go stale and feeds contain errors.",
          "- A known-software (NSRL) match lowers priority but does not clear a file: hacking tools can be known software.",
          "- Timestamps without a year (syslog style) were read as year %s; correlation time windows depend on this." % run.get("syslog_year", "?"),
          "- No finding does not mean nothing happened. Coverage is limited to the rules and sources listed above.",
          "- Original evidence was opened read-only; every file examined is listed with its hashes in `manifest.csv`.", ""]
    with open(os.path.join(out, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L))

def cmd_report(a):
    out = os.path.abspath(a.out)
    if not os.path.exists(os.path.join(out, "findings.json")):
        sys.exit("no findings.json in %s (run scan first)" % out)
    render(out)
    print("report:", os.path.join(out, "report.md"))

def cmd_review(a):
    out = os.path.abspath(a.out)
    with open(os.path.join(out, "findings.json"), encoding="utf-8") as f:
        findings = json.load(f)["findings"]
    f = next((x for x in findings if x["id"].lower() == a.finding.lower() or x["fingerprint"] == a.finding), None)
    if not f:
        sys.exit("no finding %s in %s" % (a.finding, out))
    rv = load_reviews(out)
    hist = rv.get(f["fingerprint"], {}).get("history", [])
    entry = {"status": a.status, "note": a.note or "", "examiner": a.examiner or "", "time_utc": now_utc(),
             "rule_id": f["rule_id"], "subject": f["subject"]}
    rv[f["fingerprint"]] = dict(entry, history=hist + [entry])
    with open(os.path.join(out, "reviews.json"), "w", encoding="utf-8") as fh:
        json.dump(rv, fh, indent=1, ensure_ascii=False)
    render(out)
    print("%s (%s) marked %s" % (f["id"], f["title"], a.status))


# -------------------------------------------------------------- rules/fetch
def cmd_rules(a):
    cfg = load_config(a.config)
    S = build_sources(cfg)
    print("local rules: %d | correlation rules: %d | sigma applied: %d | sigma skipped: %d"
          % (len(S["local"]), len(S["corrs"]), len(S["sigma"]), len(S["sigma_skipped"])))
    for s in S["sources"]:
        print("  %-12s %-45s loaded %-6s %s" % (s["kind"], s["org"][:45], s.get("loaded", ""), s.get("version", "")))
    for r in S["local"] + S["sigma"]:
        if a.verbose:
            print("  [%s] %-8s %s - %s" % (r["source"]["kind"], r["priority"], r["id"], r["title"]))
    sk = collections.Counter(reason for _, _, reason in S["sigma_skipped"])
    if sk:
        print("sigma skipped by reason:")
        for k, v in sk.most_common(12):
            print("  %4d  %s" % (v, k))
    if a.verbose:
        for rel, title, reason in S["sigma_skipped"]:
            print("  skipped %s (%s): %s" % (rel, title, reason))

def cmd_fetch(a):
    dest = os.path.abspath(a.dest)
    os.makedirs(dest, exist_ok=True)
    lock_p = os.path.join(dest, "FEEDS.lock.json")
    lock = json.load(open(lock_p)) if os.path.exists(lock_p) else []
    for name, url in FEEDS.items():
        p = os.path.join(dest, name)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "triagekit/%s" % __version__})
            with urllib.request.urlopen(req, timeout=120) as r, open(p + ".part", "wb") as f:
                shutil.copyfileobj(r, f)
            os.replace(p + ".part", p)
        except Exception as e:                                       # noqa: BLE001 - report and continue
            print("FAILED %s: %s" % (name, e))
            continue
        entry = {"file": name, "url": url, "downloaded_utc": now_utc(), "sha256": sha256_file(p),
                 "size": os.path.getsize(p)}
        lock.append(entry)
        print("saved %s  sha256 %s" % (name, entry["sha256"]))
    with open(lock_p, "w") as f:
        json.dump(lock, f, indent=1)
    print("\nRecorded in %s. Also obtain, on a machine with internet access:" % lock_p)
    print("  Sigma rules : git clone --depth 1 https://github.com/SigmaHQ/sigma  (point sources.sigma at sigma/rules/linux)")
    print("  NIST NSRL   : https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl")
    print("  IOC feeds   : e.g. abuse.ch exports, CISA/FBI advisory indicator files; record each snapshot date in triage.toml")


# --------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version="triagekit " + __version__)
    sp = ap.add_subparsers(dest="cmd", required=True)
    x = sp.add_parser("scan", help="triage one or more evidence folders")
    x.add_argument("evidence", nargs="*"); x.add_argument("-o", "--out", required=True)
    x.add_argument("-c", "--config"); x.add_argument("--tracekit", metavar="CASE_DIR")
    x.add_argument("--year", type=int, help="year for syslog timestamps without one")
    x.add_argument("--force", action="store_true"); x.set_defaults(f=cmd_scan)
    x = sp.add_parser("review", help="record an examiner decision on a finding")
    x.add_argument("out"); x.add_argument("finding"); x.add_argument("status", choices=STATUSES)
    x.add_argument("--note"); x.add_argument("--examiner"); x.set_defaults(f=cmd_review)
    x = sp.add_parser("report", help="re-render report.md and findings/ from a previous scan")
    x.add_argument("out"); x.set_defaults(f=cmd_report)
    x = sp.add_parser("rules", help="load and validate rules and feeds, show what will be applied")
    x.add_argument("-c", "--config"); x.add_argument("--verbose", action="store_true"); x.set_defaults(f=cmd_rules)
    x = sp.add_parser("fetch", help="download CISA KEV and MITRE ATT&CK snapshots (internet required)")
    x.add_argument("--dest", default="feeds"); x.set_defaults(f=cmd_fetch)
    a = ap.parse_args()
    try:
        a.f(a)
    except ConfigError as e:
        sys.exit("configuration error: %s" % e)

if __name__ == "__main__":
    main()
