# triagekit

**Sourced, explainable triage for extracted digital evidence.**

triagekit walks a folder of extracted evidence (read-only), hashes every file, and ranks what an examiner should review first as **info, low, medium or high**. Wherever possible the rating comes from a published source, not from the tool:

| Source | Publisher | What it contributes |
|---|---|---|
| [Sigma rules](https://github.com/SigmaHQ/sigma) | SigmaHQ community | Detection logic; the priority is the rule's own `level` |
| [Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CISA | CVE references; raises CVE-tagged detections one step |
| Indicator feeds (e.g. abuse.ch, CISA/FBI advisories, MISP exports) | The feed's publisher | Hash, IP, URL and domain matches |
| [National Software Reference Library](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl) | NIST | Lowers priority of known software files (known is **not** the same as safe) |
| [ATT&CK](https://attack.mitre.org) | MITRE | Technique labels only. ATT&CK assigns no severity, and neither does triagekit on its behalf |
| Local rules | You | Fill gaps; always labelled **LOCAL** in every output |

It is a companion to [tracekit](https://github.com/AshersHolland/Tracekit) but works on any evidence folder: a mounted image, an Autopsy export, collected logs.

> **Triage priorities are an order of review, not conclusions.** A finding is a lead until an examiner verifies it against the evidence.

## Design principles

triagekit is built so its output can be defended, not just produced:

- **Read-only.** Evidence is only opened for reading. The output folder may not be inside the evidence, and every file examined is listed with MD5, SHA-1 and SHA-256 in `manifest.csv`.
- **Explainable.** Each finding states the rule, the organisation whose data rated it, the reason, the innocent explanations to rule out, and the evidence (path, deleted/allocated state, inode, SHA-256, line numbers).
- **Deterministic.** The same evidence, rules, feeds and version always produce byte-identical `findings.json`. Its SHA-256 is printed in the report as the **result digest**, so anyone can re-run and compare.
- **Conservative escalation.** Correlation rules raise priority by **one step only**, can require multiple independent artifacts or source types, and show the full chain of contributing findings.
- **Nothing tuned away silently.** Allowlists, overrides and suppressed hits are listed in the report.
- **Honest coverage.** Sigma rules that need live telemetry (process creation, network connections) cannot be evaluated on a disk image. They are skipped and listed with the reason, not silently ignored.
- **No machine learning or AI scoring.** Every rating can be explained line by line.

## Requirements

- Python 3.11 or newer (standard library only)
- Optional: `pip install pyyaml` to load Sigma rules

Runs on Linux, macOS and Windows.

## Quick start

```bash
git clone https://github.com/AshersHolland/triagekit.git
cd triagekit

# Local rules only, no configuration needed
python3 triagekit.py scan /path/to/evidence -o ~/cases/case1/triage

# Straight from a tracekit case (adds deleted/allocated state and inode numbers)
python3 triagekit.py scan --tracekit ~/cases/case1 -o ~/cases/case1/triage
```

Open `triage/report.md`, or browse `triage/findings/high/` first.

### Adding published sources

```bash
python3 triagekit.py fetch --dest feeds          # CISA KEV + MITRE ATT&CK snapshots, hashed and dated
git clone --depth 1 https://github.com/SigmaHQ/sigma ../sigma
pip install pyyaml
cp triage.example.toml triage.toml               # then edit paths, case name, examiner
python3 triagekit.py rules -c triage.toml        # check what will be applied before scanning
python3 triagekit.py scan /path/to/evidence -o out -c triage.toml
```

Download feeds on an internet-connected machine and scan offline. **Never submit case files or hashes to online lookup services**; matching is done locally.

## Commands

| Command | Purpose |
|---|---|
| `scan EVIDENCE... -o OUT [-c CONFIG] [--tracekit CASE] [--year YYYY] [--force]` | Triage evidence and write the report |
| `review OUT F-0001 confirmed\|dismissed\|needs-followup\|unreviewed [--note] [--examiner]` | Record an examiner decision; the report updates |
| `report OUT` | Re-render the report from a previous scan |
| `rules [-c CONFIG] [--verbose]` | Load and validate rules and feeds; list skipped Sigma rules |
| `fetch [--dest DIR]` | Download CISA KEV and ATT&CK snapshots and record their hashes |

## Output

```
OUT/
  report.md            readable report: summary, high/medium table, sources, coverage, findings, limitations
  findings/
    high/F-0001.md     one file per finding, sorted into folders by priority
    medium/ low/ info/
  findings.json        machine-readable findings (deterministic; hashed as the result digest)
  manifest.csv         every input file with MD5, SHA-1, SHA-256, state and inode
  run.json             tool version and self-hash, config hash, source hashes, timing, suppressions
  sigma_skipped.csv    every Sigma rule not applied, with the reason
  reviews.json         examiner decisions (created by `review`, kept across re-scans)
```

## Writing rules

Local rules live in `rules/*.toml`. A rule:

```toml
[[rule]]
id = "LOCAL-FS-001"
title = "Script or executable stored in a temporary directory"   # a fact, never a conclusion
priority = "medium"
target = "file"                       # file | line
attack = []                           # optional MITRE ATT&CK technique IDs (labels only)
reason = "Why this deserves attention."
false_positives = "Innocent explanations the examiner must rule out."
  [rule.match]                        # every condition must be true
  path_regex = '^/(tmp|var/tmp|dev/shm)/'
  any_of = [ { executable = true }, { name_regex = '\.(sh|py)$' } ]
```

A correlation rule:

```toml
[[correlate]]
id = "LOCAL-COR-001"
title = "Failed and successful logins from the same address"
scope = "same_ip"                     # same_file | same_ip | same_user
requires = { all = ["LOCAL-LN-003", "LOCAL-LN-004"] }   # also: any = [...], "SIGMA:*", "IOC:*", "attack:T1070*"
window = "24h"
min_artifacts = 1                     # distinct files required
min_sources = 1                       # distinct source kinds required (local, sigma, ioc, kev)
reason = "..."
```

Thresholds are honoured per address or user before a finding can join a correlation, so six failures spread over six addresses cannot be reported as repeated failures from one of them. Full key lists are documented at the top of each file in `rules/`.

## Testing and validation

```bash
python3 -m unittest discover -s tests -v
```

The suite builds synthetic evidence and checks detection, correlation, determinism, the read-only guarantee, and that unsupported Sigma rules are reported.

Before relying on triagekit in casework, validate it against reference data with known contents, such as NIST's [CFReDS](https://cfreds.nist.gov) datasets, and record the false-positive and false-negative rates you observe alongside the tool version and rule hashes.

**Performance:** about 6,000–7,000 log lines per second on one core with all 75 log-applicable SigmaHQ Linux rules active. Non-log files are hashed at disk speed.

## Limitations

- Only rules that fit plain files and log lines are applied; live-telemetry Sigma rules are skipped and listed.
- Sigma field matching uses `key=value` pairs found on the line (e.g. auditd). Hex-encoded or differently formatted fields will not match. Aggregation conditions (`| count()`) are not supported.
- Indicator feeds and the KEV catalog are point-in-time snapshots. Indicators go stale and feeds contain errors.
- A known-software match lowers priority but does not clear a file.
- No finding does not mean nothing happened.

## Disclaimer

triagekit supports examiner judgment; it does not replace it. Whether evidence or testimony is admissible is decided by a court, case by case. Use only on evidence you are authorized to examine.

## License

MIT. See [LICENSE](LICENSE). Sigma rules, indicator feeds, the KEV catalog, NSRL and ATT&CK are not bundled and remain under their publishers' own terms.
