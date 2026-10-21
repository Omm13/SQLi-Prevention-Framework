# Technical Details

A local lab that (1) shows how SQL injection works against an intentionally
unsafe login, (2) shows the parameterized-query fix, and (3) **monitors every
attempt with a Security Information Management (SIM) layer**: structured
logging, detection, correlation alerts and a dashboard.

Subject: Security Information Management (SIM), Semester 7.
Topic: *SQL Injection Prevention Framework application: demonstrate SQLi
exploitation and benchmark parameterized query defenses.*

> This is the detailed technical reference. For a plain-language overview,
> see the main [README](../README.md) and [EXPLAINED_SIMPLY.md](EXPLAINED_SIMPLY.md).

All testing runs against this app's own local server and SQLite file. Nothing
here targets any external system.

---

## What the project does

| Part | What it shows |
|------|---------------|
| `/vulnerable-login` | Login built by pasting user input into SQL. The controlled demo input logs in without a password. |
| `/secure-login` | Same login using a parameterized query and salted password hashes. The same input is rejected. |
| `/monitor` | **SIM dashboard**: every login attempt, what looked suspicious, and active alerts. |
| `/benchmark` | Security outcome and speed, measured at three layers with proper statistics. |

## The SIM layer (`security/`)

| Module | Job |
|--------|-----|
| `events.py` | Writes one JSON line per login attempt to `logs/security_events.jsonl`. **Passwords are never logged.** Ready for ingestion by Wazuh / Elastic / Splunk. |
| `detector.py` | Names the SQLi warning signs in submitted text (tautology pattern, comment markers, UNION/SELECT, statement terminators, time-delay calls). Combinations are required, so ordinary names like `O'Brien` are not flagged. |
| `alerts.py` | Correlates events per source IP: repeated flagged input (high), failed-login burst (medium), and a **successful login that carried injection indicators (critical)**. |

Key design point: the **detector only watches; the parameterized query
protects.** A blocked attack on the secure endpoint is still recorded, so the
attempt is visible to the people responsible for security.

Example event:

```json
{"timestamp": "2026-10-21T12:00:00.123+00:00", "event_id": "a1b2c3d4e5f6",
 "event_type": "login_attempt", "source_ip": "127.0.0.1",
 "endpoint": "/secure-login", "username": "' OR '1'='1' /*",
 "outcome": "failure", "indicators": ["comment_sequence", "quote_then_boolean"],
 "severity": "high"}
```

## Project structure

```
app.py                      Flask app: login endpoints, /monitor, /benchmark
database/database.py        SQLite layer (plaintext lab table + hashed secure table)
security/                   SIM layer: events, detector, alerts
templates/ static/          Web pages and stylesheet
tests/                      25 self-contained tests (no server needed)
benchmark/benchmark.py      Three-layer benchmark
benchmark/plot_results.py   Chart of the results
docs/EXPLAINED_SIMPLY.md    Plain-language explanation
.github/workflows/tests.yml Runs the tests on every push
```

## Quick start

```bash
git clone https://github.com/Omm13/SQLi-Prevention-Framework.git
cd SQLi-Prevention-Framework
python -m venv venv
.\venv\Scripts\Activate.ps1          # Windows PowerShell
pip install -r requirements.txt
python app.py                        # http://127.0.0.1:5000/
```

```bash
python -m pytest -v                  # tests: no running server required
python benchmark/benchmark.py        # benchmark: no running server required
python benchmark/plot_results.py     # writes benchmark/benchmark_results.png
```

### Suggested demo order (5 minutes)

1. Open `/vulnerable-login`, enter `' OR '1'='1' /*` as username and anything
   as password. Login succeeds without a valid password.
2. Open `/secure-login`, enter the same input. It is rejected.
3. Open `/monitor`. Both attempts are logged. The successful one on the
   vulnerable page raised a **critical** alert; the blocked one is recorded
   but not critical.
4. Open `/benchmark` to show the cost comparison.

## Tests (25)

Run with Flask's in-process test client against a temporary database and log,
so they are self-contained and run in CI. They cover:

- Vulnerable endpoint accepts the demo input; secure endpoint rejects it.
- Valid and wrong-password logins on both endpoints.
- **Control cases:** names with apostrophes do not crash the secure endpoint
  and are not falsely flagged; malformed input does not crash the lab endpoint.
- Secure table stores hashes, not plaintext.
- **Timing safety:** an unknown username costs the same hash check as a known
  one (otherwise response time would reveal which usernames exist).
- Logging: required fields present, valid JSON, **passwords never written**,
  blocked attempts still logged.
- Alerting: critical alert on a successful attack, high alert on repeated
  flagged input, no alert when events are spread out or from different sources.

## Benchmark

Warm-up runs discarded; median, 95th percentile and standard deviation are
reported (not mean/min/max, which a single outlier distorts). Times in
microseconds. Typical results on a development machine (yours will differ):

| Layer | Implementation | Result | Median |
|-------|----------------|--------|-------:|
| Database | String-built query | VULNERABLE | ~5 µs |
| Database | Parameterized query | BLOCKED | ~5 µs |
| Monitoring | Input inspection | n/a | ~2 µs |
| Monitoring | Inspection + log write | n/a | ~35-55 µs |
| Application | Vulnerable endpoint | VULNERABLE | ~0.7 ms |
| Application | Secure endpoint | BLOCKED | ~105 ms |

What this actually says:

1. **Parameterization is free.** At the database layer the safe and unsafe
   query run in the same time, within noise.
2. **The secure endpoint is slower because of password hashing**, not because
   of parameterization. Hashing is slow on purpose, to make password guessing
   expensive. That cost is a security feature.
3. **Monitoring is cheap.** Even with a log write, the SIM layer adds well
   under a tenth of a millisecond.

## Mapping to standards

- OWASP Top 10 (2021): **A03 Injection**, **A09 Security Logging and Monitoring Failures** (addressed by the SIM layer), **A07 Identification and Authentication Failures** (password hashing).
- CWE-89 (SQL Injection), CWE-532 (sensitive data in logs: avoided), CWE-204 (response discrepancy / user enumeration: mitigated by the dummy hash check).

## Limitations (be upfront about these)

- **The detector is heuristic.** Pattern matching can be evaded and can
  false-positive. It is a visibility aid, not a defense; the parameterized
  query is the defense. A production SIEM would add far richer rules.
- Alert correlation reads a local JSON file, in memory per request. It does not
  scale and is not tamper-proof; real deployments ship logs off-host.
- Source IP is whatever Flask reports. Behind a proxy it would need
  `X-Forwarded-For` handling.
- The vulnerable lab table stores plaintext passwords **on purpose** to keep
  the injection demo simple. Never do this in a real application.
- No rate limiting or CSRF protection on the login forms.
- SQLite's driver refuses multiple statements in one call, which blocks
  stacked-query attacks here. That is a driver quirk, not a defense, and other
  databases behave differently.
- The benchmark measures a local single-user setup. It says nothing about
  production performance.
- Set `SQLI_LAB_MODE=0` to disable the vulnerable endpoint; do not expose this
  app on an untrusted network.

## Ethical use

Everything here targets the project's own local, intentionally vulnerable
endpoint. Only test systems you own or have written permission to test.

## License

MIT. See `LICENSE` in the project root.
