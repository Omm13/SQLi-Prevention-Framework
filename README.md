# SQL Injection Prevention Framework

A small practice website that shows **how a common hacking trick works, how to stop it, and how to notice when someone tries it.**

Made for the Semester 7 subject *Security Information Management (SIM)*.

---

## The idea in plain words

Websites ask for a username and password. If the website is built carelessly, a trick called **SQL injection** can let someone log in **without knowing the password**.

This project has two login pages:

| Page | What it is | What happens with the trick |
|------|------------|-----------------------------|
| **Vulnerable Login** | Built the careless way (on purpose, for demo) | The trick works. You get in. |
| **Secure Login** | Built the careful way | The same trick fails. |

And one more page that watches everything:

| Page | What it is |
|------|------------|
| **Security Monitor** | A log of every login attempt. Suspicious ones are marked, and an alarm is raised when they add up. |
| **Benchmark** | A speed test: does being safe make the site slower? |

Everything runs on your own computer. Nothing here attacks any other website.

---

## Try it (about 3 minutes)

```bash
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000** in your browser, then:

1. Go to **Vulnerable Login**. Type `' OR '1'='1' /*` as the username and anything as the password. You get logged in without a real password.
2. Go to **Secure Login**. Type the same thing. It says no.
3. Go to **Security Monitor**. Both tries are listed, and a red **CRITICAL** alert marks the one that worked.

---

## What we found

- **Being safe costs nothing.** The safe way and the unsafe way of asking the database take the same time.
- **The secure login is slower overall**, but only because it checks passwords carefully on purpose. That slowness is protection.
- **Watching is cheap.** The monitoring adds almost no delay.

---

## What is in the folders

| Folder / file | In simple words |
|---------------|-----------------|
| `app.py` | The website itself |
| `security/` | The "security camera" part: logging, spotting suspicious input, raising alerts |
| `database/` | Where the demo users are stored |
| `templates/` and `static/` | How the pages look |
| `tests/` | 25 automatic checks that prove everything works |
| `benchmark/` | The speed test and its chart |
| `docs/` | Longer explanations (see below) |

Run the checks yourself: `python -m pytest`

---

## Honest limits

- The "suspicious input" detector is a smart guess, not a guarantee. It is a camera, not a lock. The real protection is the careful way the Secure Login talks to the database.
- This is a classroom practice site on one computer, not a real bank.
- The Vulnerable Login keeps passwords readable on purpose, so the demo is simple. A real website must never do this.

---

## Want more detail?

- **[docs/EXPLAINED_SIMPLY.md](docs/EXPLAINED_SIMPLY.md)** explains the whole project with an everyday analogy, for non-technical readers.
- **[docs/TECHNICAL_DETAILS.md](docs/TECHNICAL_DETAILS.md)** has the full technical reference: how the logging, detection and alerts work, benchmark numbers, standards mapping (OWASP, CWE) and limitations.

---

## Use responsibly

Only test systems you own or have written permission to test.

License: MIT (see `LICENSE`).
