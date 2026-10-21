# This Project Explained Simply

No technical background needed.

## The one-sentence version

Websites often ask you to log in. If the website is built carelessly, a
trick called **SQL injection** can let someone log in **without knowing the
password**. This project shows the trick on a practice website, shows how to
stop it, and shows how to **notice** when someone is trying it.

## An everyday analogy

Imagine a bank clerk who follows written instructions on a slip of paper:
*"Find the customer named ______ whose PIN is ______."*

- **Careless clerk (vulnerable):** whatever you write in the blanks becomes
  part of the instructions. If you write *"anyone, and ignore the PIN part"*,
  the clerk follows it. That is SQL injection: your input changed the
  instructions.
- **Careful clerk (secure):** the instructions are fixed ahead of time. What
  you write is treated only as a name and a PIN, never as instructions. That is
  a **parameterized query**.

## What is in the project

| Page | Think of it as |
|------|----------------|
| **Vulnerable Login** | The careless clerk. The practice trick works here. |
| **Secure Login** | The careful clerk. The same trick fails. |
| **Security Monitor** | The security camera room. It records every attempt, marks suspicious ones, and raises an alarm when several add up. |
| **Benchmark** | A stopwatch test: does being safe make things slower? |

## The three ideas worth remembering

**1. Prevent.** Fixed instructions (parameterized queries) make the trick
impossible. This is the real protection.

**2. Detect.** Even when an attack fails, you want to know it happened. The
Security Monitor writes every login attempt to a log and flags suspicious
input. Like a camera: it does not lock the door, but it tells you someone
tried the handle.

**3. Respond.** Alerts tell a person what to look at first:

- **Critical:** a suspicious login *succeeded*. Act now.
- **High:** several suspicious attempts from one place in a short time.
- **Medium:** many failed logins in a short time.

## What the stopwatch test found

- Safe and unsafe database lookups take **the same time**. Safety is free.
- The secure login *is* slower overall, but only because it checks passwords
  the careful way (scrambling them on purpose so stolen data is useless). That
  slowness is protection, not waste.
- The monitoring costs almost nothing.

## Honest limits

- The "suspicious input" detector is a smart guess, not a guarantee. It can
  miss things and occasionally raise a false alarm. It is a camera, not a lock.
- This is a classroom practice site on one computer, not a real bank.
- The practice login deliberately keeps passwords readable so the demo is
  easy. A real site must never do that.

## How to see it yourself (3 minutes)

1. Start the app (`python app.py`) and open `http://127.0.0.1:5000/`.
2. Vulnerable Login: type `' OR '1'='1' /*` as the username, anything as the
   password. It lets you in.
3. Secure Login: type the same thing. It refuses.
4. Open Security Monitor. Both attempts are listed, and a red **CRITICAL**
   alert shows the one that worked.

## Words you may hear

- **SQL:** the language websites use to ask databases questions.
- **Injection:** sneaking instructions in through a form field.
- **Parameterized query:** a database question whose instructions are fixed
  and whose blanks can only hold plain data.
- **Hash:** a one-way scramble of a password so the real one is never stored.
- **SIM / SIEM:** collecting security logs in one place and watching them for
  trouble.
- **Log:** a diary of what happened.
- **Alert:** an alarm raised when events add up to a pattern.
