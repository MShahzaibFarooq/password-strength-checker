# Password Strength Checker

## Overview

Password Strength Checker is a beginner-friendly cybersecurity internship project built with Flask, HTML, CSS, and vanilla JavaScript. It analyzes password strength locally and checks whether a password has appeared in known breach data using the official Have I Been Pwned Pwned Passwords API.

## Features

- Password strength classification: WEAK, MEDIUM, or STRONG
- Minimum length validation
- Lowercase, uppercase, number, and special-character checks
- Local common-password detection
- Breached-password detection through Have I Been Pwned
- Show/hide password control
- JSON API endpoint for frontend/backend communication
- Graceful handling when the online breach check is unavailable

## Security Features

- Passwords are not stored in files, logs, sessions, or a database.
- The plaintext password is never sent to Have I Been Pwned.
- The complete SHA-1 hash is never sent to Have I Been Pwned.
- Only the first 5 characters of the SHA-1 hash are sent to the HIBP range API.
- The returned hash suffixes are checked locally.
- `hmac.compare_digest` is used for hash suffix comparison.
- Local checks continue to work if the HIBP API cannot be reached.

## Technologies Used

- Python 3
- Flask
- requests
- HTML5
- CSS3
- Vanilla JavaScript

## How It Works

The browser sends a password to the local Flask backend through `POST /api/check-password`. The backend performs the password analysis in memory, checks the local common-password list, queries the HIBP range API using k-anonymity, and returns a JSON response to update the web interface.

```text
Browser
  -> HTML/CSS/JavaScript
  -> POST /api/check-password
  -> Flask
  -> Local password analysis
  -> data/10k-most-common.txt
  -> HIBP Pwned Passwords API
  -> JSON response
  -> Frontend result
```

## Password Strength Criteria

Passwords shorter than 8 characters immediately fail the minimum-length requirement and are classified as WEAK.

Scoring:

- Less than 8 characters: 0 length points and immediate WEAK
- 8 to 11 characters: +1
- 12 or more characters: +2
- Lowercase letter: +1
- Uppercase letter: +1
- Number: +1
- Special character: +1

Classification:

- Known common password: WEAK
- Known breached password: WEAK
- Score 0 to 3: WEAK
- Score 4 to 5: MEDIUM
- Score 6: STRONG

A password is not classified as STRONG just because it is long. It must satisfy character-variety requirements and must not be common or found in known breach data.

## Common Password Detection

The project uses `data/10k-most-common.txt` as a local common-password list. This list is used only to detect commonly used passwords. It is not a complete breach database.

## Breached Password Detection

The breached-password check uses the official Have I Been Pwned Pwned Passwords API:

`https://api.pwnedpasswords.com/range/{first5}`

The app calculates the SHA-1 hash locally, converts it to uppercase, sends only the first 5 hash characters to HIBP, and checks the returned suffixes locally. The plaintext password and complete SHA-1 hash are never sent to HIBP.

If the API is unavailable, times out, returns an HTTP error, or returns an unexpected response, the app displays `Breach check unavailable` and still returns the local password-strength analysis.

## Installation

```bash
python -m venv venv
```

Windows:

```bash
venv\Scripts\activate
pip install -r requirements.txt
```

## Running the Project

```bash
python app.py
```

Then open the local Flask URL, usually:

```text
http://127.0.0.1:5000
```

## Testing

Install dependencies, then run:

```bash
pytest
```

Example expected results:

| Password | Expected Result |
| --- | --- |
| `123456` | WEAK |
| `password` | WEAK and common password |
| `Password1` | Not STRONG |
| `Password123!` | Likely common or breached, therefore not STRONG |
| `Ab1!` | WEAK because it is below 8 characters |
| `abcdefgh` | WEAK because it lacks character variety |
| `ABCDEFGH` | Not STRONG |
| Long random password with lowercase, uppercase, number, and symbol | Potentially STRONG if not common or breached |

The app is also tested for empty passwords, very long passwords, spaces, Unicode characters, symbols, invalid API input, HIBP API failures, and HIBP request privacy.

## Security Considerations

This project is an educational password-strength analysis tool for cybersecurity training. It demonstrates secure API usage, password-quality checks, string handling, validation, and defensive error handling. It should not be treated as a complete enterprise password-security system.
