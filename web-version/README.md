# Web Version

This folder contains the Flask web version of Password Strength Checker.

## Install

```powershell
cd D:\GitHub\Projects\password-strength-checker\web-version
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```powershell
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## API

Endpoint:

```text
POST /api/check-password
```

Request:

```json
{
  "password": "example"
}
```

Response:

```json
{
  "strength": "WEAK",
  "score": 4,
  "checks": {
    "minimum_length": true,
    "lowercase": true,
    "uppercase": true,
    "number": true,
    "symbol": false,
    "common_password": true,
    "breached_password": true
  },
  "breach_count": 1000,
  "breach_check_available": true
}
```

The plaintext password is never returned in the API response.
