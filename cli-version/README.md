# CLI Version

This folder contains the pure Python terminal version of Password Strength Checker.

## Run

The CLI requires `requests` for the HIBP breach check.

```powershell
cd D:\GitHub\Projects\password-strength-checker\cli-version
python -m pip install requests
python password_checker.py
```

For exact local testing without hidden input:

```powershell
python password_checker.py --password "Hassan@786"
```

The CLI asks for a password, analyzes it in memory, and displays:

- Minimum length result
- Lowercase letter result
- Uppercase letter result
- Number result
- Special-character result
- Common password result
- Breach status and occurrence count when available
- Final strength: WEAK, MEDIUM, or STRONG
- Effective score after hard security overrides

The CLI shows typed input while entering the password, but it does not print the plaintext password again after analysis and does not store it.

## Notes

The CLI uses the shared project logic in `..\shared\password_logic.py` and the common-password list in `..\data\10k-most-common.txt`. It does not require Flask, HTML, CSS, JavaScript, or a web server.
