"""
Run this once to generate your admin password hash.
Then set ADMIN_PW_HASH environment variable to the output.
"""
import hashlib
import getpass

pw = getpass.getpass("Enter admin password: ")
confirm = getpass.getpass("Confirm password: ")

if pw != confirm:
    print("Passwords do not match.")
else:
    h = hashlib.sha256(pw.encode()).hexdigest()
    print(f"\nADMIN_PW_HASH={h}")
    print("\nSet this as an environment variable before starting app.py")
    print("On Linux/Mac:  export ADMIN_PW_HASH=" + h)
    print("On Windows:    set ADMIN_PW_HASH=" + h)
    print("PythonAnywhere: add to .env or WSGI config")
