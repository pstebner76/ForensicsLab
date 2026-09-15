from pathlib import Path
import hashlib
import sys
def sha256_file(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()
if len(sys.argv) < 2:
    print("Usage: python triage.py <file>")
    sys.exit(1)
target = Path(sys.argv[1])
if not target.exists():
    print(f"No such file exists: {target}")
    sys.exit(1)
if not target.is_file():
    print(f"Not a file: {target}")
    sys.exit(1)  
     
print(sha256_file(target))
