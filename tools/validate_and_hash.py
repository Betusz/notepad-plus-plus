# tools/validate_and_hash.py
import sys, hashlib, json, pathlib
import pefile
import lief

def is_pe(path):
    try:
        pefile.PE(path)
        return True
    except Exception:
        return False

root = pathlib.Path(sys.argv[1])
report = []
for f in root.rglob("*"):
    if not f.is_file():
        continue
    entry = {"file": str(f), "size": f.stat().st_size}
    with open(f, "rb") as fh:
        data = fh.read()
        entry["sha256"] = hashlib.sha256(data).hexdigest()
    if is_pe(str(f)):
        entry["format"] = "PE"
        try:
            bin = lief.parse(str(f))
            entry["imports"] = [imp.name for imp in bin.imports] if bin else []
            entry["sections"] = [s.name for s in bin.sections] if bin else []
        except Exception:
            entry["imports"] = []
            entry["sections"] = []
        report.append(entry)

print(json.dumps(report, indent=2))
with open(root / "report.json", "w") as out:
    out.write(json.dumps(report, indent=2))
