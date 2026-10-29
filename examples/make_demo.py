#!/usr/bin/env python3
"""Build a small, deliberately leaky demo package so you can try build-tells.

The fake secrets are assembled at run time and are not valid anywhere.
Usage: python3 examples/make_demo.py OUTDIR   -> OUTDIR/leaky/ and OUTDIR/leaky-1.0.0.tgz
"""
import io, json, os, sys, tarfile

out = sys.argv[1] if len(sys.argv) > 1 else "demo-out"
root = os.path.join(out, "leaky")
os.makedirs(os.path.join(root, "dist"), exist_ok=True)

fake_key = "AK" + "IA" + "DEMO" + "7" * 12
fake_pw = "s3" + "cr3t-" + "Qz9vLm2xWp"
app_js = f"""// app bundle
const API = "https://staging-api.acme-shop.example.com/v2";
const cfg = {{ awsKey: "{fake_key}", debug: true }};
const db = "postgres://report:{fake_pw}@10.0.4.12:5432/orders";
function canExport(u) {{ return u.isPremium; }}  // TODO: check on server
//# sourceMappingURL=app.js.map
"""
srcmap = {"version": 3, "file": "app.js", "sources": ["../src/app.ts", "../src/pricing.ts"],
          "sourcesContent": ["export const margin = 0.37;", "// pricing rules"], "mappings": ""}
files = {
    "package.json": json.dumps({"name": "leaky", "version": "1.0.0", "main": "dist/app.js"}, indent=1),
    "README.md": "# leaky\nDemo package for build-tells.\n",
    "dist/app.js": app_js,
    "dist/app.js.map": json.dumps(srcmap),
    ".env": "SERVICE_TOKEN=" + "tok_" + "9" * 20 + "\n",
    "notes.bak": "built on /Users/" + "dana" + "/work/leaky\n",
}
for rel, text in files.items():
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(text)
tgz = os.path.join(out, "leaky-1.0.0.tgz")
with tarfile.open(tgz, "w:gz") as t:
    for rel, text in files.items():
        data = text.encode()
        info = tarfile.TarInfo("package/" + rel)
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
print(root)
print(tgz)
