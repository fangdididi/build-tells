#!/usr/bin/env python3
"""build-tells: read-only audit of what a shipped artifact gives away.

Reads a directory, a single file, or an archive (zip family, tar family,
Electron .asar; nested archives two levels deep) exactly as a stranger would
receive it, lists every "tell", and keeps a verdict ledger so a release can be
judged CLEAN / NOTES / HOLD / INCOMPLETE.

Standard library only. Never prints a full secret.
"""
import argparse, fnmatch, hashlib, io, json, math, os, re, struct, sys, tarfile, zipfile
from datetime import datetime, timezone

VERSION = "1.0.0"
MAX_FILE = 20 * 1024 * 1024      # largest single file whose text is scanned
MAX_ARCHIVE = 1024 * 1024 * 1024  # largest archive/layer opened in memory
MAX_PER_FILE_KIND = 25
VERDICTS = ("LEAK", "MOVE", "TRIM", "PUBLIC", "FALSE")
NEEDS_WHY = ("MOVE", "PUBLIC", "FALSE")
SEV_RANK = {"high": 3, "med": 2, "low": 1}

ZIP_EXT = (".zip", ".whl", ".jar", ".war", ".ear", ".apk", ".aar", ".vsix", ".xpi", ".nupkg", ".ipa", ".egg")
TAR_EXT = (".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".crate", ".gem")

# ---------------------------------------------------------------- patterns
KEY_RULES = [
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), None),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), None),
    ("github-fine-grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"), None),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), None),
    ("stripe-secret", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"), None),
    ("stripe-publishable", re.compile(r"\bpk_live_[A-Za-z0-9]{16,}\b"), "publishable-by-design: confirm and mark PUBLIC"),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), None),
    ("openai-style-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}"), None),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "often public-by-design (Firebase/Maps) if restricted by referrer/app; check restrictions"),
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), None),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "decode the payload: a long-lived service token is a LEAK, a sample is FALSE"),
    ("credential-url", re.compile(r"\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@\"'<>]{1,64}:[^\s@/\"'<>]{3,128}@[^\s/\"'<>]+"), None),
]
GENERIC_ASSIGN = re.compile(
    r"""(?i)\b([a-z0-9_.-]*(?:secret|passwd|password|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key))\b["']?\s*[:=]\s*["']([^"'\s]{12,200})["']""")
PLACEHOLDER = re.compile(r"(?i)(x{4,}|\*{3,}|your[_-]|changeme|example|placeholder|dummy|sample|redacted|<[^>]*>|\$\{|\{\{|%s|process\.env|os\.environ|getenv|todo|replace[_-]?me|test|fake)")
HOST_RULES = [
    ("private-ip", re.compile(r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"), "med"),
    ("internal-domain", re.compile(r"\b(?:[a-z0-9-]+\.)+(?:internal|corp|intranet|lan|local|localdomain|private)\b(?![.-]?[a-z0-9])", re.I), "med"),
    ("pre-prod-host", re.compile(r"\b(?:staging|stage|stg|dev|qa|uat|preprod|sandbox|internal|admin)(?:[0-9-][a-z0-9-]*)?\.(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I), "med"),
    ("loopback-port", re.compile(r"\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0):\d{2,5}\b"), "low"),
]
PATH_RULE = re.compile(r"(?:/Users/|/home/|[A-Za-z]:\\\\?Users\\\\?)([A-Za-z0-9._-]{2,40})[/\\]")
PATH_IGNORE_USERS = {"runner", "user", "username", "you", "me", "name", "shared", "public", "default", "travis", "circleci", "vsts", "jenkins", "node", "app", "build", "builder"}
NOTE_RULE = re.compile(r"\b(?:TODO|FIXME|HACK|XXX)\b[:( ]|(?i:do not ship|remove before (?:release|ship|launch)|temporary hack|don'?t commit)")
GATE_RULE = re.compile(r"\b(?:is(?:Premium|Pro|Paid|Admin|Licensed|Subscribed|Vip|Trial(?:Expired)?)|checkLicen[cs]e|validateLicen[cs]e|licen[cs]eKey|verifyPurchase|unlockAll|paywall(?:Enabled)?|entitlements?Check|hasEntitlement)\b")
DEBUG_RULE = re.compile(r"""(?i)\b(?:debug|devMode|dev_mode|enableDebug|verbose)\b["']?\s*[:=]\s*(?:true|1|["']true["'])\b|\bDEBUG\s*=\s*True\b|NODE_ENV["']?\s*[:=]\s*["']development["']""")
SRCMAP_REF = re.compile(r"(?://|/\*)[#@] sourceMappingURL=([^\s*]+)")

STRAY_HIGH = [".env", ".env.*", "*.pem", "*.key", "id_rsa*", "id_ed25519*", "id_ecdsa*", "*.p12", "*.pfx", "*.keystore", "*.jks", ".npmrc", ".pypirc", ".netrc", ".git-credentials", "credentials.json", "service-account*.json", "*.kdbx", ".htpasswd"]
STRAY_DIR_HIGH = [".git", ".svn", ".hg", ".aws", ".ssh"]
STRAY_LOW = [".DS_Store", "Thumbs.db", "*.bak", "*.orig", "*.swp", "*.swo", "*~", "*.log", "*.tmp", "npm-debug.log*", "yarn-error.log*", ".idea", ".vscode", "coverage", "__tests__", ".nyc_output", "*.sqlite", "*.sqlite3", "*.db", "*.dump", "*.sql"]
ENV_EXAMPLE = re.compile(r"\.env\.(?:example|sample|template|dist|defaults)$")
TEXT_EXT_HINT = (".map",)


def entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def redact(s):
    s = s.strip()
    if len(s) <= 8:
        return s[:2] + "…(%d)" % len(s)
    return s[:4] + "…" + "(%d chars)" % len(s)


def fid(kind, path, token):
    return hashlib.sha1(("%s|%s|%s" % (kind, path, token)).encode("utf-8", "replace")).hexdigest()[:10]


# ---------------------------------------------------------------- reading
def _is_zip_name(n):
    return n.lower().endswith(ZIP_EXT)


def _is_tar_name(n):
    return n.lower().endswith(TAR_EXT)


def read_asar(data):
    """Return list of (path, bytes) from an Electron .asar blob."""
    if len(data) < 16:
        raise ValueError("asar too short")
    size_field, header_pickle_size = struct.unpack_from("<II", data, 0)
    if size_field != 4:
        raise ValueError("not an asar header")
    _payload, json_len = struct.unpack_from("<II", data, 8)
    header = json.loads(data[16:16 + json_len].decode("utf-8"))
    base = 8 + header_pickle_size
    out = []

    def walk(node, prefix):
        for name, ent in (node.get("files") or {}).items():
            p = prefix + name
            if "files" in ent:
                out.append((p + "/", None))
                walk(ent, p + "/")
            elif ent.get("unpacked"):
                out.append((p, b""))
            else:
                off = base + int(ent.get("offset", 0))
                out.append((p, data[off:off + int(ent.get("size", 0))]))
    walk(header, "")
    return out


def archive_kind(name, data=None):
    """'zip' | 'tar' | 'asar' | None. Extension first, then magic bytes (layer blobs have no extension)."""
    low = name.lower()
    if _is_zip_name(low):
        return "zip"
    if _is_tar_name(low):
        return "tar"
    if low.endswith(".asar"):
        return "asar"
    if not data or low.endswith((".docx", ".xlsx", ".pptx", ".odt", ".epub")):
        return None
    head = data[:4]
    try:
        if head == b"PK\x03\x04":
            zipfile.ZipFile(io.BytesIO(data)).close()
            return "zip"
        if head[:2] == b"\x1f\x8b" or data[257:262] == b"ustar":
            tarfile.open(fileobj=io.BytesIO(data), mode="r:*").close()
            return "tar"
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError):
        return None
    return None


def is_archive(name):
    return archive_kind(name) is not None


def members_of(kind, data):
    """Yield (path, bytes|None) for an archive blob; None marks a directory."""
    if kind == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                if info.is_dir():
                    yield info.filename, None
                else:
                    yield info.filename, (z.read(info) if info.file_size <= MAX_ARCHIVE else b"")
    elif kind == "tar":
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
            for m in t.getmembers():
                if m.isdir():
                    yield m.name, None
                elif m.isfile():
                    f = t.extractfile(m)
                    yield m.name, (f.read() if f and m.size <= MAX_ARCHIVE else b"")
    elif kind == "asar":
        for p, b in read_asar(data):
            yield p, b
    else:
        raise ValueError("unknown archive type")


def iter_artifact(target, depth=2):
    """Yield (display_path, bytes|None). Archives are opened (their own entry is yielded
    with empty bytes); nested archives are opened up to `depth` levels."""
    def expand(prefix, kind, data, d):
        try:
            for p, b in members_of(kind, data):
                p = p[2:] if p.startswith("./") else p
                shown = prefix + "!" + p if prefix else p
                k = archive_kind(p, b) if (b and d > 1) else None
                if k:
                    yield shown, b""
                    yield from expand(shown, k, b, d - 1)
                elif b is not None and len(b) > MAX_FILE:
                    yield shown, b""
                else:
                    yield shown, b
        except (zipfile.BadZipFile, tarfile.TarError, ValueError, struct.error, json.JSONDecodeError, EOFError, OSError) as e:
            yield (prefix or "artifact") + "!<unreadable:%s>" % type(e).__name__, b""

    if os.path.isdir(target):
        for root, dirs, files in os.walk(target):
            dirs.sort()
            rel_root = os.path.relpath(root, target)
            for dn in dirs:
                yield os.path.normpath(os.path.join(rel_root, dn)).replace(os.sep, "/") + "/", None
            for fn in sorted(files):
                full = os.path.join(root, fn)
                rel = os.path.normpath(os.path.join(rel_root, fn)).replace(os.sep, "/")
                if os.path.islink(full):
                    continue
                size = os.path.getsize(full)
                data = b""
                if size <= MAX_ARCHIVE:
                    with open(full, "rb") as fh:
                        data = fh.read()
                k = archive_kind(fn, data) if depth > 0 and data else None
                if k:
                    yield rel, b""
                    yield from expand(rel, k, data, depth)
                else:
                    yield rel, (data if len(data) <= MAX_FILE else b"")
    elif os.path.isfile(target):
        with open(target, "rb") as fh:
            data = fh.read()
        base = os.path.basename(target)
        k = archive_kind(base, data)
        if k:
            yield from expand("", k, data, depth)
        else:
            yield base, data
    else:
        raise FileNotFoundError(target)


# ---------------------------------------------------------------- scanning
def looks_binary(b):
    return b"\x00" in b[:8192]


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def excerpt(text, start, end, secret=False, token=None, mask=()):
    if secret:
        return redact(token if token is not None else text[start:end])
    s = text[max(0, start - 30):min(len(text), end + 30)]
    for t in sorted(mask, key=len, reverse=True):
        s = s.replace(t, redact(t))
    if mask:  # a secret cut by the window edge must not survive as a fragment
        for t in mask:
            for k in range(8, len(t)):
                if s.startswith(t[-k:]) or s.endswith(t[:k]):
                    s = s.replace(t[-k:], "…") if s.startswith(t[-k:]) else s[:len(s) - k] + "…"
                    break
    s = s.replace("\n", " ").replace("\r", " ")
    return s.strip()[:120]


def stray_check(path, is_dir):
    name = path.rstrip("/").split("/")[-1].split("!")[-1]
    parts = [p for p in re.split(r"[/!]", path.rstrip("/")) if p]
    if is_dir:
        if name in STRAY_DIR_HIGH:
            return "high", "repository/credential directory shipped: " + name
        for pat in STRAY_LOW:
            if fnmatch.fnmatch(name, pat):
                return "low", "editor/test/coverage directory shipped: " + name
        return None
    if any(p in STRAY_DIR_HIGH for p in parts[:-1]):
        return None  # reported once at directory level
    if ENV_EXAMPLE.search(name):
        return None
    for pat in STRAY_HIGH:
        if fnmatch.fnmatch(name, pat):
            return "high", "credential-shaped file shipped: " + name
    for pat in STRAY_LOW:
        if fnmatch.fnmatch(name, pat):
            return "low", "build/editor leftover shipped: " + name
    return None


def scan_text(path, text, findings, card):
    counts = {}

    def add(kind, sev, start, end, token, hint=None, secret=False, rule=None):
        if counts.get(kind, 0) >= MAX_PER_FILE_KIND:
            return
        counts[kind] = counts.get(kind, 0) + 1
        findings.append({
            "id": fid(kind, path, token), "kind": kind, "severity": sev, "path": path,
            "line": line_of(text, start), "rule": rule or kind.lower(),
            "excerpt": excerpt(text, start, end, secret, token, seen_tokens), "hint": hint or "",
            "match": redact(token) if secret or any(token in t for t in seen_tokens) else token[:80],
        })

    seen_tokens = set()
    for rule, rx, hint in KEY_RULES:
        for m in rx.finditer(text):
            tok = m.group(0)
            if tok in seen_tokens:
                continue
            seen_tokens.add(tok)
            if rule == "credential-url":
                pw = tok.split("://", 1)[1].split("@", 1)[0].split(":", 1)[1]
                if PLACEHOLDER.search(pw) or pw in ("pass", "password", "pwd"):
                    continue
            add("KEY", "high" if hint is None else "med", m.start(), m.end(), tok, hint, True, rule)
    for m in GENERIC_ASSIGN.finditer(text):
        val = m.group(2)
        if val in seen_tokens or PLACEHOLDER.search(val) or entropy(val) < 3.5:
            continue
        if any(val in t or t in val for t in seen_tokens):
            continue
        seen_tokens.add(val)
        add("KEY", "high", m.start(2), m.end(2), val, "named " + m.group(1) + "; confirm it is real", True, "generic-assignment")
    for rule, rx, sev in HOST_RULES:
        for m in rx.finditer(text):
            tok = m.group(0)
            if rule == "private-ip" and any(int(x) > 255 for x in re.findall(r"\d+", tok)):
                continue
            add("HOST", sev, m.start(), m.end(), tok, None, False, rule)
    for m in PATH_RULE.finditer(text):
        user = m.group(1)
        if user.lower() in PATH_IGNORE_USERS:
            continue
        add("PATH", "low", m.start(), m.end(), m.group(0), "build machine path reveals account name '%s'" % user, False, "dev-path")
    for m in NOTE_RULE.finditer(text):
        add("NOTE", "low", m.start(), m.end(), text[m.start():m.start() + 60].split("\n")[0].strip(), None, False, "note")
    for m in GATE_RULE.finditer(text):
        add("GATE", "med", m.start(), m.end(), m.group(0), "client-side check: anyone holding the artifact can flip it", False, "client-gate")
    for m in DEBUG_RULE.finditer(text):
        add("DEBUG", "low", m.start(), m.end(), m.group(0), None, False, "debug-switch")
    for m in SRCMAP_REF.finditer(text):
        ref = m.group(1)
        if ref.startswith("data:"):
            add("MAP", "high", m.start(), m.end(), ref[:80], "inline source map embedded in shipped file", False, "inline-map")
        else:
            add("MAP", "low", m.start(), m.end(), ref, "points at a map; check whether that map is served or shipped", False, "map-reference")


def scan_map(path, data, findings):
    try:
        doc = json.loads(data.decode("utf-8", "replace"))
    except ValueError:
        findings.append({"id": fid("MAP", path, "unparsed"), "kind": "MAP", "severity": "med", "path": path,
                         "line": 1, "rule": "map-file", "excerpt": "unparseable .map file", "hint": ""})
        return
    if not isinstance(doc, dict):
        return
    sources = doc.get("sources") or []
    content = doc.get("sourcesContent") or []
    with_content = sum(1 for c in content if c)
    sev = "high" if with_content else "med"
    hint = ("%d original source file(s) recoverable verbatim" % with_content) if with_content else "source file names and layout recoverable"
    sample = ", ".join(str(s) for s in sources[:3])
    findings.append({"id": fid("MAP", path, "map"), "kind": "MAP", "severity": sev, "path": path, "line": 1,
                     "rule": "map-file", "excerpt": ("%d sources: %s" % (len(sources), sample))[:120], "hint": hint})


def load_card(path):
    if not path:
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def scan(target, card=None):
    card = card or {}
    expect = card.get("expect") or []
    ignore = card.get("ignore") or []
    findings, files, total = [], 0, 0
    for path, data in iter_artifact(target):
        if any(fnmatch.fnmatch(path, g) for g in ignore):
            continue
        is_dir = data is None
        st = stray_check(path, is_dir)
        if st:
            findings.append({"id": fid("STRAY", path, "stray"), "kind": "STRAY", "severity": st[0], "path": path,
                             "line": 0, "rule": "stray", "excerpt": path, "hint": st[1]})
        if is_dir:
            continue
        files += 1
        total += len(data)
        if expect and not any(fnmatch.fnmatch(path, g) for g in expect) and not st:
            findings.append({"id": fid("EXTRA", path, "extra"), "kind": "EXTRA", "severity": "med", "path": path,
                             "line": 0, "rule": "not-in-expect", "excerpt": path, "hint": "not covered by the ship card's expect list"})
        if not data:
            continue
        if path.lower().endswith(".map"):
            scan_map(path, data, findings)
            continue
        if looks_binary(data):
            # still look for secrets in printable runs of binaries
            text = "\n".join(s.decode("latin-1") for s in re.findall(rb"[\x20-\x7e]{12,}", data))
            sub = []
            scan_text(path, text, sub, card)
            findings.extend(f for f in sub if f["kind"] in ("KEY", "HOST", "PATH"))
            continue
        scan_text(path, data.decode("utf-8", "replace"), findings, card)
    # de-duplicate ids
    seen, uniq = set(), []
    for f in findings:
        if f["id"] in seen:
            continue
        seen.add(f["id"])
        uniq.append(f)
    apply_card(uniq, card)
    return {"files": files, "bytes": total, "findings": uniq}


def apply_card(findings, card):
    for rule in card.get("public_by_design") or []:
        kind = rule.get("kind")
        rx = re.compile(rule.get("match", "^$"))
        for f in findings:
            if f.get("verdict"):
                continue
            if kind and f["kind"] != kind:
                continue
            if f["kind"] == "KEY" and kind != "KEY":
                continue  # a secret can only be waved through by an explicit KEY rule
            if rx.search(f["path"]) or rx.search(f["excerpt"]) or rx.search(f.get("rule", "")):
                f["verdict"] = "PUBLIC"
                f["why"] = rule.get("why") or "listed in ship card"
                f["auto"] = True


# ---------------------------------------------------------------- ledger
def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def merge(old, result, target):
    old = old or {}
    prev = {f["id"]: f for f in old.get("findings", [])}
    resolved = {r["id"]: r for r in old.get("resolved", [])}
    current_ids = set()
    for f in result["findings"]:
        current_ids.add(f["id"])
        p = prev.get(f["id"]) or resolved.get(f["id"])
        if p and p.get("verdict") and not f.get("auto"):
            f["verdict"], f["why"] = p["verdict"], p.get("why", "")
        if p and p.get("rotated"):
            f["rotated"] = True
        resolved.pop(f["id"], None)
    for i, p in prev.items():
        if i not in current_ids:
            r = dict(p)
            r["gone_since"] = now_iso()
            resolved[i] = r
    return {"tool": "build-tells", "version": VERSION, "artifact": target, "scanned_at": now_iso(),
            "files": result["files"], "bytes": result["bytes"],
            "findings": result["findings"], "resolved": list(resolved.values())}


def judge(ledger, fid_prefix, verdict, why="", rotated=False):
    verdict = verdict.upper() if verdict else None
    if verdict and verdict not in VERDICTS:
        raise ValueError("verdict must be one of " + ", ".join(VERDICTS))
    pool = ledger.get("findings", []) + ledger.get("resolved", [])
    hits = [f for f in pool if f["id"].startswith(fid_prefix)]
    if fid_prefix == "*":
        hits = list(pool)
    if not hits:
        raise KeyError("no finding with id " + fid_prefix)
    if len(hits) > 1 and fid_prefix != "*" and len({h["id"] for h in hits}) > 1:
        raise KeyError("ambiguous id prefix " + fid_prefix)
    for h in hits:
        if verdict:
            h["verdict"], h["why"] = verdict, why
            h.pop("auto", None)
        if rotated:
            h["rotated"] = True
    return hits


def report(ledger, card=None):
    card = card or {}
    shipped_before = bool(card.get("previously_shipped"))
    audience = card.get("audience", "public")
    issues = []
    cur = ledger.get("findings", [])
    for f in cur:
        v = f.get("verdict")
        if not v:
            issues.append(("UNJUDGED", f))
        elif v in NEEDS_WHY and not (f.get("why") or "").strip():
            issues.append(("NO_WHY", f))
        elif v == "LEAK":
            issues.append(("LEAK_PRESENT", f))
        elif v == "MOVE" and audience != "internal":
            issues.append(("MOVE_OPEN", f))
        elif v == "TRIM":
            issues.append(("TRIM_OPEN", f))
        if f["kind"] == "KEY" and v == "LEAK" and shipped_before and not f.get("rotated"):
            issues.append(("ROTATE_PENDING", f))
    for r in ledger.get("resolved", []):
        if r["kind"] in ("KEY", "STRAY") and r.get("verdict") == "LEAK" and shipped_before and not r.get("rotated"):
            issues.append(("ROTATE_PENDING", r))
    codes = {c for c, _ in issues}
    if codes & {"LEAK_PRESENT", "ROTATE_PENDING"}:
        outcome, code = "HOLD", 2
    elif codes & {"UNJUDGED", "NO_WHY"}:
        outcome, code = "INCOMPLETE", 3
    elif codes & {"MOVE_OPEN", "TRIM_OPEN"}:
        outcome, code = "SHIP_WITH_NOTES", 1
    else:
        outcome, code = "CLEAN_TO_SHIP", 0
    tally = {}
    for f in cur:
        tally[f["kind"]] = tally.get(f["kind"], 0) + 1
    return {"outcome": outcome, "exit": code, "issues": [(c, f["id"], f["kind"], f["path"]) for c, f in issues],
            "tally": tally, "files": ledger.get("files"), "artifact": ledger.get("artifact")}


def diff(old, new):
    o = {f["id"] for f in old.get("findings", [])}
    added = [f for f in new.get("findings", []) if f["id"] not in o]
    n = {f["id"] for f in new.get("findings", [])}
    gone = [f for f in old.get("findings", []) if f["id"] not in n]
    worst = max([SEV_RANK[f["severity"]] for f in added] or [0])
    return {"added": added, "gone": gone, "exit": 1 if worst >= SEV_RANK["med"] else 0}


CARD_TEMPLATE = {
    "artifact": "dist/  (or my-lib-1.2.0.tgz, app.asar, image.tar ...)",
    "audience": "public",
    "previously_shipped": False,
    "expect": ["package.json", "README.md", "LICENSE", "dist/*.js", "dist/*.d.ts"],
    "secret_by_design": ["server API keys", "database URLs", "signing keys"],
    "public_by_design": [
        {"kind": "KEY", "match": "pk_live_", "why": "Stripe publishable key, meant for browsers"},
        {"kind": "HOST", "match": "localhost:3000", "why": "documented dev-server default in README"}
    ],
    "client_enforced_on_purpose": [],
    "ignore": []
}


# ---------------------------------------------------------------- cli
def _load(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _save(p, obj):
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1, ensure_ascii=False)
        f.write("\n")


def print_table(findings, out=sys.stdout):
    order = sorted(findings, key=lambda f: (-SEV_RANK[f["severity"]], f["kind"], f["path"], f["line"]))
    for f in order:
        v = f.get("verdict") or "-"
        out.write("%-10s %-4s %-5s %-6s %s:%s  %s%s\n" % (
            f["id"], f["severity"], f["kind"], v, f["path"], f["line"], f.get("match") or f["excerpt"][:70],
            ("  [" + f["hint"] + "]") if f.get("hint") else ""))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tells.py", description="What does your shipped build give away?")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="write a ship card template")
    p.add_argument("--out", default="shipcard.json")
    p = sub.add_parser("scan", help="scan an artifact and update the ledger")
    p.add_argument("artifact")
    p.add_argument("--card")
    p.add_argument("--ledger", default="tells-ledger.json")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("judge", help="record a verdict for one finding (id prefix, or * for all)")
    p.add_argument("id")
    p.add_argument("verdict", nargs="?", choices=[v for v in VERDICTS] + [v.lower() for v in VERDICTS])
    p.add_argument("why", nargs="?", default="")
    p.add_argument("--rotated", action="store_true", help="the exposed secret has been revoked/rotated")
    p.add_argument("--ledger", default="tells-ledger.json")
    p = sub.add_parser("report", help="judge the release")
    p.add_argument("--ledger", default="tells-ledger.json")
    p.add_argument("--card")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("diff", help="new tells since a baseline ledger")
    p.add_argument("old")
    p.add_argument("new")
    a = ap.parse_args(argv)

    if a.cmd == "init":
        if os.path.exists(a.out):
            print("refusing to overwrite " + a.out, file=sys.stderr)
            return 4
        _save(a.out, CARD_TEMPLATE)
        print("wrote " + a.out)
        return 0
    if a.cmd == "scan":
        card = load_card(a.card)
        res = scan(a.artifact, card)
        old = _load(a.ledger) if os.path.exists(a.ledger) else None
        led = merge(old, res, a.artifact)
        _save(a.ledger, led)
        if a.json:
            print(json.dumps(led, indent=1, ensure_ascii=False))
        else:
            print_table(led["findings"])
            t = {}
            for f in led["findings"]:
                t[f["kind"]] = t.get(f["kind"], 0) + 1
            print("-- %d files, %d bytes, %d tells %s, ledger %s" % (
                led["files"], led["bytes"], len(led["findings"]), json.dumps(t, sort_keys=True), a.ledger))
        return 0
    if a.cmd == "judge":
        led = _load(a.ledger)
        if not a.verdict and not a.rotated:
            print("give a verdict or --rotated", file=sys.stderr)
            return 4
        if a.verdict and a.verdict.upper() in NEEDS_WHY and not a.why.strip():
            print("%s needs a reason" % a.verdict.upper(), file=sys.stderr)
            return 4
        try:
            hits = judge(led, a.id, a.verdict, a.why, a.rotated)
        except (KeyError, ValueError) as e:
            print(str(e).strip("'\""), file=sys.stderr)
            return 4
        _save(a.ledger, led)
        for h in hits:
            print("%s %s %s %s" % (h["id"], h["kind"], h.get("verdict") or "-", "rotated" if h.get("rotated") else ""))
        return 0
    if a.cmd == "report":
        led = _load(a.ledger)
        r = report(led, load_card(a.card))
        if a.json:
            print(json.dumps(r, indent=1, ensure_ascii=False))
        else:
            print("artifact: %s  files: %s" % (r["artifact"], r["files"]))
            print("tells by kind: " + json.dumps(r["tally"], sort_keys=True))
            for c, i, k, p in r["issues"]:
                print("  %-15s %s %-5s %s" % (c, i, k, p))
            print("OUTCOME: " + r["outcome"])
        return r["exit"]
    if a.cmd == "diff":
        d = diff(_load(a.old), _load(a.new))
        for f in d["added"]:
            print("+ %s %s %s %s:%s %s" % (f["id"], f["severity"], f["kind"], f["path"], f["line"], f["excerpt"][:60]))
        for f in d["gone"]:
            print("- %s %s %s %s" % (f["id"], f["severity"], f["kind"], f["path"]))
        print("-- %d new, %d gone" % (len(d["added"]), len(d["gone"])))
        return d["exit"]
    return 4


if __name__ == "__main__":
    sys.exit(main())
