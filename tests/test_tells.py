import io, json, os, struct, subprocess, sys, tarfile, tempfile, unittest, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "scripts", "tells.py")
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
import tells  # noqa: E402

# Fake secrets are assembled so no real-looking token sits in this file.
AWS = "AK" + "IA" + "TESTONLY" + "23456789"
GHP = "gh" + "p_" + "a1B2c3D4e5" * 4
SK_LIVE = "sk" + "_live_" + "Zx9" * 8
PK_LIVE = "pk" + "_live_" + "Qw8" * 8
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"


def rj(p):
    with open(p) as f:
        return json.load(f)


def rb(p):
    with open(p, "rb") as f:
        return f.read()


def write(root, rel, text, mode="w"):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, mode) as f:
        f.write(text)
    return p


def make_asar(files):
    """files: dict path->bytes (flat or with one dir level)."""
    tree, blob, off = {"files": {}}, b"", 0
    for path, data in files.items():
        node = tree
        parts = path.split("/")
        for d in parts[:-1]:
            node = node["files"].setdefault(d, {"files": {}})
        node["files"][parts[-1]] = {"size": len(data), "offset": str(off)}
        blob += data
        off += len(data)
    hj = json.dumps(tree).encode()
    pad = (4 - len(hj) % 4) % 4
    inner = struct.pack("<I", len(hj)) + hj + b"\0" * pad
    header_pickle = struct.pack("<I", len(inner)) + inner
    return struct.pack("<II", 4, len(header_pickle)) + header_pickle + blob


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def kinds(self, res):
        return sorted({f["kind"] for f in res["findings"]})

    def by(self, res, kind):
        return [f for f in res["findings"] if f["kind"] == kind]

    def cli(self, *args):
        return subprocess.run([sys.executable, SCRIPT] + list(args), capture_output=True, text=True, cwd=self.d)


class KeyTests(Base):
    def scan_text(self, text, name="a.js"):
        write(self.d, name, text)
        return tells.scan(self.d)

    def test_aws_key_found_and_redacted(self):
        r = self.scan_text('k="%s"' % AWS)
        keys = self.by(r, "KEY")
        self.assertEqual(len(keys), 1)
        self.assertNotIn(AWS, json.dumps(r))
        self.assertTrue(keys[0]["excerpt"].startswith("AKIA"))

    def test_github_token(self):
        r = self.scan_text("t=" + GHP)
        self.assertEqual(self.by(r, "KEY")[0]["rule"], "github-token")

    def test_stripe_secret_high_publishable_med_with_hint(self):
        r = self.scan_text("a='%s'; b='%s'" % (SK_LIVE, PK_LIVE))
        rules = {f["rule"]: f for f in self.by(r, "KEY")}
        self.assertEqual(rules["stripe-secret"]["severity"], "high")
        self.assertEqual(rules["stripe-publishable"]["severity"], "med")
        self.assertIn("publishable", rules["stripe-publishable"]["hint"])

    def test_private_key_block(self):
        r = self.scan_text(PEM + "\nMIIE...\n", "x.txt")
        self.assertEqual(self.by(r, "KEY")[0]["rule"], "private-key-block")

    def test_credential_url(self):
        r = self.scan_text('db="mysql://app:Vq7Lp2Rz@db.example.net/x"')
        self.assertEqual(self.by(r, "KEY")[0]["rule"], "credential-url")

    def test_credential_url_placeholder_skipped(self):
        r = self.scan_text('db="mysql://app:password@db.example.net/x" e="redis://u:${PASS}@h/0"')
        self.assertEqual(self.by(r, "KEY"), [])

    def test_generic_assignment_high_entropy(self):
        r = self.scan_text('const apiKey = "Hq83kLm0Pz7xVb2N";')
        self.assertEqual(self.by(r, "KEY")[0]["rule"], "generic-assignment")

    def test_generic_assignment_placeholder_and_low_entropy_skipped(self):
        r = self.scan_text('password = "your_password_here"; secret = "aaaaaaaaaaaaaaaa"; token: "process.env.TOKEN_VALUE"')
        self.assertEqual(self.by(r, "KEY"), [])

    def test_secret_masked_in_other_excerpts(self):
        r = self.scan_text('const cfg = { k: "%s", debug: true };' % AWS)
        self.assertTrue(self.by(r, "DEBUG"))
        self.assertNotIn(AWS, json.dumps(r))

    def test_secret_in_binary_printable_run(self):
        write(self.d, "lib.so", "x", "w")
        with open(os.path.join(self.d, "lib.so"), "wb") as f:
            f.write(b"\x00\x01\x02" + ("key=" + AWS).encode() + b"\x00" * 10)
        r = tells.scan(self.d)
        self.assertEqual(len(self.by(r, "KEY")), 1)

    def test_same_token_once(self):
        r = self.scan_text("a='%s' b='%s'" % (AWS, AWS))
        self.assertEqual(len(self.by(r, "KEY")), 1)


class OtherTellTests(Base):
    def scan_text(self, text, name="a.js"):
        write(self.d, name, text)
        return tells.scan(self.d)

    def test_private_ip_and_bad_ip(self):
        r = self.scan_text('a="10.1.2.3" b="10.999.1.1" c="172.20.0.5" d="172.40.0.1"')
        got = sorted(f["match"] for f in self.by(r, "HOST"))
        self.assertEqual(got, ["10.1.2.3", "172.20.0.5"])

    def test_internal_domain(self):
        r = self.scan_text('u="https://billing.corp/api" v="db1.internal"')
        self.assertEqual(len(self.by(r, "HOST")), 2)

    def test_preprod_host(self):
        r = self.scan_text('u="https://staging-api.shop.example.com" w="https://devices.example.com"')
        hosts = [f["match"] for f in self.by(r, "HOST")]
        self.assertEqual(hosts, ["staging-api.shop.example.com"])

    def test_loopback_low(self):
        r = self.scan_text('fetch("http://localhost:8080/x")')
        self.assertEqual(self.by(r, "HOST")[0]["severity"], "low")

    def test_dev_path_user(self):
        r = self.scan_text('"/Users/kim/proj/src/a.ts" "/home/runner/work/x"')
        p = self.by(r, "PATH")
        self.assertEqual(len(p), 1)
        self.assertIn("kim", p[0]["hint"])

    def test_windows_path(self):
        r = self.scan_text(r'"C:\\Users\\lee\\src\\a.ts"')
        self.assertEqual(len(self.by(r, "PATH")), 1)

    def test_notes(self):
        r = self.scan_text("// TODO: remove\n// FIXME(x) later\n/* do not ship */\n")
        self.assertEqual(len(self.by(r, "NOTE")), 3)

    def test_note_cap_per_file(self):
        r = self.scan_text("".join("// TODO: %d\n" % i for i in range(60)))
        self.assertEqual(len(self.by(r, "NOTE")), tells.MAX_PER_FILE_KIND)

    def test_gate(self):
        r = self.scan_text("if (user.isPremium || checkLicense(k)) unlockAll()")
        self.assertEqual(len(self.by(r, "GATE")), 3)

    def test_debug(self):
        r = self.scan_text('x={debug:true}; DEBUG = True; y={"NODE_ENV":"development"}')
        self.assertEqual(len(self.by(r, "DEBUG")), 3)

    def test_map_reference_and_inline(self):
        r = self.scan_text("x\n//# sourceMappingURL=a.js.map\n/*# sourceMappingURL=data:application/json;base64,eyJ2 */")
        sev = sorted(f["severity"] for f in self.by(r, "MAP"))
        self.assertEqual(sev, ["high", "low"])

    def test_map_file_with_content_high(self):
        write(self.d, "a.js.map", json.dumps({"version": 3, "sources": ["s.ts"], "sourcesContent": ["code"]}))
        m = self.by(tells.scan(self.d), "MAP")[0]
        self.assertEqual(m["severity"], "high")
        self.assertIn("1 original", m["hint"])

    def test_map_file_without_content_med(self):
        write(self.d, "a.js.map", json.dumps({"version": 3, "sources": ["s.ts"]}))
        self.assertEqual(self.by(tells.scan(self.d), "MAP")[0]["severity"], "med")

    def test_map_file_unparseable(self):
        write(self.d, "a.js.map", "{nope")
        self.assertEqual(self.by(tells.scan(self.d), "MAP")[0]["severity"], "med")

    def test_clean_file_no_tells(self):
        r = self.scan_text("export const add = (a, b) => a + b;\n")
        self.assertEqual(r["findings"], [])


class StrayTests(Base):
    def test_env_and_keyfile_high(self):
        write(self.d, ".env", "A=1\n")
        write(self.d, "certs/server.pem", "x")
        r = tells.scan(self.d)
        st = {f["path"]: f["severity"] for f in r["findings"] if f["kind"] == "STRAY"}
        self.assertEqual(st, {".env": "high", "certs/server.pem": "high"})

    def test_env_example_ok(self):
        write(self.d, ".env.example", "A=\n")
        self.assertEqual(tells.scan(self.d)["findings"], [])

    def test_git_dir_reported_once(self):
        write(self.d, ".git/config", "[core]\n")
        write(self.d, ".git/HEAD", "ref\n")
        st = [f for f in tells.scan(self.d)["findings"] if f["kind"] == "STRAY"]
        self.assertEqual([f["path"] for f in st], [".git/"])

    def test_low_leftovers(self):
        write(self.d, ".DS_Store", "x")
        write(self.d, "a.js.bak", "x")
        write(self.d, "coverage/index.html", "x")
        st = sorted(f["path"] for f in tells.scan(self.d)["findings"] if f["kind"] == "STRAY")
        self.assertEqual(st, [".DS_Store", "a.js.bak", "coverage/"])

    def test_expect_list_extra(self):
        write(self.d, "dist/a.js", "ok")
        write(self.d, "src/a.ts", "ok")
        r = tells.scan(self.d, {"expect": ["dist/*"]})
        self.assertEqual([f["path"] for f in r["findings"] if f["kind"] == "EXTRA"], ["src/a.ts"])

    def test_ignore(self):
        write(self.d, "vendor/x.js", "// TODO: x")
        self.assertEqual(tells.scan(self.d, {"ignore": ["vendor/*"]})["findings"], [])


class ArchiveTests(Base):
    def test_tgz(self):
        p = os.path.join(self.d, "pkg.tgz")
        with tarfile.open(p, "w:gz") as t:
            data = ('k="%s"' % AWS).encode()
            i = tarfile.TarInfo("package/index.js"); i.size = len(data)
            t.addfile(i, io.BytesIO(data))
        r = tells.scan(p)
        self.assertEqual(self.by(r, "KEY")[0]["path"], "package/index.js")

    def test_zip_wheel(self):
        p = os.path.join(self.d, "x-1.0-py3-none-any.whl")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("x/__init__.py", "DEBUG = True\n")
            z.writestr("x/.env", "A=1")
        r = tells.scan(p)
        self.assertEqual(self.kinds(r), ["DEBUG", "STRAY"])

    def test_nested_archive(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("conf.txt", "host=db.internal\n")
        p = os.path.join(self.d, "app.war")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("WEB-INF/lib/inner.jar", inner.getvalue())
        r = tells.scan(p)
        self.assertEqual(self.by(r, "HOST")[0]["path"], "WEB-INF/lib/inner.jar!conf.txt")

    def test_archive_inside_directory(self):
        with zipfile.ZipFile(os.path.join(self.d, "bundle.zip"), "w") as z:
            z.writestr("a.js", "// FIXME: x")
        r = tells.scan(self.d)
        self.assertEqual(self.by(r, "NOTE")[0]["path"], "bundle.zip!a.js")

    def test_asar(self):
        p = os.path.join(self.d, "app.asar")
        with open(p, "wb") as f:
            f.write(make_asar({"main.js": b"if(isLicensed){}", "lib/cfg.json": b'{"api":"http://10.2.3.4"}'}))
        r = tells.scan(p)
        self.assertEqual(self.kinds(r), ["GATE", "HOST"])
        self.assertEqual(self.by(r, "HOST")[0]["path"], "lib/cfg.json")

    def test_corrupt_archive_reported_not_crash(self):
        p = os.path.join(self.d, "bad.zip")
        with open(p, "wb") as f:
            f.write(b"PK\x03\x04garbage")
        paths = [x for x, _ in tells.iter_artifact(p)]
        self.assertTrue(any("unreadable" in x for x in paths))

    def test_extensionless_layer_blob_sniffed(self):
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode="w") as t:
            data = b"[default]\naws_access_key_id=" + AWS.encode()
            i = tarfile.TarInfo("root/.aws/credentials"); i.size = len(data)
            t.addfile(i, io.BytesIO(data))
        p = os.path.join(self.d, "image.tar")
        with tarfile.open(p, "w") as t:
            b = layer.getvalue()
            i = tarfile.TarInfo("blobs/sha256/0f3a9c"); i.size = len(b)
            t.addfile(i, io.BytesIO(b))
        r = tells.scan(p)
        self.assertEqual(self.by(r, "KEY")[0]["path"], "blobs/sha256/0f3a9c!root/.aws/credentials")

    def test_plain_gzip_not_treated_as_archive(self):
        import gzip
        p = os.path.join(self.d, "notes.gz")
        with open(p, "wb") as f:
            f.write(gzip.compress(b"hello"))
        self.assertEqual(tells.archive_kind("notes.gz", rb(p)), None)

    def test_single_file(self):
        p = write(self.d, "one.js", "// HACK: x")
        self.assertEqual(self.by(tells.scan(p), "NOTE")[0]["path"], "one.js")

    def test_missing_target(self):
        with self.assertRaises(FileNotFoundError):
            list(tells.iter_artifact(os.path.join(self.d, "nope")))


class CardTests(Base):
    def test_public_by_design_key_requires_key_rule(self):
        write(self.d, "a.js", "k='%s'" % PK_LIVE)
        r = tells.scan(self.d, {"public_by_design": [{"match": "pk_live_", "why": "x"}]})
        self.assertIsNone(self.by(r, "KEY")[0].get("verdict"))
        r = tells.scan(self.d, {"public_by_design": [{"kind": "KEY", "match": "stripe-publishable", "why": "browser key"}]})
        k = self.by(r, "KEY")[0]
        self.assertEqual((k["verdict"], k["why"]), ("PUBLIC", "browser key"))

    def test_public_by_design_host(self):
        write(self.d, "a.js", "fetch('http://localhost:3000')")
        r = tells.scan(self.d, {"public_by_design": [{"kind": "HOST", "match": "localhost:3000", "why": "doc default"}]})
        self.assertEqual(self.by(r, "HOST")[0]["verdict"], "PUBLIC")


class LedgerTests(Base):
    def led(self, findings, resolved=()):
        return {"findings": findings, "resolved": list(resolved), "files": 1, "artifact": "x"}

    def f(self, kind="NOTE", verdict=None, why="", sev="low", i="a1", **kw):
        d = {"id": i, "kind": kind, "severity": sev, "path": "p", "line": 1, "excerpt": "", "hint": "", "verdict": verdict, "why": why}
        d.update(kw)
        return d

    def test_clean(self):
        self.assertEqual(tells.report(self.led([]))["outcome"], "CLEAN_TO_SHIP")

    def test_unjudged_incomplete(self):
        r = tells.report(self.led([self.f()]))
        self.assertEqual((r["outcome"], r["exit"]), ("INCOMPLETE", 3))

    def test_public_needs_why(self):
        self.assertEqual(tells.report(self.led([self.f(verdict="PUBLIC")]))["outcome"], "INCOMPLETE")
        self.assertEqual(tells.report(self.led([self.f(verdict="PUBLIC", why="docs")]))["outcome"], "CLEAN_TO_SHIP")

    def test_leak_holds(self):
        r = tells.report(self.led([self.f("KEY", "LEAK", sev="high"), self.f(i="b")]))
        self.assertEqual((r["outcome"], r["exit"]), ("HOLD", 2))

    def test_trim_and_move_notes(self):
        self.assertEqual(tells.report(self.led([self.f(verdict="TRIM")]))["outcome"], "SHIP_WITH_NOTES")
        self.assertEqual(tells.report(self.led([self.f("GATE", "MOVE", "server check next sprint")]))["exit"], 1)

    def test_move_ok_for_internal_audience(self):
        r = tells.report(self.led([self.f("GATE", "MOVE", "ok")]), {"audience": "internal"})
        self.assertEqual(r["outcome"], "CLEAN_TO_SHIP")

    def test_rotate_pending_on_resolved_key(self):
        gone = self.f("KEY", "LEAK", sev="high", i="k1")
        led = self.led([], [gone])
        self.assertEqual(tells.report(led, {"previously_shipped": True})["outcome"], "HOLD")
        self.assertEqual(tells.report(led, {"previously_shipped": False})["outcome"], "CLEAN_TO_SHIP")
        gone["rotated"] = True
        self.assertEqual(tells.report(led, {"previously_shipped": True})["outcome"], "CLEAN_TO_SHIP")

    def test_merge_keeps_verdicts_and_resolves(self):
        old = self.led([self.f(i="a1", verdict="TRIM"), self.f(i="b2", verdict="LEAK", kind="KEY")])
        new = tells.merge(old, {"files": 1, "bytes": 1, "findings": [self.f(i="a1")]}, "x")
        self.assertEqual(new["findings"][0]["verdict"], "TRIM")
        self.assertEqual([r["id"] for r in new["resolved"]], ["b2"])
        self.assertIn("gone_since", new["resolved"][0])

    def test_merge_reappearing_leaves_resolved(self):
        old = self.led([], [self.f(i="a1", verdict="LEAK")])
        new = tells.merge(old, {"files": 1, "bytes": 1, "findings": [self.f(i="a1")]}, "x")
        self.assertEqual(new["resolved"], [])
        self.assertEqual(new["findings"][0]["verdict"], "LEAK")

    def test_judge_prefix_and_errors(self):
        led = self.led([self.f(i="abc123"), self.f(i="abd999")])
        tells.judge(led, "abc", "trim")
        self.assertEqual(led["findings"][0]["verdict"], "TRIM")
        with self.assertRaises(KeyError):
            tells.judge(led, "ab", "TRIM")
        with self.assertRaises(KeyError):
            tells.judge(led, "zz", "TRIM")
        with self.assertRaises(ValueError):
            tells.judge(led, "abc", "MAYBE")

    def test_judge_star_and_rotated(self):
        led = self.led([self.f(i="a"), self.f(i="b")])
        tells.judge(led, "*", "FALSE", "fixture")
        self.assertEqual({x["verdict"] for x in led["findings"]}, {"FALSE"})
        tells.judge(led, "a", None, rotated=True)
        self.assertTrue(led["findings"][0]["rotated"])

    def test_diff(self):
        old = self.led([self.f(i="a")])
        new = self.led([self.f(i="a"), self.f(i="b", sev="high", kind="KEY")])
        d = tells.diff(old, new)
        self.assertEqual(([x["id"] for x in d["added"]], d["exit"]), (["b"], 1))
        self.assertEqual(tells.diff(new, old)["exit"], 0)

    def test_ids_stable_across_scans(self):
        write(self.d, "a.js", "// TODO: x\nk='%s'" % AWS)
        a = [f["id"] for f in tells.scan(self.d)["findings"]]
        b = [f["id"] for f in tells.scan(self.d)["findings"]]
        self.assertEqual(a, b)

    def test_entropy_and_redact(self):
        self.assertEqual(tells.entropy(""), 0.0)
        self.assertLess(tells.entropy("aaaa"), 0.01)
        self.assertEqual(tells.redact("abcdefghijkl"), "abcd…(12 chars)")
        self.assertEqual(tells.redact("abc"), "ab…(3)")


class CliTests(Base):
    def test_full_cycle(self):
        art = os.path.join(self.d, "art")
        write(art, "dist/a.js", "k='%s'\n// TODO: tidy\n" % AWS)
        led = os.path.join(self.d, "l.json")
        r = self.cli("scan", art, "--ledger", led)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(AWS, r.stdout)
        self.assertEqual(self.cli("report", "--ledger", led).returncode, 3)
        data = rj(led)
        key = [f for f in data["findings"] if f["kind"] == "KEY"][0]["id"]
        note = [f for f in data["findings"] if f["kind"] == "NOTE"][0]["id"]
        self.assertEqual(self.cli("judge", key, "LEAK", "--ledger", led).returncode, 0)
        self.assertEqual(self.cli("judge", note, "TRIM", "--ledger", led).returncode, 0)
        self.assertEqual(self.cli("report", "--ledger", led).returncode, 2)
        write(art, "dist/a.js", "// TODO: tidy\n")
        card = write(self.d, "card.json", json.dumps({"previously_shipped": True}))
        self.cli("scan", art, "--ledger", led)
        r = self.cli("report", "--ledger", led, "--card", card)
        self.assertEqual(r.returncode, 2)
        self.assertIn("ROTATE_PENDING", r.stdout)
        self.cli("judge", key, "--rotated", "--ledger", led)
        self.assertEqual(self.cli("report", "--ledger", led, "--card", card).returncode, 1)
        write(art, "dist/a.js", "export {}\n")
        self.cli("scan", art, "--ledger", led)
        r = self.cli("report", "--ledger", led, "--card", card)
        self.assertEqual(r.returncode, 0)
        self.assertIn("CLEAN_TO_SHIP", r.stdout)

    def test_judge_needs_why(self):
        art = os.path.join(self.d, "art")
        write(art, "a.js", "// TODO: x\n")
        led = os.path.join(self.d, "l.json")
        self.cli("scan", art, "--ledger", led)
        i = rj(led)["findings"][0]["id"]
        self.assertEqual(self.cli("judge", i, "PUBLIC", "--ledger", led).returncode, 4)
        self.assertEqual(self.cli("judge", i, "PUBLIC", "kept on purpose", "--ledger", led).returncode, 0)

    def test_init_no_overwrite(self):
        self.assertEqual(self.cli("init").returncode, 0)
        self.assertTrue(rj(os.path.join(self.d, "shipcard.json"))["expect"])
        self.assertEqual(self.cli("init").returncode, 4)

    def test_json_output_and_diff_cli(self):
        art = os.path.join(self.d, "art")
        write(art, "a.js", "x")
        l1, l2 = os.path.join(self.d, "1.json"), os.path.join(self.d, "2.json")
        r = self.cli("scan", art, "--ledger", l1, "--json")
        self.assertEqual(json.loads(r.stdout)["findings"], [])
        write(art, "b.js", "u='http://db.internal'")
        self.cli("scan", art, "--ledger", l2)
        r = self.cli("diff", l1, l2)
        self.assertEqual(r.returncode, 1)
        self.assertIn("1 new", r.stdout)

    def test_demo_builder(self):
        demo = os.path.join(HERE, "..", "examples", "make_demo.py")
        out = os.path.join(self.d, "demo")
        subprocess.run([sys.executable, demo, out], check=True, capture_output=True)
        r = tells.scan(os.path.join(out, "leaky-1.0.0.tgz"))
        self.assertTrue({"KEY", "MAP", "STRAY", "GATE", "HOST", "PATH", "NOTE", "DEBUG"} <= set(self.kinds(r)))


if __name__ == "__main__":
    unittest.main()
