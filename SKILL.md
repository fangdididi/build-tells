---
name: build-tells
description: Read-only audit of what a release artifact gives away before (or after) you ship it — npm tarballs, wheels, web dist folders, Electron .asar, Docker image exports, APK/IPA, VSIX, crates. Opens the exact bytes a stranger receives, lists every "tell" (secrets, source maps with original code, stray .env/.git files, internal hosts, build-machine paths, client-side paywall checks, debug switches, leftover notes), records a verdict per tell (LEAK / MOVE / TRIM / PUBLIC / FALSE), fixes them in the build config instead of by hand, and ends with CLEAN_TO_SHIP / SHIP_WITH_NOTES / HOLD / INCOMPLETE. Use when someone says "before I publish", "what's in my bundle", "did I leak a key", "is my source map public", "can people see my code", or "harden my release against reverse engineering".
---

# build-tells

> Anything you ship to a stranger's machine will be read — by a curious person, a scraper, or an AI agent that unpacks bundles for a living. This skill does that reading first, on your side, and turns every surprise into a decision.

A *tell* is anything inside a shipped artifact that teaches an outsider more than you meant to teach: a key, a map back to your original source, a staging hostname, `/Users/dana/` baked into a stack trace, an `isPremium` check that only lives in the client, a `.env` that slipped into the tarball. None of these need a clever attacker. They are just *there*, in plain bytes.

The skill is built on three convictions:

1. **Audit the artifact, never the repo.** The repository is what you *think* you ship. The tarball, the wheel, the image layers, the `.asar` are what you *actually* ship. They differ more often than anyone likes.
2. **Removing beats hiding.** Minifying and obfuscating raise the cost of reading; they never make a shipped secret secret. The durable fixes are: don't ship it, move it to the server, or accept it in writing.
3. **Shipped once means shipped forever.** A key that went out in version 1.4.2 is still in 1.4.2 — on the registry, in CDN caches, in mirrors, in someone's `node_modules`. Deleting it from 1.4.3 fixes nothing until the key is revoked.

## When to use

- Right before publishing a package, pushing an image, uploading an app build, or deploying a front-end.
- After a scare: "a key showed up in a scanner alert", "someone posted our source on a forum", "our bundle has a `.map` next to it".
- When asked to make a release "harder to reverse engineer" — start by shrinking what's there to read.
- In CI, as a ratchet: fail the build when a *new* medium-or-worse tell appears.

**Not for:** auditing software you don't own or aren't authorized to ship; reviewing source-code logic bugs (use a code-security review); judging third-party packages you install (that is an intake check, a different job).

## Ground rules

- **Read-only.** Never modify the artifact under audit. Fixes happen in build configuration, then you rebuild.
- **Never print a full secret.** Quote the first four characters and the length. The helper redacts automatically, including in surrounding context.
- **Never "test" a found credential against the live service** to see if it works. Ask the owner or check the provider's dashboard. Treat every found secret as live until proven dead.
- **Scope is your own artifact.** If the user asks you to unpack someone else's app to extract its secrets, decline and offer to audit their own build instead.

## The tell catalogue

| Kind | What it is | Default severity |
|---|---|---|
| `KEY` | Secret-shaped strings: cloud access keys, VCS tokens, payment secret keys, chat tokens, AI-provider keys, private-key blocks, JWTs, `scheme://user:pass@host`, high-entropy values assigned to names like `apiKey`/`secret`/`password` | high (publishable-by-design keys: med, with a hint) |
| `MAP` | `.map` files (high when `sourcesContent` carries your original code), inline `data:` source maps, `sourceMappingURL` references | high / med / low |
| `STRAY` | Files that should never be in a release: `.env`, `*.pem`, `id_rsa`, `.npmrc`, `.git/`, `.aws/`, keystores; and low-grade leftovers like `.DS_Store`, `*.bak`, `coverage/`, `*.log`, database dumps | high / low |
| `EXTRA` | Files outside the ship card's `expect` allowlist | med |
| `HOST` | Private IPs, `*.internal`/`*.corp`/`*.local` names, `staging.`/`dev.`/`admin.` hosts, loopback with ports | med / low |
| `PATH` | Build-machine paths that reveal an account name (`/Users/kim/…`, `C:\Users\lee\…`) | low |
| `GATE` | Client-side entitlement checks (`isPremium`, `checkLicense`, `unlockAll`…) — anyone holding the bytes can flip them | med |
| `DEBUG` | Debug switches left on, development mode markers | low |
| `NOTE` | `TODO`/`FIXME`/`HACK`/`XXX`, "do not ship", "remove before release" | low |

The scanner finds candidates. You still do a manual pass (step 4) for the tells no regex can see.

## Workflow

### Step 1 — Write the ship card

Create `shipcard.json` (`python3 scripts/tells.py init` writes a template). Fill it in *before* looking at findings, so the findings can't talk you into lowering the bar.

```json
{
  "artifact": "my-lib-2.3.0.tgz",
  "audience": "public",
  "previously_shipped": true,
  "expect": ["package/package.json", "package/README.md", "package/LICENSE", "package/dist/*"],
  "secret_by_design": ["payment secret key", "database URL", "signing key"],
  "public_by_design": [
    {"kind": "KEY", "match": "stripe-publishable", "why": "browser key, restricted to our domains"}
  ],
  "client_enforced_on_purpose": [],
  "ignore": []
}
```

- `audience`: `public` (anyone), `customers` (paying users — still strangers), or `internal`. Only `internal` relaxes `MOVE` items.
- `previously_shipped`: true if any earlier version reached the audience. This switches on the rotation rule.
- `expect`: the allowlist of what *should* be in the artifact. Anything else becomes an `EXTRA` tell.
- `public_by_design`: tells you have already decided are fine. A `KEY` can only be waved through by a rule that explicitly says `"kind": "KEY"`.

### Step 2 — Get the stranger's copy

Build or download the artifact exactly as it reaches people. Never audit the working tree.

| You ship | Get the bytes with |
|---|---|
| npm package | `npm pack` (look at `npm pack --dry-run` too) → `.tgz` |
| Python package | `python -m build` → audit **both** the wheel and the sdist (sdists often carry far more) |
| Web front-end | the production build folder (`dist/`, `build/`, `.next/static`, `out/`), *and* check what the server answers: `curl -sI https://your.site/assets/app.js.map` |
| Electron app | `resources/app.asar` from the packaged app |
| Docker image | `docker save repo:tag -o image.tar` — the helper opens every layer, including files that a later layer "deleted" |
| Android / iOS | the `.apk` / `.aab` / `.ipa` (all zip) |
| VS Code / browser extension | `.vsix` / `.xpi` / unpacked extension folder |
| Rust / Ruby / .NET | `cargo package` → `.crate`; `gem build` → `.gem`; `.nupkg` |
| Native binary / Go | the binary itself (printable strings are scanned), plus `go version -m ./bin` for embedded build info |

### Step 3 — Scan

```bash
python3 scripts/tells.py scan my-lib-2.3.0.tgz --card shipcard.json --ledger tells-ledger.json
```

The helper opens directories, single files, zip-family and tar-family archives, Electron `.asar`, and nested archives two levels deep (a jar inside a war, a layer inside an image export — recognised by magic bytes even without an extension). Output: one line per tell with a stable id, severity, kind, location and a redacted excerpt, plus a ledger file that remembers verdicts between scans.

### Step 4 — Manual pass: what an outsider learns in an hour

Spend ten minutes reading the artifact the way an unhurried outsider would. Look for what patterns can't catch:

- **Business logic in the client:** pricing formulas, margin constants, scoring weights, fraud rules, recommendation tweaks.
- **Unannounced things:** feature-flag names, routes, or strings that reveal products not yet launched.
- **Hidden surface:** admin or internal API endpoints listed in the bundle, GraphQL schemas, introspection left on.
- **Prompts:** system prompts and tool descriptions for AI features shipped to the browser or app.
- **People:** real customer names or emails in fixtures, sample data, comments, or test snapshots.
- **Metadata:** EXIF/GPS in images, author fields in PDFs and office files, `docker history --no-trunc` showing build args.
- **Your own map:** if the original source can be rebuilt (map with `sourcesContent`, unminified build, Python `.py` next to `.pyc`), read what it says about you.

Record each as a manual tell in your notes or add it to the ledger by hand (any id, same fields).

### Step 5 — Judge every tell

```bash
python3 scripts/tells.py judge 3f2a LEAK
python3 scripts/tells.py judge 9c1e MOVE "license check moves to /api/entitlements in this release"
python3 scripts/tells.py judge 51b0 PUBLIC "localhost:3000 is the documented dev default"
python3 scripts/tells.py judge 7d44 FALSE "test fixture JWT with a 1970 expiry, signed by a throwaway key"
python3 scripts/tells.py judge 22ab TRIM
```

| Verdict | Meaning | Needs a reason |
|---|---|---|
| `LEAK` | Must not ship. Blocks the release while present. | no |
| `MOVE` | Logic or data that belongs on the server; the client copy is UX at most. | yes |
| `TRIM` | Harmless but noisy or fingerprinting; strip it from the build. | no |
| `PUBLIC` | Meant to be visible; decision recorded. | yes |
| `FALSE` | Not a real tell (fixture, documentation, look-alike). | yes |

Decision rules:

- A real credential with server-side power is always `LEAK`. "It's only a read key" is still a `LEAK` unless the provider explicitly designs it for public clients and it's restricted (domain/app/bundle-id).
- A `GATE` is `MOVE` unless the feature is genuinely cosmetic. If a check protects money or data, the server must make it again on every request.
- A source map with `sourcesContent` is `LEAK` for closed-source products and `PUBLIC` only for open-source ones with a reason.
- `STRAY` credential files are `LEAK` even if you believe they're empty — confirm by reading them, then remove them anyway.
- When unsure between `TRIM` and `PUBLIC`, choose `TRIM`. Less in the box is never worse.

### Step 6 — Fix at the source of the build

Edit build configuration, rebuild, never hand-edit the artifact.

| Tell | Durable fix |
|---|---|
| `KEY` | Remove from client code; fetch short-lived tokens from your server. **If `previously_shipped`: revoke/rotate first**, then remove, then `judge <id> --rotated`. |
| `MAP` | Generate maps but don't deploy them ("hidden" maps uploaded only to your error tracker), or drop `sourcesContent`; block `*.map` at the server. |
| `STRAY` / `EXTRA` | Switch from deny-lists to allow-lists: `files` in `package.json`; explicit includes in `pyproject.toml`/`MANIFEST.in`; `.dockerignore` plus a multi-stage build that copies only the output; packager `files` globs for Electron. |
| Docker layer secrets | Never `COPY` a secret then `rm` it — the earlier layer keeps it. Use build-time secret mounts and multi-stage builds; rebuild the image from scratch. |
| `HOST` | Inject endpoints at runtime or per-environment build defines; remove dead staging URLs. |
| `PATH` | Build in CI or use path remapping (`-trimpath` for Go, `--remap-path-prefix` for Rust, `-ffile-prefix-map` for C/C++). |
| `GATE` | Server-side entitlement check on every paid action; keep the client check only to hide buttons. |
| `DEBUG` | Production build mode; define-replace debug flags so dead code is removed. |
| `NOTE` | Let the minifier strip comments (keep legal notices only). |

### Step 7 — Rebuild, re-scan, decide

```bash
python3 scripts/tells.py scan my-lib-2.3.0.tgz --card shipcard.json --ledger tells-ledger.json
python3 scripts/tells.py report --ledger tells-ledger.json --card shipcard.json
```

Tells that disappeared move to the ledger's `resolved` list with their verdict. The report:

| Outcome | Exit | When |
|---|---|---|
| `CLEAN_TO_SHIP` | 0 | every tell judged and nothing open |
| `SHIP_WITH_NOTES` | 1 | only `MOVE`/`TRIM` items remain (write them in the release notes or a ticket) |
| `HOLD` | 2 | any `LEAK` still present, or a removed `LEAK` secret from a previously shipped version not yet marked `--rotated` (`ROTATE_PENDING`) |
| `INCOMPLETE` | 3 | tells without a verdict, or `MOVE`/`PUBLIC`/`FALSE` without a reason |

`HOLD` beats `INCOMPLETE`: a known leak is reported even if the review is unfinished.

### Step 8 — Keep the baseline

Save the clean ledger as a baseline and compare every new build against it:

```bash
python3 scripts/tells.py diff baseline-ledger.json tells-ledger.json   # exit 1 if a new med/high tell appeared
```

The ledger never contains full secrets, but it does contain hostnames and paths — keep it in a private place if those are sensitive.

## Examples

**1. An npm library about to publish 2.3.0.** Scan of the tarball finds `package/dist/index.js.map` with 41 original files in `sourcesContent`, a `.env` with a test-environment token, and `/Users/kim/` in a stack-trace string. The ship card says `previously_shipped: true`, and `npm view` shows 2.2.0 also contained the `.env`. Verdicts: map `LEAK` (closed-source), `.env` `LEAK`, path `TRIM`. Fixes: `"files": ["dist/*.js", "dist/*.d.ts"]` in `package.json`, maps disabled for publish. The token is revoked and `--rotated` recorded. Re-scan: 3 tells resolved, report `CLEAN_TO_SHIP`. Release note: "2.2.0 contained a revoked test token; upgrade recommended."

**2. An Electron app with a Pro tier.** Inside `app.asar`: `isLicensed` and `checkLicense` in the renderer bundle, `api.staging-billing.example.com`, and `debug: true`. Verdicts: both gates `MOVE` ("export and sync endpoints now require a server entitlement"), staging host `LEAK` (it accepts test cards), debug `TRIM`. Outcome after rebuild: `SHIP_WITH_NOTES` — the client gate still exists for UI, and the note says so honestly.

**3. A Docker image that "removed" a key.** `docker save` export: the top layer has no credentials, but layer 3 holds `root/.aws/credentials` because the Dockerfile copied and later deleted it. Verdict `LEAK`, rotate, switch to a build secret mount, rebuild from a clean base. The diff against the last baseline shows the layer-3 tell gone and nothing new.

## Tips

- Run the scan on the sdist **and** the wheel, the `.aab` **and** the universal `.apk` — packagers include different things.
- Generated files are the usual culprits: bundler output, `__generated__`, snapshot tests, coverage reports.
- A front-end "secret" is a contradiction. If the browser needs it, an outsider can read it; design for that.
- Ignore rules (`"ignore": [...]`) are for paths you have judged as a class (a vendored, audited library), not for silencing noise you haven't looked at.
- In CI, run `scan` + `diff` against the stored baseline and fail on exit 1; run `report` before tagging and fail on exit 2 or 3.
- The helper is a net, not a guarantee. A clean report means "no known tell left unjudged", not "nothing can be learned".

## Files

- `scripts/tells.py` — stdlib-only helper: `init`, `scan`, `judge`, `report`, `diff`.
- `examples/make_demo.py` — builds a deliberately leaky demo package to practise on.
- `tests/test_tells.py` — `python3 -m unittest discover -s tests`.
