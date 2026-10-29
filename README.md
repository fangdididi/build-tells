# build-tells

**English** | [中文](README.zh-CN.md)

An agent skill that reads your release the way a stranger will — before the stranger does. Point it at the exact artifact you are about to ship (npm tarball, wheel, `dist/` folder, Electron `.asar`, Docker image export, APK/IPA, VSIX, crate) and it lists every *tell*: secrets, source maps that hand back your original code, `.env` and `.git` files that slipped in, staging hostnames, build-machine paths, paywall checks that only live in the client, debug switches, and "do not ship" notes. Each tell gets a recorded verdict, the fix goes into your build config, and the release ends with a clear outcome: `CLEAN_TO_SHIP`, `SHIP_WITH_NOTES`, `HOLD`, or `INCOMPLETE`.

Works with Claude Code, Codex, Cursor and any agent that reads `SKILL.md`. The helper is plain Python 3 with no dependencies.

## Why

People and AI agents now unpack shipped bundles routinely. Most leaks found that way need no skill at all — the key, the map, the internal URL are simply sitting in the bytes. Three habits prevent almost all of them, and this skill enforces them:

- **Audit the artifact, not the repo.** What you think you ship and what the packager actually includes are different more often than you'd guess.
- **Remove, don't hide.** Obfuscation raises reading cost; it never turns a shipped secret back into a secret. Don't ship it, move it server-side, or accept it in writing.
- **Shipped once is shipped forever.** A key in an old version stays in registries, caches and mirrors. It must be revoked, not just deleted — the report refuses to go green until you confirm rotation.

## Features

- **Opens what you actually ship:** directories, single files, zip family (`.zip .whl .jar .war .apk .aab .ipa .vsix .xpi .nupkg`), tar family (`.tgz .tar.gz .tar.xz .crate .gem`), Electron `.asar`, and nested archives two levels deep — including extension-less Docker layer blobs, recognised by magic bytes.
- **Nine tell kinds:** `KEY`, `MAP`, `STRAY`, `EXTRA`, `HOST`, `PATH`, `GATE`, `DEBUG`, `NOTE`, each with a severity and a hint.
- **Secrets never echoed:** keys are shown as `AKIA…(20 chars)`, and any secret is masked inside every other excerpt too.
- **Ship card first:** declare audience, allowlist, and what's public by design *before* looking at results. A key can only be waved through by an explicit key rule.
- **Verdict ledger:** `LEAK / MOVE / TRIM / PUBLIC / FALSE`, with reasons required where it matters; verdicts survive rebuilds by stable ids; vanished tells move to `resolved`.
- **Rotation rule:** if an earlier version already shipped, a removed secret keeps the release on `HOLD` until it is marked `--rotated`.
- **CI-ready:** exit codes for `report` (0/1/2/3) and a `diff` against a baseline that fails on any new medium-or-worse tell.
- **Manual-pass checklist** for what no pattern can see: business logic in the client, unannounced feature names, hidden endpoints, shipped prompts, real customer data, file metadata.

## Install

Clone into your agent's skills folder:

```bash
# Claude Code
git clone https://github.com/fangdididi/build-tells ~/.claude/skills/build-tells

# Codex
git clone https://github.com/fangdididi/build-tells ~/.codex/skills/build-tells

# Cursor (project skills folder)
git clone https://github.com/fangdididi/build-tells .cursor/skills/build-tells
```

Any other agent (Gemini CLI, Copilot, OpenCode, Windsurf…): point it at `SKILL.md`, or `SKILL.zh-CN.md` for Chinese.

Requirements: Python 3.8+. Nothing else.

## Usage

Ask your agent in plain words:

> "Before I publish 2.3.0, check what's in the tarball."
> "Did our Electron build leak anything?"
> "Is there a source map with our code on the production site?"

Or drive the helper yourself:

```bash
python3 scripts/tells.py init                                   # writes shipcard.json
npm pack                                                        # or: python -m build / docker save / ...
python3 scripts/tells.py scan my-lib-2.3.0.tgz --card shipcard.json
python3 scripts/tells.py judge 2c01 LEAK
python3 scripts/tells.py judge bc64 MOVE "export now checked by the server"
python3 scripts/tells.py judge 5deb PUBLIC "public status page host"
python3 scripts/tells.py report --card shipcard.json            # exit 0 clean, 1 notes, 2 hold, 3 incomplete
python3 scripts/tells.py diff baseline-ledger.json tells-ledger.json
```

| Command | What it does |
|---|---|
| `init` | Write a ship card template (never overwrites) |
| `scan ARTIFACT` | Scan, print tells, update the ledger (keeps earlier verdicts) |
| `judge ID VERDICT [WHY]` | Record a verdict by id prefix; `--rotated` confirms a secret was revoked |
| `report` | Outcome plus open issues (`UNJUDGED`, `NO_WHY`, `LEAK_PRESENT`, `ROTATE_PENDING`, `MOVE_OPEN`, `TRIM_OPEN`) |
| `diff OLD NEW` | New and gone tells between two ledgers |

## Example

Try it on the bundled demo package (its fake secrets are generated at run time):

```bash
python3 examples/make_demo.py /tmp/demo
python3 scripts/tells.py scan /tmp/demo/leaky-1.0.0.tgz --ledger /tmp/demo/ledger.json
```

```
2c014e6ffb high KEY   -      package/dist/app.js:3  AKIA…(20 chars)
0e572147c7 high KEY   -      package/dist/app.js:4  post…(50 chars)
abf182a3e5 high MAP   -      package/dist/app.js.map:1  2 sources: ../src/app.ts, ../src/pricing.ts  [2 original source file(s) recoverable verbatim]
233c3fb01e high STRAY -      package/.env:0  package/.env  [credential-shaped file shipped: .env]
bc64a8c11a med  GATE  -      package/dist/app.js:5  isPremium  [client-side check: anyone holding the artifact can flip it]
5debad693c med  HOST  -      package/dist/app.js:2  staging-api.acme-shop.example.com
493979291b med  HOST  -      package/dist/app.js:4  10.0…(9 chars)
1e652c3600 low  DEBUG -      package/dist/app.js:3  debug: true
112d91593c low  MAP   -      package/dist/app.js:6  app.js.map  [points at a map; check whether that map is served or shipped]
d55f771a0a low  NOTE  -      package/dist/app.js:5  TODO: check on server
c12496dcb4 low  PATH  -      package/notes.bak:1  /Users/dana/  [build machine path reveals account name 'dana']
243b34f82f low  STRAY -      package/notes.bak:0  package/notes.bak  [build/editor leftover shipped: notes.bak]
-- 6 files, 655 bytes, 12 tells
```

The private IP is masked because it sits inside a credential URL. From here: judge each line, fix the build (`files` allowlist, no maps in the publish, key moved server-side and revoked), re-pack, re-scan, and `report` until it says `CLEAN_TO_SHIP` or an honest `SHIP_WITH_NOTES`.

More worked scenarios (an npm library with a shipped `.env`, an Electron app with a client-only Pro check, a Docker image whose "deleted" key lives in layer 3) are in [SKILL.md](SKILL.md#examples).

## File structure

```
build-tells/
├── SKILL.md              # the skill (English)
├── SKILL.zh-CN.md        # the skill (Chinese)
├── README.md
├── README.zh-CN.md
├── LICENSE
├── scripts/
│   └── tells.py          # init / scan / judge / report / diff (stdlib only)
├── examples/
│   └── make_demo.py      # builds a deliberately leaky demo package
└── tests/
    └── test_tells.py     # python3 -m unittest discover -s tests
```

## Limits

A clean report means every known tell has a decision — not that nothing can be learned from your release. Pattern matching misses business logic, naming, and metadata; the manual pass in the skill covers those. Audit only artifacts you own or are authorized to ship.

## License

MIT © fangdididi
