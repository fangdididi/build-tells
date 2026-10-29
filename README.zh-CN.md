# build-tells

[English](README.md) | **中文**

一个代理技能：用陌生人的眼光读你的发布包——赶在陌生人之前。把它指向你即将交付的那个产物（npm tarball、wheel、`dist/` 目录、Electron `.asar`、Docker 镜像导出、APK/IPA、VSIX、crate），它会列出每一处*破绽*：密钥、能还原原始代码的 source map、混进去的 `.env` 和 `.git`、staging 域名、构建机路径、只在客户端判断的付费校验、没关的调试开关、"do not ship" 注释。每条破绽都有记录在案的判定，修复写进构建配置，发布以一个清晰的结论收尾：`CLEAN_TO_SHIP`、`SHIP_WITH_NOTES`、`HOLD` 或 `INCOMPLETE`。

适用于 Claude Code、Codex、Cursor 以及任何能读取 `SKILL.md` 的代理。辅助脚本是纯 Python 3，无任何依赖。

## 为什么需要

现在，人和 AI 代理都会例行公事地拆开别人发出来的包。这样发现的泄露大多不需要任何技巧——key、map、内网地址就那么躺在字节里。三个习惯能挡住绝大多数问题，这个技能就是用来强制执行它们的：

- **审产物，不审仓库。** 你以为发出去的和打包器实际带上的，不一致的频率远超你的想象。
- **删除，而不是隐藏。** 混淆只提高阅读成本，永远不能让已发出的秘密重新变成秘密。要么不发，要么挪到服务端，要么白纸黑字地接受。
- **发过一次就是永远发过。** 旧版本里的 key 会一直留在包仓库、缓存和镜像站里。必须吊销，而不只是删除——在你确认轮换之前，报告不会变绿。

## 功能

- **打开你真正发出去的东西：** 目录、单文件、zip 系（`.zip .whl .jar .war .apk .aab .ipa .vsix .xpi .nupkg`）、tar 系（`.tgz .tar.gz .tar.xz .crate .gem`）、Electron `.asar`，以及两层嵌套——包括没有扩展名的 Docker 层文件，按魔数识别。
- **九类破绽：** `KEY`、`MAP`、`STRAY`、`EXTRA`、`HOST`、`PATH`、`GATE`、`DEBUG`、`NOTE`，各带严重度和提示。
- **绝不回显密钥：** key 显示为 `AKIA…(20 chars)`，并且在其他所有片段里也会被遮盖。
- **先写发布卡：** 在看结果*之前*声明受众、白名单和设计上可公开的内容。密钥只能被显式的 KEY 规则放行。
- **判定台账：** `LEAK / MOVE / TRIM / PUBLIC / FALSE`，关键处必须写理由；判定通过稳定 id 在重建之间保留；消失的破绽移入 `resolved`。
- **轮换规则：** 如果更早的版本已经发出，被删掉的密钥会让发布一直处于 `HOLD`，直到标记 `--rotated`。
- **适配 CI：** `report` 有退出码（0/1/2/3），`diff` 对比基线，出现新的中等及以上破绽即失败。
- **人工检查清单：** 覆盖规则看不到的东西——客户端里的业务逻辑、未公布的功能名、隐藏接口、随包下发的提示词、真实客户数据、文件元数据。

## 安装

克隆到代理的 skills 目录：

```bash
# Claude Code
git clone https://github.com/fangdididi/build-tells ~/.claude/skills/build-tells

# Codex
git clone https://github.com/fangdididi/build-tells ~/.codex/skills/build-tells

# Cursor（项目 skills 目录）
git clone https://github.com/fangdididi/build-tells .cursor/skills/build-tells
```

其他代理（Gemini CLI、Copilot、OpenCode、Windsurf……）：让它读取 `SKILL.zh-CN.md`（中文）或 `SKILL.md`（英文）。

环境要求：Python 3.8+，别的都不需要。

## 使用

直接用自然语言告诉代理：

> "发布 2.3.0 之前，帮我看看 tarball 里有什么。"
> "我们的 Electron 构建有没有泄露东西？"
> "生产站点上是不是挂着带源码的 source map？"

或者自己调用脚本：

```bash
python3 scripts/tells.py init                                   # 生成 shipcard.json
npm pack                                                        # 或：python -m build / docker save / ...
python3 scripts/tells.py scan my-lib-2.3.0.tgz --card shipcard.json
python3 scripts/tells.py judge 2c01 LEAK
python3 scripts/tells.py judge bc64 MOVE "导出改由服务端校验"
python3 scripts/tells.py judge 5deb PUBLIC "公开状态页域名"
python3 scripts/tells.py report --card shipcard.json            # 退出码 0 干净、1 有备注、2 拦截、3 未完成
python3 scripts/tells.py diff baseline-ledger.json tells-ledger.json
```

| 命令 | 作用 |
|---|---|
| `init` | 生成发布卡模板（不会覆盖已有文件） |
| `scan ARTIFACT` | 扫描、打印破绽、更新台账（保留之前的判定） |
| `judge ID VERDICT [WHY]` | 按 id 前缀记录判定；`--rotated` 确认密钥已吊销 |
| `report` | 给出结论和未结问题（`UNJUDGED`、`NO_WHY`、`LEAK_PRESENT`、`ROTATE_PENDING`、`MOVE_OPEN`、`TRIM_OPEN`） |
| `diff OLD NEW` | 两份台账之间新增和消失的破绽 |

## 示例

用自带的演示包试一下（里面的假密钥在运行时生成）：

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

私有 IP 被遮盖，是因为它位于一个带凭据的连接串里。接下来：逐条判定，修构建（`files` 白名单、发布时不带 map、key 挪到服务端并吊销），重新打包、复扫，然后 `report`，直到结论是 `CLEAN_TO_SHIP` 或如实的 `SHIP_WITH_NOTES`。

更多完整场景（发出过 `.env` 的 npm 库、只在客户端校验 Pro 的 Electron 应用、"删掉的" key 其实还在第 3 层的 Docker 镜像）见 [SKILL.zh-CN.md](SKILL.zh-CN.md#示例)。

## 文件结构

```
build-tells/
├── SKILL.md              # 技能（英文）
├── SKILL.zh-CN.md        # 技能（中文）
├── README.md
├── README.zh-CN.md
├── LICENSE
├── scripts/
│   └── tells.py          # init / scan / judge / report / diff（仅标准库）
├── examples/
│   └── make_demo.py      # 生成一个故意"漏洞百出"的演示包
└── tests/
    └── test_tells.py     # python3 -m unittest discover -s tests
```

## 局限

干净的报告意味着每条已知破绽都有了决定——而不是你的发布包里什么都看不出来。模式匹配看不到业务逻辑、命名和元数据，技能里的人工检查负责这些。只审计你拥有或有权发布的产物。

## 许可证

MIT © fangdididi
