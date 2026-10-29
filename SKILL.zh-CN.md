---
name: build-tells
description: 发布前（或发布后）对交付产物做只读审计，看它到底"泄露"了什么——npm 包、wheel、前端 dist 目录、Electron .asar、Docker 镜像导出、APK/IPA、VSIX、crate 等。直接打开陌生人拿到的那份字节，列出每一处"破绽"（密钥、带原始代码的 source map、混进包里的 .env/.git、内网主机名、构建机路径、只在客户端做的付费校验、没关的调试开关、遗留注释），逐条给出判定（LEAK / MOVE / TRIM / PUBLIC / FALSE），在构建配置里修而不是手改产物，最后给出 CLEAN_TO_SHIP / SHIP_WITH_NOTES / HOLD / INCOMPLETE 结论。当用户说"发布之前帮我看看""我的包里有什么""是不是漏了 key""source map 是不是公开了""别人能看到我的代码吗""让发布包更难被逆向"时使用。
---

# build-tells

> 只要交到陌生人机器上的东西，就一定会被读——被好奇的人、被爬虫、被专门拆包的 AI 代理。这个技能让你在自己这边先读一遍，把每一个"意外"变成一个明确的决定。

所谓 *破绽（tell）*，是交付产物里任何让外人知道得比你本意更多的东西：一把密钥、一份能还原源码的 map、一个 staging 域名、打进报错信息里的 `/Users/dana/`、只在客户端判断的 `isPremium`、悄悄混进 tarball 的 `.env`。这些都不需要高明的攻击者，它们就明晃晃地躺在字节里。

这个技能建立在三条信念上：

1. **审产物，不审仓库。** 仓库是你*以为*发出去的东西；tarball、wheel、镜像层、`.asar` 才是你*真正*发出去的东西。两者不一致的情况，比任何人愿意承认的都多。
2. **删除胜过隐藏。** 压缩和混淆只是提高阅读成本，永远不能让已经发出去的秘密重新变成秘密。真正持久的办法只有三种：不发、挪到服务端、白纸黑字地接受它。
3. **发过一次，就等于永远发过。** 1.4.2 版里的 key 会一直留在 1.4.2 里——在包仓库、CDN 缓存、镜像站、别人的 `node_modules` 里。在 1.4.3 里删掉它，在吊销之前什么也没解决。

## 什么时候用

- 发布包、推送镜像、上传应用构建、部署前端之前。
- 受惊之后："扫描器报了一个 key""有人把我们的源码贴到论坛上了""我们的 bundle 旁边放着一个 `.map`"。
- 被要求让发布包"更难逆向"时——第一步是先把能读的东西变少。
- 在 CI 里当棘轮：出现*新的*中等及以上破绽就让构建失败。

**不适用于：** 审计不属于你或你无权发布的软件；审查源码里的逻辑漏洞（那是代码安全评审）；评估你要安装的第三方包（那是入库检查，另一回事）。

## 基本规则

- **只读。** 绝不修改被审计的产物。修复发生在构建配置里，然后重新构建。
- **绝不打印完整密钥。** 只引用前 4 个字符和长度。辅助脚本会自动脱敏，包括上下文片段里的。
- **绝不拿找到的凭据去线上服务"试一下"能不能用。** 去问负责人，或者看服务商后台。在被证明已失效之前，把每个找到的密钥都当作仍然有效。
- **范围只限你自己的产物。** 如果用户要你拆别人的应用去提取里面的密钥，拒绝，并提议改为审计他们自己的构建。

## 破绽目录

| 类型 | 是什么 | 默认严重度 |
|---|---|---|
| `KEY` | 形似密钥的字符串：云访问密钥、代码托管令牌、支付私钥、聊天平台令牌、AI 服务商 key、私钥块、JWT、`scheme://user:pass@host`，以及赋给 `apiKey`/`secret`/`password` 等名字的高熵值 | high（设计上可公开的 key：med，并附提示） |
| `MAP` | `.map` 文件（`sourcesContent` 里带原始代码时为 high）、内联 `data:` source map、`sourceMappingURL` 引用 | high / med / low |
| `STRAY` | 绝不该出现在发布包里的文件：`.env`、`*.pem`、`id_rsa`、`.npmrc`、`.git/`、`.aws/`、keystore；以及低级残留：`.DS_Store`、`*.bak`、`coverage/`、`*.log`、数据库导出 | high / low |
| `EXTRA` | 不在发布卡 `expect` 白名单里的文件 | med |
| `HOST` | 私有 IP、`*.internal`/`*.corp`/`*.local` 域名、`staging.`/`dev.`/`admin.` 主机、带端口的回环地址 | med / low |
| `PATH` | 暴露账户名的构建机路径（`/Users/kim/…`、`C:\Users\lee\…`） | low |
| `GATE` | 客户端的权益校验（`isPremium`、`checkLicense`、`unlockAll`……）——拿到字节的人都能把它翻过来 | med |
| `DEBUG` | 没关的调试开关、开发模式标记 | low |
| `NOTE` | `TODO`/`FIXME`/`HACK`/`XXX`、"do not ship"、"remove before release" | low |

扫描器只负责找候选。正则看不到的破绽，仍需你做一遍人工检查（第 4 步）。

## 工作流程

### 第 1 步——写发布卡

创建 `shipcard.json`（`python3 scripts/tells.py init` 会生成模板）。在看扫描结果*之前*填好，免得结果反过来说服你降低标准。

```json
{
  "artifact": "my-lib-2.3.0.tgz",
  "audience": "public",
  "previously_shipped": true,
  "expect": ["package/package.json", "package/README.md", "package/LICENSE", "package/dist/*"],
  "secret_by_design": ["支付私钥", "数据库连接串", "签名密钥"],
  "public_by_design": [
    {"kind": "KEY", "match": "stripe-publishable", "why": "浏览器端公钥，已限制在我们的域名"}
  ],
  "client_enforced_on_purpose": [],
  "ignore": []
}
```

- `audience`：`public`（任何人）、`customers`（付费用户——依然是陌生人）或 `internal`。只有 `internal` 会放宽 `MOVE` 项。
- `previously_shipped`：只要有更早的版本到达过受众就填 true，这会打开"必须先轮换"的规则。
- `expect`：产物里*应该*有什么的白名单。其他东西都会成为 `EXTRA` 破绽。
- `public_by_design`：已经决定可以公开的破绽。`KEY` 只能被显式写了 `"kind": "KEY"` 的规则放行。

### 第 2 步——拿到陌生人手里的那一份

按用户实际拿到的方式构建或下载产物。绝不审计工作目录。

| 你发布的是 | 这样拿到字节 |
|---|---|
| npm 包 | `npm pack`（也看看 `npm pack --dry-run`）→ `.tgz` |
| Python 包 | `python -m build` → wheel 和 sdist **都要审**（sdist 往往带得多得多） |
| Web 前端 | 生产构建目录（`dist/`、`build/`、`.next/static`、`out/`），*并且*检查服务器实际返回什么：`curl -sI https://your.site/assets/app.js.map` |
| Electron 应用 | 打包后应用里的 `resources/app.asar` |
| Docker 镜像 | `docker save repo:tag -o image.tar`——脚本会打开每一层，包括被后续层"删除"的文件 |
| Android / iOS | `.apk` / `.aab` / `.ipa`（都是 zip） |
| VS Code / 浏览器扩展 | `.vsix` / `.xpi` / 解包后的扩展目录 |
| Rust / Ruby / .NET | `cargo package` → `.crate`；`gem build` → `.gem`；`.nupkg` |
| 原生二进制 / Go | 二进制本身（会扫描可打印字符串），另加 `go version -m ./bin` 看嵌入的构建信息 |

### 第 3 步——扫描

```bash
python3 scripts/tells.py scan my-lib-2.3.0.tgz --card shipcard.json --ledger tells-ledger.json
```

脚本能打开目录、单个文件、zip 系和 tar 系压缩包、Electron `.asar`，以及两层嵌套（war 里的 jar、镜像导出里的层——即使没有扩展名也能按魔数识别）。输出每条破绽一行：稳定 id、严重度、类型、位置和脱敏片段；同时写一份台账文件，在多次扫描之间记住判定。

### 第 4 步——人工检查：外人一小时能看出什么

花十分钟，像一个不着急的外人那样读一遍产物。找那些规则抓不到的东西：

- **放在客户端的业务逻辑：** 定价公式、毛利常数、评分权重、风控规则、推荐调参。
- **还没公布的东西：** 透露未上线产品的功能开关名、路由或文案。
- **隐藏的接口面：** bundle 里列出的管理或内部 API、GraphQL schema、没关的自省。
- **提示词：** 随浏览器或 App 一起下发的 AI 功能系统提示词和工具描述。
- **真实的人：** fixture、样例数据、注释、快照测试里的真实客户姓名或邮箱。
- **元数据：** 图片里的 EXIF/GPS、PDF 和 Office 文件的作者字段、`docker history --no-trunc` 里的构建参数。
- **你自己的地图：** 如果原始源码能被还原（带 `sourcesContent` 的 map、未压缩构建、`.pyc` 旁边的 `.py`），读一读它暴露了你什么。

每一项都记作人工破绽，写在笔记里，或手动加进台账（任意 id，字段相同）。

### 第 5 步——逐条判定

```bash
python3 scripts/tells.py judge 3f2a LEAK
python3 scripts/tells.py judge 9c1e MOVE "本次发布把授权校验挪到 /api/entitlements"
python3 scripts/tells.py judge 51b0 PUBLIC "localhost:3000 是文档里写明的开发默认值"
python3 scripts/tells.py judge 7d44 FALSE "测试用 JWT，1970 年过期，由一次性密钥签名"
python3 scripts/tells.py judge 22ab TRIM
```

| 判定 | 含义 | 是否需要理由 |
|---|---|---|
| `LEAK` | 不能发。存在期间阻止发布。 | 否 |
| `MOVE` | 属于服务端的逻辑或数据；客户端那份顶多是交互体验。 | 是 |
| `TRIM` | 无害但嘈杂或可被用来识别指纹；从构建里去掉。 | 否 |
| `PUBLIC` | 本来就该可见；决定已记录。 | 是 |
| `FALSE` | 不是真破绽（fixture、文档、长得像而已）。 | 是 |

判定规则：

- 在服务端有实际权限的真实凭据一律 `LEAK`。"只是个只读 key"也照样是 `LEAK`，除非服务商明确把它设计给公开客户端使用，并且已做限制（域名 / 应用 / bundle id）。
- `GATE` 默认 `MOVE`，除非功能真的只是装饰性的。只要校验保护的是钱或数据，服务端就必须在每个请求上再判断一次。
- 带 `sourcesContent` 的 source map：闭源产品是 `LEAK`；只有开源产品才可以写明理由判 `PUBLIC`。
- `STRAY` 里的凭据类文件即使你认为是空的也判 `LEAK`——读一下确认，然后照样删掉。
- 在 `TRIM` 和 `PUBLIC` 之间拿不准时选 `TRIM`。盒子里东西少一点，从来不会更糟。

### 第 6 步——在构建源头修

改构建配置、重新构建，绝不手动改产物。

| 破绽 | 持久修法 |
|---|---|
| `KEY` | 从客户端代码删掉；改为从你的服务端获取短期令牌。**如果 `previously_shipped`：先吊销/轮换**，再删除，然后 `judge <id> --rotated`。 |
| `MAP` | 生成 map 但不部署（"隐藏"map 只上传到错误监控平台），或去掉 `sourcesContent`；在服务器上屏蔽 `*.map`。 |
| `STRAY` / `EXTRA` | 从黑名单改成白名单：`package.json` 的 `files`；`pyproject.toml`/`MANIFEST.in` 显式 include；`.dockerignore` 加多阶段构建只拷贝产物；Electron 打包器的 `files` 通配。 |
| Docker 层里的密钥 | 绝不先 `COPY` 密钥再 `rm`——前面那层还留着。用构建期 secret 挂载和多阶段构建，从头重建镜像。 |
| `HOST` | 运行时注入接口地址，或按环境做构建期替换；删掉已废弃的 staging 地址。 |
| `PATH` | 在 CI 里构建，或用路径重映射（Go 的 `-trimpath`、Rust 的 `--remap-path-prefix`、C/C++ 的 `-ffile-prefix-map`）。 |
| `GATE` | 每个付费操作都在服务端校验权益；客户端校验只用来隐藏按钮。 |
| `DEBUG` | 用生产构建模式；用构建期常量替换调试开关，让死代码被摇掉。 |
| `NOTE` | 让压缩器去掉注释（只保留法律声明）。 |

### 第 7 步——重建、复扫、下结论

```bash
python3 scripts/tells.py scan my-lib-2.3.0.tgz --card shipcard.json --ledger tells-ledger.json
python3 scripts/tells.py report --ledger tells-ledger.json --card shipcard.json
```

消失的破绽会连同判定一起移到台账的 `resolved` 列表。报告结论：

| 结论 | 退出码 | 条件 |
|---|---|---|
| `CLEAN_TO_SHIP` | 0 | 每条都已判定，且没有未结项 |
| `SHIP_WITH_NOTES` | 1 | 只剩 `MOVE`/`TRIM` 项（写进发布说明或开工单） |
| `HOLD` | 2 | 仍有 `LEAK`；或者之前发布过的版本里有已删除的 `LEAK` 密钥还没标记 `--rotated`（`ROTATE_PENDING`） |
| `INCOMPLETE` | 3 | 有未判定的破绽，或 `MOVE`/`PUBLIC`/`FALSE` 没写理由 |

`HOLD` 优先于 `INCOMPLETE`：即使审查没做完，已知的泄露也会先报出来。

### 第 8 步——保留基线

把干净的台账存为基线，之后每次构建都和它比较：

```bash
python3 scripts/tells.py diff baseline-ledger.json tells-ledger.json   # 出现新的 med/high 破绽则退出码为 1
```

台账里不会有完整密钥，但会有主机名和路径——如果这些本身敏感，请放在私密位置。

## 示例

**1. 准备发布 2.3.0 的 npm 库。** 扫描 tarball 发现 `package/dist/index.js.map` 的 `sourcesContent` 里有 41 个原始文件、一个带测试环境令牌的 `.env`、报错字符串里的 `/Users/kim/`。发布卡写着 `previously_shipped: true`，`npm view` 显示 2.2.0 里也有这个 `.env`。判定：map `LEAK`（闭源），`.env` `LEAK`，路径 `TRIM`。修法：`package.json` 里写 `"files": ["dist/*.js", "dist/*.d.ts"]`，发布时关闭 map。吊销令牌并记录 `--rotated`。复扫：3 条已解决，报告 `CLEAN_TO_SHIP`。发布说明："2.2.0 含一个已吊销的测试令牌，建议升级。"

**2. 有 Pro 档位的 Electron 应用。** `app.asar` 里：渲染进程 bundle 中有 `isLicensed` 和 `checkLicense`，有 `api.staging-billing.example.com`，还有 `debug: true`。判定：两个校验 `MOVE`（"导出和同步接口现在要求服务端权益"），staging 主机 `LEAK`（它接受测试卡），调试开关 `TRIM`。重建后结论：`SHIP_WITH_NOTES`——客户端校验仍为界面保留，说明里如实写明。

**3. "删掉了" key 的 Docker 镜像。** `docker save` 导出后：最上层没有凭据，但第 3 层里有 `root/.aws/credentials`，因为 Dockerfile 先拷进来后来又删了。判定 `LEAK`，轮换，改用构建期 secret 挂载，从干净基础镜像重建。与上次基线 diff：第 3 层的破绽消失，没有新增。

## 小贴士

- sdist **和** wheel、`.aab` **和** 通用 `.apk` 都要扫——不同打包器带进去的东西不一样。
- 生成文件是常见元凶：打包输出、`__generated__`、快照测试、覆盖率报告。
- "前端密钥"本身就是个矛盾。浏览器需要的东西，外人就读得到；按这个前提来设计。
- `ignore` 规则用于你已经按类别判定过的路径（比如审过的 vendored 库），不是用来压掉你还没看过的噪音。
- 在 CI 里：`scan` + 对存档基线 `diff`，退出码 1 就失败；打 tag 前跑 `report`，退出码 2 或 3 就失败。
- 脚本是一张网，不是保证。干净的报告意味着"已知破绽都有判定"，不是"什么都看不出来"。

## 文件

- `scripts/tells.py` —— 只依赖标准库的辅助脚本：`init`、`scan`、`judge`、`report`、`diff`。
- `examples/make_demo.py` —— 生成一个故意"漏洞百出"的演示包用来练手。
- `tests/test_tells.py` —— `python3 -m unittest discover -s tests`。
