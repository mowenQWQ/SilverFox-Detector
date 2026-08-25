# 银狐木马检测 / 隔离 / 恢复 / 清理 / IOC 更新工具 (SilverFox Detection Tool)

一个**开源、可审计**的 Windows 银狐木马（SilverFox）辅助排查工具集。
以「检测 + 隔离备份 + 恢复 + 清理 + IOC 数据库 + 自动更新」为核心：扫描常见落地点、
持久化入口、可疑外连与 **C2 命中**，把可疑文件**移动到隔离区**（默认只报告不隔离），
内置真实银狐 IOC 种子库，支持联网/离线多源自动更新恶意哈希与 C2 情报。

> 本工具是**辅助排查手段**，不替代专业杀软。删除隔离区文件前请人工确认。

## 特性（v1.55）

- **双文件架构**：`.bat` 启动器 (GBK 中文) + `SilverFoxDetect.ps1` 引擎 (UTF-8 BOM)。
  启动器不做 UAC 自启，窗口**永不闪退**；多路径搜 PowerShell + 绝对路径调用，不依赖 PATH。
- **引擎内存加载（v1.31）**：启动器以 `scriptblock::Create` 方式把引擎读入内存执行，
  磁盘上的工具文件即使被扫描/隔离也不影响运行中的引擎（配合零信任模式）。
- **单实例互斥锁（v1.32）**：文件独占锁（FileShare.None），已有实例运行时拒绝启动，
  彻底杜绝多实例并发导致报告互相污染；异常退出后锁自动释放并提示"上次未正常退出"。
- **自身防篡改（v1.32）**：`integrity.manifest` 记录全部关键文件 SHA256 并以内置 salt
  签名，启动时逐文件校验；发现篡改/替换立即红色警告并写入报告。
- **多重启动模式（v1.32）**：`/safe` 安全模式急救（检测 SafeBoot，可选 bcdedit 设置
  安全模式重启查杀）、`/offline` 离线断网急救（跳过网络扫描与在线更新，只用本地 IOC）。
- **系统免疫（v1.33）**：`/immune` 三类免疫——文件免疫（关键系统文件哈希基线）、
  Hosts 免疫（劫持条目检测 + C2 命中报警 + 只读加固）、开机免疫（启动项基线 diff，
  新增自启项即报警）；`/rebuild` 重建基线。
- **系统修复（v1.33）**：`/repair` 交互式修复 hosts（恢复默认+备份）/ DNS（异常检测+刷新缓存）/
  代理劫持（备份后关闭）/ Winsock-LSP（netsh reset），全部先备份再修复。
- **银狐修改追踪（v1.33）**：`/trace` 扫描银狐常落点目录（Temp/AppData/ProgramData/Public/启动等），
  标记伪装可执行、双扩展名、随机名文件。
- **零信任模式（v1.31）**：`/zerotrust` 下工具目录自身也纳入扫描，检测木马/样本掉入
  工具目录的场景；工具自身文件由 `Test-ToolSelfFile` 自动保护，绝不误杀、不重复检出隔离区。
- **测试样本随更新同步（v1.31）**：工具包内附无害测试样本（`测试样本_Windows/`），
  其哈希内置引擎 + `known_hashes.txt` + `update.json`，`/update` 后始终在库。
- **三处留痕**：屏幕 + `%USERPROFILE%\sf_debug.log` + 桌面报告同步写入证据。
- **默认只报告不隔离**：检测默认不动任何文件；`/quarantine` 才自动隔离（仅限明确高危
  特征：伪装系统进程 / 双扩展名 / 已知恶意哈希），避免误隔离正常软件。
- **整合单入口（v1.41, 想法11）**：根目录只保留 `银狐木马检测.bat` 一个入口，
  恢复/清理/回滚/清缓存/诊断全部通过参数调用（`/restore` `/purge` `/rollback`
  `/clearcache` `/diag`），旧独立 bat 归档到 `bin/_legacy_bat/`。
- **独立组件 · 文件占用检测（想法8, v1.55）**：`文件占用检测/占用检测.bat` 是双击即用的
  小工具，定位「谁在占用某文件/目录」（典型场景：恢复隔离文件时被记事本/Word 锁住无法移动）。
  纯标准库、零依赖（Win 走 Restart Manager API，Linux 走 `/proc` 扫描），与主工具完全解耦，
  可单独分发给需要排查占用的用户（详见 `文件占用检测/README.txt`）。
- **国际化 i18n（v1.55）**：主工具与独立组件均支持**中英双语**，UI 语言**默认跟随系统**
  （中文 / 英文），未知语言回退英文；可用 `/lang=en|zh`（主工具）或 `--lang en|zh`
  （独立 Python 工具）强制指定。启动器会先检测系统语言再向引擎透传。
- **签名验证看日期（v1.55）**：`integrity.manifest` 新增 `signed=YYYY-MM-DD` 签名日期并纳入
  签名载荷——改日期即导致签名失效；引擎校验时另做日期合法性检查（拒绝未来日期 / 时钟异常），
  进一步防篡改与防"用旧日期伪装旧版"。
- **恢复工具**：`银狐木马检测.bat /restore` 一键把隔离区文件移回原路径
  （自动兼容 OneDrive 桌面重定向，含 UAC 申请）。
- **清理工具（想法1）**：`银狐木马检测.bat /purge` 逐项选择删除隔离文件，
  二次确认 + 审计日志（`%USERPROFILE%\sf_purge_audit.log`），可选回收站模式。
- **回滚工具（想法9）**：`银狐木马检测.bat /rollback` 从回滚备份恢复被永久删除的文件。
- **缓存清理**：`银狐木马检测.bat /clearcache` 删除哈希缓存，下次检测重新计算。
- **诊断小工具**：`银狐木马检测.bat /diag` 5 步定位基础环境问题。
- **真实 IOC 种子库（离线即用）**：内置银狐样本 MD5 与 C2 域名/IP。
- **双哈希比对**：MD5 + SHA-256。
- **C2 命中检测**：进程命令行含已知 C2 域名、外部连接命中已知 C2 IP 时标记。
- **IOC 自动更新（多源容错）**：本地离线包 → 远程银狐 IOC → abuse.ch URLhaus；
  任一源失败自动跳过，离线也能用内置/本地库。
- **完全开源可审计**。

## 目录结构

```
.
├── 银狐木马检测.bat          # 唯一入口 v1.55（GBK 中文, 整合单入口, 系统语言自适应）
├── 文件占用检测/             # 独立组件：文件占用检测 (想法8, v1.55, 中英双语)
│   ├── who_is_using.py       # 核心引擎 (Win Restart Manager / Linux /proc, 零依赖, 中英双语)
│   ├── 占用检测.bat          # GBK 启动器 (双击运行)
│   └── README.txt            # 用法说明 (中英双语)
├── README.md                 # 本文件
├── LICENSE                   # MIT 许可证
├── .gitignore                # 忽略报告/隔离区/自动 IOC/临时文件
├── integrity.manifest        # 关键文件 SHA256 + 防篡改签名 + 签名日期
├── 测试样本_Windows/         # 无害测试样本（验证检测能力）
└── bin/
    ├── SilverFoxDetect.ps1   # 检测引擎 v1.55（7 模块 + 全模式 + 风险评分引擎 + i18n）
    ├── Restore.ps1           # 恢复引擎（/restore）
    ├── Purge.ps1             # 清理引擎（/purge, 逐项选择+二次确认+审计）
    ├── Rollback.ps1          # 回滚引擎（/rollback）
    ├── Clear-Cache.ps1       # 缓存清理（/clearcache）
    ├── Verify-ExitFlag.ps1   # 退出标记验签
    ├── whitelist.txt         # 白名单
    ├── _legacy_bat/          # 旧版独立 bat 归档（v1.41 前入口）
    ├── ioc/
    │   ├── known_hashes.txt  # 手动维护哈希库（MD5+SHA256）
    │   ├── known_c2.txt      # 手动维护 C2 域名/IP
    │   ├── auto_hashes.txt   # 自动更新生成的哈希库（gitignore）
    │   └── auto_c2.txt       # 自动更新生成的 C2 库（gitignore）
    └── update/
        └── update.json       # 本地离线更新包
```

## 使用方法

1. 把整个仓库放到 Windows 机器（保持 `bin/` 目录结构完整）。
2. **右键「以管理员身份运行」** `银狐木马检测.bat`（非管理员也能跑，只是 HKLM/服务
   扫描项受限；普通权限时脚本会询问是否申请 UAC）。
3. 第一次窗口里会先打印横幅，**按任意键继续**——这是确认窗口本身没问题。
4. 检测过程把结果写到桌面 `银狐木马检测报告_<时间戳>.txt`，同时输出到
   `%USERPROFILE%\sf_debug.log`（崩溃时的关键证据）和当前目录 `sf_run.log`。
5. 非系统目录的普通进程归入 `进程观察清单_<时间戳>.txt`（仅参考，不处理）。

### 参数

| 参数 | 作用 |
|---|---|
| `/quarantine` | 自动隔离（仅明确高危特征：伪装系统进程/双扩展名/已知恶意哈希） |
| `/restore` | 进入恢复模式（调用 Restore.ps1，移回隔离文件） |
| `/purge` | 进入清理模式（调用 Purge.ps1，逐项选择删除隔离文件） |
| `/rollback` | 进入回滚模式（调用 Rollback.ps1，从回滚备份恢复被删文件） |
| `/clearcache` | 清理哈希缓存（调用 Clear-Cache.ps1） |
| `/diag` | 诊断模式（5 步定位基础环境问题） |
| `/mem` | 内存内容检测（进程内存 C2/反射/编码特征 + Run 内容 + 任务脚本本体） |
| `/update` | 手动全量更新 IOC |
| `/autoupdate` | 强制自动更新（含 URLhaus 大库） |
| `/full` | 全盘扫描模式（较慢） |
| `/nohash` | 跳过哈希比对（加速） |
| `/noquarantine` | 明确禁用自动隔离 |
| `/lang=en` `/lang=zh` | 强制界面语言（默认跟随系统：中文/英文，未知回退英文） |
5. 检测完会**自动用记事本打开报告**；关闭记事本后回到 bat，按任意键退出。

## 一闪而过 / 闪退 排查（v1.5）

按以下顺序排除：

1. **先跑 `银狐木马检测.bat /diag`**，把屏幕里 5 步的输出全部看一遍。最常见是 PowerShell 不存在
   或 `.ps1` 没在同一目录。
2. **右键「以管理员身份运行」**——某些策略下双击会被截胡。
3. **看桌面**：有没有 `银狐木马检测报告_*.txt`？有的话 PowerShell 至少启动过了，
   文件大小能说明它跑到了哪一步。
4. **看 `%USERPROFILE%\sf_debug.log`**：每行都有 `[HH:mm:ss]` 时间戳，最后一行就是
   崩的位置。
5. **看 `sf_run.log`**（启动器写在 bat 同目录）：记录 bat 自身的执行轨迹，包括
   `PowerShell exit code`。
6. 如果以上都不可见：极大可能是**杀软拦截**——把 `.bat` 和 `.ps1` 加入信任区再试。
3. 首次/过期会自动轻量更新银狐 IOC；等待扫描完成，报告自动在桌面生成并打开。
4. 按报告「处置建议」逐项核实、清理。

> **排错**：若窗口仍一闪而过，请打开 `cmd.exe`，`cd` 到脚本目录后手动运行 `银狐木马检测.bat`，可见真实报错；同时脚本会在同目录写 `debug_lastrun.log`、在用户目录写 `sf_debug.log`，便于定位。

### 命令行参数

| 参数 | 说明 |
|------|------|
| （无参数） | 关键目录模式 + 哈希比对 + 自动隔离；IOC 缺失/过期则自动轻量更新 |
| `/update` | 联网全量更新 IOC 数据库（含 abuse.ch URLhaus 大库）后退出 |
| `/autoupdate` | 扫描前强制完整更新 IOC |
| `/nohash` | 关闭哈希比对 |
| `/full` | 全盘模式：扫描当前用户目录全量（较慢） |
| `/noquarantine` | 仅报告不隔离 |
| `/restore` | 恢复模式：隔离文件移回原路径 |
| `/purge` | 清理模式：逐项选择删除隔离文件 |
| `/rollback` | 回滚模式：从回滚备份恢复 |
| `/clearcache` | 清理哈希缓存 |
| `/diag` | 诊断模式 |
| `/mem` | 内存内容检测（需管理员读取他人进程内存） |
| `/threads=N` | 哈希线程数（1-16） |
| `/immune` / `/rebuild` | 系统免疫 / 重建基线 |
| `/repair` | 系统修复（hosts/DNS/代理/Winsock） |
| `/trace` | 银狐修改追踪 |
| `/drivers` | 驱动签名审计（含手动删除） |
| `/unlock` | 解锁清单 |
| `/netblock` | 网络封锁管理 |
| `/safe` / `/offline` | 安全模式 / 离线急救 |
| `/ring0` | Ring0 提权删除 |
| `/zerotrust` | 零信任模式（工具目录自身也检测） |
| `/noshutdownguard` | 关闭关机拦截 |
| `/lang=en` / `/lang=zh` | 强制界面语言（默认跟随系统：中文/英文，未知回退英文） |

示例：`银狐木马检测.bat /full /update`、`银狐木马检测.bat /restore`

## 检测原理

| 模块 | 检测目标 |
|------|----------|
| 1 进程 / 命令行 | 非系统目录可执行文件、**伪装系统进程**（不在 System32 下的 `svchost/explorer/lsass` 等）、银狐相关可疑命令行、**C2 域名命中** |
| 2 落地文件 + 双哈希 | `Temp/AppData/ProgramData/启动/下载/文档` 下的双扩展名（*.png.exe）、随机长名 exe、与系统进程同名文件；逐文件比对 **MD5 + SHA-256** 与 IOC 库 |
| 3 注册表 | `Run/RunOnce` 自启动项里指向脚本解释器/临时目录的条目 |
| 4 计划任务 | 指向用户目录或脚本解释器的任务 |
| 5 服务 | 映像路径落在 Temp/AppData 或调用可疑程序的异常服务 |
| 6 网络 + C2 | 已建立外部连接（排除内网/回环），并标记命中已知 **C2 IP** 的外联 |
| 7 WMI | `root\subscription` 下的 WMI 持久化事件 |

命中后默认将文件**移动**到桌面隔离区（保留原路径清单），不主动删除。

## IOC 数据库与自动更新

**数据分层**（检测时取并集）：
- **内置种子库**：写进脚本的 `$BuiltinHashes` / `$BuiltinC2*`，离线兜底，真实银狐 IOC。
- **手动库**：`ioc/known_hashes.txt`（MD5/SHA256）、`ioc/known_c2.txt`，入库，社区维护。
- **自动库**：`ioc/auto_hashes.txt`、`ioc/auto_c2.txt`，由更新程序生成，gitignore。

**更新机制**：
- 运行 `银狐木马检测.bat /update` 执行全量更新（拉取远程银狐 IOC + abuse.ch URLhaus
  全量 SHA-256 大库）并写入自动库。
- 普通扫描时，若自动库**不存在或超过 7 天**，自动执行**轻量更新**（仅远程银狐 IOC，
  不拉大库，快速）。
- **离线/非在线更新**：把离线 IOC 包放到 `update/update.json`（格式见该文件），更新时
  优先读取，无需联网。适合内网分发。
- **设为定时自动更新**（计划任务，无需交互）：
  ```bat
  schtasks /create /tn "SilverFoxIOCUpdate" /tr ""C:\path\银狐木马检测.bat" /update" /sc daily /st 06:00 /rl highest
  ```

**更新源（多源容错，失败跳过）**：
1. `update/update.json`（本地离线包）
2. 远程银狐 IOC：`raw.githubusercontent.com/YD-Shell/Silverfox_Detector/main/iocs.py`
   与 `.../update/update.json`
3. abuse.ch URLhaus 通用恶意哈希大库：`https://urlhaus.abuse.ch/downloads/csv/`

## 数据来源与致谢

- 内置银狐 IOC 源自 **奇安信威胁情报中心 2026-07《银狐 Ghost 分发商投递 MODBEACON》**
  公开报告，经开源项目 `YD-Shell/Silverfox_Detector` 整理复用。
- 通用恶意哈希来自 **abuse.ch URLhaus**（明确允许防御用途下载）。
- IOC 具有时效性，请持续通过 `/update` 或自家威胁情报平台更新。

## 贡献

- **哈希/C2 IOC**：欢迎在 `ioc/known_hashes.txt`、`ioc/known_c2.txt` 提 PR，
  注明来源/时间/变种；自动库由更新程序维护，请勿手改。
- 提交前请确保 IOC 经过核实，避免误报。

## 无法运行 / 排错

若双击后窗口一闪而过或桌面没有报告，按以下顺序排查：

1. **用管理员身份运行**：在 `.bat` 上右键 →「以管理员身份运行」（最完整，可扫 HKLM/计划任务/服务）。
2. **看错误码**：v1.3 在检测阶段结束会显示返回的错误码；若非 0，请把该窗口截图反馈。
3. **手动跑 PowerShell 自解压验证**：在 `.bat` 同目录打开 PowerShell，执行
   `powershell -NoProfile -ExecutionPolicy Bypass -File .\银狐木马检测.bat` 看具体报错。
4. **确认系统有 PowerShell**：Win10/11 自带；极老系统需先安装。
5. **杀软误拦**：个别安全软件会拦截自解压/提权行为，可临时加入白名单后再试。

> 旧版（v1.2 及之前）采用 `findstr`+`certutil` 解 Base64，在部分 Windows 上会解码失败
> 导致无报告；v1.3 改为由 PowerShell 直接读取 `.bat` 自身解码，已修复该问题。

## 安全与免责声明

- 本工具基于**公开已知特征 + 启发式规则**，不能保证 100% 检出（加壳/免杀变种可能绕过）。
- 仅做「检测 + 隔离」，不主动删除文件；隔离区文件请人工确认后再清理。
- 使用本工具造成的任何后果由使用者自行承担。企业环境建议先在隔离机验证。
- 请配合火绒/360/Windows Defender 等专业杀软做全盘查杀。

## 许可证

[MIT](LICENSE) — 可自由使用、修改与再分发，但需保留版权声明。
