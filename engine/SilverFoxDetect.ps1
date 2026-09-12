# ===================== 银狐特攻 PowerShell engine v1.95 =====================
# v1.95 (v2.15.74): [2/7]新增 PE 结构启发 —— 识别"双段 overlay(尾部巨量附加数据)+加壳节(.ndata/UPX/零尺寸节)"类型的白签名捆绑投递样本
#                   (典型: 前置小存根PE + 尾部NSIS真程序 + .ndata加壳, keylogger暗桩). /struct=1(默认仅观察)/2多信号叠加/3高危即隔离;
#                   /deep-pe 开启导入表敏感API(keylogger/剪贴板/注入/下载执行)扫描. 实例样本 WeChatWin_4.1.13 哈希已入 known_hashes.
# v1.94 (v2.15.73): 全盘检测改为真全盘(所有固定分区根+深度999全递归; 此前只扫用户目录+系统关键目录浅扫, 用户反馈"不全盘")
# v1.93 (v2.15.72): 抽取 Invoke-DefExclCheck(Defender排除项检测函数), 扫描主流程新增 [9] Defender排除项检查(病毒加自身白名单让杀软失明)
# v1.92 (v2.15.71): thirdAV 检测提前到函数开头(阶段1/2 在原位置之前执行, 导致策略警告未降噪); 阶段5 StartType/阶段15 防护补 thirdAV 信息; 360 自启名加宽+进程运行判断(有360等时 Defender 策略/服务/防护停用属正常, 降为信息) + DNS 常见公共域名白名单 + 杀软自启缺失仅按已安装厂商匹配 + Sense 等非必需服务移出缺失检测
# v1.90 (v2.15.69): ①IOC 入库(假图吧工具 6域名+2 SHA256) ②Defender排除项盘根/系统目录->高危 ③restoreav 自动清除盘根排除项 ④[1/7] 强制重启特征 —— 大名单扩容(老牌CA/常用软件厂商自建), 仅"乱码/随机字符型自签"标警告, 其余降为信息; 不再自动弹处置; [8/7]编号修正
# v1.88 (v2.15.62): netblock/解锁清单输出同步 GUI 进度面板(黑窗口黑屏也能看到结果)
# v1.87 (v2.15.58): 证书列表提示增强(多数为网银/企业CA自带, 勿盲目全删) + IFEO 双 ErrorAction 清理
# v1.86 (v2.15.57): 全部交互界面小白友好 —— 解锁/网络封锁/修复菜单/驱动删除/Ring0 黑话改大白话+说明
# v1.85 (v2.15.56): 证书傻瓜式处置 —— 发现可疑自签名证书后引导用户输入序号, 自动导出备份到"证书隔离区"再从系统移除(可双击.cer恢复); 全程进度面板提示
# v1.84 (v2.15.55): 证书信任链检查 —— 扫描[8/7] + restoreav 阶段: 枚举根证书存储自签名非知名证书(病毒常装自签名证书伪造可信), 仅报告不自动删除
# v1.83 (v2.15.54): 简单兼容 —— ①[6/7] Win7 无 Get-NetTCPConnection 时 netstat -ano 回退 ②驱动恢复 Set-Service -StartupType System(PS5.1枚举不支持)改 sc.exe config start= system ③启动进度行加 OS/PS 版本摘要
# v1.82 (v2.15.53): ①加扫 C:\Windows\SysWOW64(32位镜像目录, 银狐32位样本常驻) ②交互扩展: 待核实/非文件类可疑项也弹菜单引导(只展示+建议, 不自动改) ③报告弹出确认写进度
# v1.81 (v2.15.52): ①扫描点扩展:System32 顶层+System32\drivers(银狐常驻点, 隐藏目录本已覆盖) ②伪系统进程先结束进程再隔离 ③交互菜单加"进程处置" ④驱动签名信任检查(非微软/主流签名驱动 -> 观察)
# v1.80 (v2.15.51): banner 版本残留(v1.64->动态) + restoreav 函数头版本 + 杀软状态码解码保守化(360 等自研编码不误导)
# v1.79 (v2.15.49): Get-ExecPath 展开 %SystemRoot%/%ProgramFiles% 等环境变量(服务/计划任务 PathName 可能用, 展开后验签/白名单才准确)
# v1.78 (v2.15.46): 交互盲区提示 —— 黑窗口黑屏时 Read-Host 提示同步到 GUI 进度面板(交互确认/解锁/网络封锁/修复菜单/驱动删除); restoreav 完成自动打开报告
# v1.77 (v2.15.45): ①驱动服务类型保护(WdBoot/WdFilter 恢复为 System 而非 Automatic) ②防火墙自动开启返回(黑窗口黑屏时 Read-Host 交互盲区, 改为自动+警告记录)
# v1.76 (v2.15.44): 版本残留清理(进度文件首行/审计日志)+ 防火墙自动开启改为交互确认(防误伤) + restoreav 各阶段进度同步 GUI
# v1.75 (v2.15.43): 恢复杀毒软件加"修复前后健康对比"(修复前快照 -> 修复 -> 复查对比, 直观验证效果)
# v1.74 (v2.15.42): 恢复杀毒软件再扩充3项 —— 防火墙状态(被关自动恢复)/Defender引擎状态(Get-MpComputerStatus+Set-MpPreference恢复)/IFEO进程劫持(杀软exe加Debugger, 病毒经典手法)
# v1.73 (v2.15.41): 恢复杀毒软件再扩充 —— Defender排除项检测(病毒加自身白名单)/服务缺失检测/杀软自启动项缺失检测/TamperProtection防篡改检查/代理-DNS异常提示/安全中心状态码解码
# v1.72 (v2.15.40): 恢复杀毒软件全面扩充 —— Defender策略全子键(Real-Time Protection/SpyNet/Threats) + 客户端设置 + UAC(EnableLUA) + 任务管理器/注册表编辑器禁用 + Windows Update禁用 + Defender全家服务(WdNisSvc/Sense等) + 第三方安全软件服务恢复 + hosts安全域名劫持移除 + 安全软件进程检测
# v1.71 (v2.15.39): ①待核实(REVIEW)明细直接写入报告(不再只有统计数字) ②新增 /restoreav 恢复杀毒软件(Defender策略禁用项/服务启动类型/MpCmdRun默认恢复/第三方杀软状态提示)
# v1.70 (v2.15.38): [4/7]计划任务/[5/7]服务 —— 单条目异常不再拖垮整段(每项 try/catch, 坏项跳过统计继续); catch 写完整异常类型+消息
# v1.69 (v2.15.36): [2/7] 验签挂起修复(Test-TrustedSigner/Test-SafeHarbor 仅对 PE 且 <=50MB 验签, 云盘占位/大文件不再挂起)
#                   + 进度行同步 GUI(Write-ScanProgress) + 报告头/审计版本残留清理
# v1.68 (v2.15.35): 扫描进度文件 (Write-ScanProgress -> legacy\sf_scan_progress.log), 供 GUI 主程序实时展示扫描进度
# v1.64 (v2.15.21): 层3 诊断增强 —— WndProc 收到 WM_QUERYENDSESSION 时写入 %TEMP%\sf_sg_query.log
#                    (确认消息是否到达; 若未收到且用户测试带 /f 强制关机, 用户态无法阻止)
# v1.63 (v2.15.20): 修复层3 C# 编译错误(MSG m 未初始化 CS0165 -> 隐藏窗口创建失败 -> QUERYENDSESSION 从未生效)
#                    + 对外名称规范化为「银狐检测工具」
# v1.62 (v2.15.19): 关机拦截层3 重建 —— 隐藏窗口 + 消息循环线程, WM_QUERYENDSESSION 返回 FALSE
#                    (杀 shutdown.exe 无法撤销已提交的系统关机; 必须拒绝 QUERYENDSESSION);
#                    WMI 通道改用 Register-WmiEvent (CIM 对 Win32_ProcessStartTrace 返回 null)
# v1.61 (v2.15.18): 修复 ①TrimEnd char 转换坑(白名单目录前缀双反斜杠字符串转 char 失败)
#                    ②关机拦截 WMI 订阅参数集冲突(-ClassName 与 -Query 不能同用) + System32 下 shutdown 改按命令行识别自身标记 kill
#                    ③控制台编码统一 936 (bat 移除 chcp 65001, bat GBK echo 与引擎输出一致), 修复结尾乱码
# v1.60 (v2.15.15): 签名安全港 Test-SafeHarbor + 弱信号权重下调(RANDOM_NAME_EXE 5/PERSIST_APPDATA 5/WIN_HIDDEN 5/IEX_GENERIC 5/BASE64_GENERIC 2/HIDDEN_PE 15) + 启动环境日志 sf_debug.log + 扩展 whitelist
# v2.15.16 交付修复: 文件头恢复单 BOM (双重 BOM 下 PS5.1 静默拒绝执行) + banner 版本同步 v1.60
# v1.46 GUI+API 集成: 新增 bin/SilverFoxUI.ps1 (Windows Forms 启动器) + bin/API.md (C#/Python/Java/Go 调用示例)
# v1.45 代码混淆 + 自保护强化: ①Add-Type C# 块全部 base64 编码 (DllImport/API 名源码不可见, 降杀软误报)
#                                  ②watchdog 用 cmd start /B spawn 脱离父进程 (bat 关闭/进程树被杀不连带守护)
#                                  ③敏感 API 名运行时 sf-deb 解码
# v1.45: 代码混淆 - 敏感 API/路径名运行时解码, 降杀软启发式误报
$script:_sf_d = @{}
function sf-deb([string]$n) {
  if ($script:_sf_d.ContainsKey($n)) { return $script:_sf_d[$n] }
  try { $v = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($n)) } catch { $v = $n }
  $script:_sf_d[$n] = $v; return $v
}
# v1.44 自保护增强: ①进程级保护提前到参数解析后立即生效(任何模式分支/扫描之前)
#                       ②DACL 移除 Everyone/Users 终止权限 (非管理员无法 taskkill)
#                       ③watchdog bin/SelfGuard.ps1: 被任务管理器/taskkill/恶意软件强制终止后自动重启引擎
#                       ④/bruteprotect 硬保护: [硬保护API] BreakOnTermination (被用户态 kill -> 蓝屏威慑)
#                       ⑤/bruteprotect 默认关闭, 普通模式无蓝屏风险
# v1.43 用户反馈修复: ①退出乱码 (Console.OutputEncoding 936→UTF8 与 cmd chcp 65001 对齐)
#                       ②隐藏属性可执行降级观察 (Bcut/Inno Setup dll 不再误报高危, 走白名单/签名豁免)
#                       ③PE+图片/无扩展名 高危判定前查签名/白名单 (CPU-Z 等知名软件免报)
#                       ④默认扫描后弹交互菜单 (有文件类高危时), /interactive 旧行为保留, 加 /noask 关闭
#                       ⑤whitelist.txt 增 CPUID / 必剪 知名签名+目录
# v1.42 复查修复: ①EnvUser 定义提前(此前 catch 引用空值) ②WMI 关机进程并入事件(只删不解析→丢失) ③进程 Path 为空回退 CIM+观察清单(不再静默丢弃) ④cmdBad+c2pat 重复 Flag 合并 ⑤计划任务 Win7/PS5.1 兼容(Get-ScheduledTask 探测+schtasks 回退) ⑥死代码清理
# v1.40 安全加固: ①Quarantine 假成功修复(Move-Item Stop+复核) ②SYSTEM 删除防 %VAR% 误删 ③白名单目录前缀补分隔符 ④关机守护只拦非系统路径 ⑤/threads 参数修复 ⑥退出标记防符号链接 ⑦路径提取支持空格
# v1.39 新增:
#  1) 恶意程序网络封锁 - C2 IP 外联/域名命中自动封禁 (防火墙按 IP + 按进程出站); /netblock 查看解除; /nonetblock 关闭
# v1.38 新增:
#  1) 威胁锁定 (检测出先锁定) - 高危文件/问题驱动检出后自动加锁防篡改/防恢复; 隔离/删除前自动解锁; /unlock 手动解锁; 锁定清单.txt
# v1.37 新增:
#  1) 驱动审计交互删除 - /drivers 检测后手动选择删除问题驱动 (Ring0 提权: 停服务->备份->逐级提权删文件; DriverStore 条目提示 pnputil)
# v1.36 新增:
#  1) 驱动审计 /drivers (想法6) - 过期签名/脆弱驱动(BYOVD)检测
#     - 枚举已加载驱动(Win32_SystemDriver) + 数字签名校验(有效/过期/吊销/未签名/哈希不匹配)
#     - 比对内置脆弱驱动库(参考 loldrivers.io 知名 BYOVD: RTCore64/gdrv/dbutil_2_3/ene/capcom/AsIO 等)
#     - DriverStore 深度扫描(可选 /drivers+full), 记录: 路径/签发者/签名状态/过期时间/SHA256/加载状态
#     - 只记录不删除, 提示核实/禁用/更新
# v1.35 新增:
#  1) 操作留痕 (想法5) - 统一审计日志 操作留痕.log (工具根目录, UTF-8 追加)
#     覆盖: 引擎启动/退出/各模式分支/扫描/隔离/交互确认/IOC更新/关机拦截/异常
#     格式: [yyyy-MM-dd HH:mm:ss] [类型] 描述
# v1.34 新增:
#  1) 关机拦截 /shutdownguard (默认开启, 防银狐强制重启打断检测)
#     - 后台 Runspace 轮询发现 shutdown/reboot 进程即记录 + kill
#     - WMI 事件订阅: 捕获 shutdown.exe 调用
#     - ShutdownBlockReasonCreate API: 阻止系统关机并给出理由
#     - 限频提示 (阈值可配置: $ShutdownGuardMaxPerWindow / $ShutdownGuardWindowSec)
#     - 记录发起进程 (PID/名/映像路径/命令行) 写入报告和审计日志
#     - /noshutdownguard 可关闭
# v1.31 新增:
#  1) 零信任模式 /zerotrust - 工具目录自身也纳入扫描(取消工具根目录排除),
#     工具自身文件自动保护(不隔离不误杀), 用于检测掉落到工具目录的木马/样本
#  2) 引擎内存加载支持 - 启动器以 scriptblock::Create 方式加载引擎,
#     工具目录文件被扫描/隔离不影响正在运行的内存副本(保证工具自身运行)
#  3) 测试样本哈希入库(随更新同步)
# v1.7 重大修复:
#  1) 默认"只报告, 不隔离" - 不再自动移动任何正常软件文件
#  2) 进程扫描: 只有明确恶意特征才标记(伪装系统进程/C2/编码命令)
#     普通非系统进程归入"观察清单", 不 Flag 不隔离
#  3) 文件扫描: 修复 Downloads 枚举错误; 只对明确恶意特征(双扩展名/
#     伪装系统进程名/已知恶意哈希)标记, 长随机名仅观察
#  4) 计划任务: 排除 Microsoft\ 系统任务, 消除 112 条误报
#  5) WMI: 排除微软官方筛选器(SCM Event Log Filter 等)
#  6) 命令行: 去掉 'silver' 关键词, 排除脚本自身进程
#  7) 报告长度: 观察清单写入单独文件, 外连限制条数

try {
  [System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance)
  # v1.61: 编码统一为 936 (v2.15.18): bat 已移除 chcp 65001, 控制台代码页=系统默认(936);
  #        引擎输出必须同样 936, 否则 bat(GBK echo) 与引擎(UTF8) 混用必然乱码.
  #        非 Windows (Linux pwsh) 保持 UTF-8.
  try {
    if ($env:OS -eq 'Windows_NT') { [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(936) }
    else { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 }
  } catch {}
} catch {
  try { if ($env:OS -eq 'Windows_NT') { [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(936) } } catch {}
}
# v1.25: 跨平台环境变量兜底 (Linux 上 $env:TEMP/$env:USERPROFILE 为 null)
# v1.42: 定义移到 toolRoot 之前 (此前 catch 里引用 $script:EnvUser 时它还是空)
$script:EnvTmp  = if ($env:TEMP)  { $env:TEMP }  elseif ($env:TMP)  { $env:TMP }  else { [System.IO.Path]::GetTempPath() }
$script:EnvUser = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }

# v1.15: 日志写到工具目录(脚本所在目录的父目录=bat同目录), 用户目录作兜底
# v1.31: 内存加载时 $PSCommandPath 为空, 用启动器传入的 SF_TOOLROOT 兜底
$script:toolRoot = if ($PSCommandPath) { Split-Path (Split-Path $PSCommandPath -Parent) -Parent }
                  elseif ($env:SF_TOOLROOT) { $env:SF_TOOLROOT.TrimEnd('\','/') }
                  else { (Get-Location).Path }
try { New-Item -ItemType Directory -Path $script:toolRoot -Force -ErrorAction Stop | Out-Null; $logDir = $script:toolRoot } catch { $logDir = $script:EnvUser }
$DebugLog = Join-Path $logDir "sf_debug.log"
try { "" | Out-File -FilePath $DebugLog -Append } catch {}
# v1.60: 启动环境日志 — 便于远程诊断 9020 / 权限 / 路径问题
try {
  $envLines = @(
    "=== engine start v1.60 env ===",
    ("time=" + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')),
    ("psversion=" + $PSVersionTable.PSVersion.ToString()),
    ("psexepath=" + [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName),
    ("scriptdir=" + $script:toolRoot),
    ("executionpolicy=" + (Get-ExecutionPolicy)),
    ("whoami=" + ((whoami) 2>&1)),
    ("isadmin=" + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)),
    ("args=" + ($args -join ' ')),
    "=== env end ==="
  )
  $envLines | Out-File -FilePath $DebugLog -Append -Encoding UTF8
} catch {}


# v1.80: banner 版本动态提取(文件头注释里的 engine vX.Y), 不再写死
$bannerVer = 'v1.80'
try {
  $head = (Get-Content -LiteralPath $PSCommandPath -TotalCount 3 -ErrorAction SilentlyContinue) -join ''
  $m = [regex]::Match($head, 'engine v(\d+\.\d+)')
  if ($m.Success) { $bannerVer = 'v' + $m.Groups[1].Value }
} catch {}
$bannerLine = "[$(Get-Date -Format 'HH:mm:ss')] PowerShell engine $bannerVer started. PID=$PID  (by 莫问QWQ)"
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SilverFox Detector - PowerShell engine running"          -ForegroundColor Cyan
Write-Host "  $bannerLine"                                             -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Add-Content -Path $DebugLog -Value $bannerLine



# ===================== v1.48: 进程级自保护 (引擎加载即生效, 双击 bat 即启动) =====================
# ①进程 DACL: 仅 SYSTEM + Owner 完全控制, 移除 Everyone/Users/Administrators 终止权限
#   v1.48: 之前保留 BA 权限 -> 管理员任务管理器仍能杀; 改 OW(Owner) -> 任务管理器"拒绝访问"
# ②v1.49: 蓝屏威慑默认开启 (BreakOnTermination): 任何用户态 kill (含管理员任务管理器) -> 系统蓝屏 0xDEADDEAD
#          /softprotect 降级关闭; watchdog 复活兜底
# ③watchdog (bin/SelfGuard.ps1): 进程被强制终止后自动重启引擎, 直到正常退出
# 调用点: banner 后立即调用 (双击 bat -> 引擎加载 -> 立刻保护, 早于参数解析/扫描)
$script:ScriptArgs = @($args)   # 供 watchdog 透传重启参数 (函数内 $args 会被遮蔽)
$script:SelfProtect = $true
$script:BreakOnTerm = $false     # v1.50: 默认不蓝屏 (病毒不怕蓝屏且影响业务); 仅 /bruteprotect 显式开启
$script:ForceExtreme = $false    # v1.52: /extremeprotect 开关 (内核保护已搁置, 仅提示, 不加载驱动)
$script:ResetExtreme = $false    # v1.52: /resetextreme 清除历史极端态标志 (兼容 v1.51 升级)
foreach ($_a in $args) {
  if ($_a -match '^/noselfprotect$|^-noselfprotect$') { $script:SelfProtect = $false }
  if ($_a -match '^/softprotect$|^-softprotect$')     { $script:BreakOnTerm = $false; $script:ResetExtreme = $true }
  if ($_a -match '^/bruteprotect$|^-bruteprotect$')   { $script:BreakOnTerm = $true }
  if ($_a -match '^/extremeprotect$|^-extremeprotect$') { $script:ForceExtreme = $true }
  if ($_a -match '^/resetextreme$|^-resetextreme$')     { $script:ResetExtreme = $true }
}
# ===================== v1.50: watchdog 心跳自愈 (核心防杀) =====================
# 引擎被杀 -> watchdog 复活引擎 (已有); watchdog 被杀 -> 引擎检测心跳超时重新 spawn
# 两者任一被单独 kill 都能自愈, 只有"同时杀两个进程"才破防 (恶意程序很难做到)
function Spawn-Watchdog {
  # spawn bin/SelfGuard.ps1 (cmd start "" 空标题脱离父进程, 见 v1.46)
  try {
    $guard = Join-Path $script:toolRoot 'bin\SelfGuard.ps1'
    if (-not (Test-Path -LiteralPath $guard)) { return $false }
    $pwshPath = ''
    try { $pwshPath = (Get-Process -Id $PID).Path } catch {}
    if (-not $pwshPath) { $pwshPath = 'powershell.exe' }
    $enginePath = Join-Path $script:toolRoot 'bin\SilverFoxDetect.ps1'
    $ra = @($script:ScriptArgs | ForEach-Object { '"' + ($_ -replace '"', '""') + '"' }) -join ' '
    $payload = $script:toolRoot + "`n" + $enginePath + "`n" + $PID + "`n" + $ra
    $enc = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload))
    $spawnCmd = '"' + $pwshPath + '" -NoProfile -ExecutionPolicy Bypass -File "' + $guard + '" -Encoded ' + $enc
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo.FileName = 'cmd.exe'
    $p.StartInfo.Arguments = '/c start "" /B /MIN ' + $spawnCmd
    $p.StartInfo.WindowStyle = 'Hidden'
    $p.StartInfo.CreateNoWindow = $true
    $p.StartInfo.UseShellExecute = $false
    $p.Start() | Out-Null
    return $true
  } catch { return $false }
}
function Ensure-Watchdog {
  # 检查 watchdog 心跳 (sf_guard.heartbeat 45 秒内更新过=存活), 超时则重新 spawn
  if (-not $script:SelfProtect) { return }
  $hb = Join-Path $script:toolRoot 'sf_guard.heartbeat'
  try {
    if (Test-Path -LiteralPath $hb) {
      $age = (Get-Date) - (Get-Item $hb).LastWriteTime
      if ($age.TotalSeconds -lt 45) { return }
    }
  } catch {}
  if (Spawn-Watchdog) {
    Add-Content -Path $DebugLog -Value ("[自保护] watchdog 心跳超时, 已重新 spawn")
    Write-Host "  [自保护] watchdog 心跳超时, 已重新拉起守护" -ForegroundColor Yellow
  }
}

function Start-ProcessGuard {
  if (-not $script:SelfProtect) { return }
  $note = @()
  # 1) 进程 DACL: 仅 SYSTEM + Owner 完全控制, 移除 Everyone/Users/Administrators 终止权限
  #    v1.48: OW(Owner)=进程创建者, 拥有完全控制可随时恢复; 任务管理器(普通/管理员)结束进程 -> 拒绝访问
  try {
    if (-not ('ProcGuard' -as [type])) {
        Add-Type -TypeDefinition ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('dXNpbmcgU3lzdGVtOwp1c2luZyBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXM7CnB1YmxpYyBjbGFzcyBQcm9jR3VhcmQgewogIFtEbGxJbXBvcnQoImtlcm5lbDMyLmRsbCIsIFNldExhc3RFcnJvcj10cnVlKV0KICBwdWJsaWMgc3RhdGljIGV4dGVybiBJbnRQdHIgT3BlblByb2Nlc3ModWludCBhY2Nlc3MsIGJvb2wgaW5oZXJpdCwgaW50IHBpZCk7CiAgW0RsbEltcG9ydCgiYWR2YXBpMzIuZGxsIiwgU2V0TGFzdEVycm9yPXRydWUpXQogIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIGJvb2wgU2V0S2VybmVsT2JqZWN0U2VjdXJpdHkoSW50UHRyIGhhbmRsZSwgaW50IHNlY0luZm8sIGJ5dGVbXSBzZGIpOwogIFtEbGxJbXBvcnQoImFkdmFwaTMyLmRsbCIpXQogIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIGJvb2wgQ29udmVydFN0cmluZ1NlY3VyaXR5RGVzY3JpcHRvclRvU2VjdXJpdHlEZXNjcmlwdG9yKHN0cmluZyBzdHIsIHVpbnQgcmV2LCBvdXQgSW50UHRyIHNkYiwgb3V0IHVpbnQgc2l6ZSk7CiAgW0RsbEltcG9ydCgia2VybmVsMzIuZGxsIildCiAgcHVibGljIHN0YXRpYyBleHRlcm4gYm9vbCBDbG9zZUhhbmRsZShJbnRQdHIgaCk7Cn0=')))
      }
      $h = [ProcGuard]::OpenProcess(0x0400 -bor 0x0001 -bor 0x0008, $false, $PID)  # QUERY|TERMINATE|WRITE_DAC
      if ($h -ne [IntPtr]::Zero) {
        $sddl = "O:SYG:SYD:(A;;GA;;;SY)(A;;GA;;;OW)"
        $sdb = [IntPtr]::Zero; $size = [uint32]0
        [void][ProcGuard]::ConvertStringSecurityDescriptorToSecurityDescriptor($sddl, 1, [ref]$sdb, [ref]$size)
        $bytes = New-Object byte[] $size
        [Runtime.InteropServices.Marshal]::Copy($sdb, $bytes, 0, $size)
        $ok = [ProcGuard]::SetKernelObjectSecurity($h, 4, $bytes)  # DACL_SECURITY_INFORMATION = 4
        [void][ProcGuard]::CloseHandle($h)
        if ($ok) { $note += 'DACL已启用' } else { $note += ('DACL失败(' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() + ')') }
      } else {
        $note += ('DACL失败(OpenProcess ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() + ')')
      }
  } catch { $note += 'DACL异常' }
  # 2) 蓝屏威慑 (v1.50: 仅 /bruteprotect 显式开启, 默认不用 - 病毒不怕蓝屏且影响用户业务)
  #    核心防杀靠: DACL 拒绝访问 + watchdog 心跳自愈 (见 Ensure-Watchdog)
  if ($script:BreakOnTerm) {
    try {
      if (-not ('BrutalGuard' -as [type])) {
        Add-Type -TypeDefinition ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('dXNpbmcgU3lzdGVtOwp1c2luZyBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXM7CnB1YmxpYyBjbGFzcyBCcnV0YWxHdWFyZCB7CiAgW0RsbEltcG9ydCgibnRkbGwuZGxsIiwgU2V0TGFzdEVycm9yPXRydWUpXQogIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIGludCBOdFNldEluZm9ybWF0aW9uUHJvY2VzcyhJbnRQdHIgaCwgaW50IGNscywgcmVmIGludCBpbmZvLCBpbnQgbGVuKTsKICBbRGxsSW1wb3J0KCJrZXJuZWwzMi5kbGwiLCBTZXRMYXN0RXJyb3I9dHJ1ZSldCiAgcHVibGljIHN0YXRpYyBleHRlcm4gSW50UHRyIEdldEN1cnJlbnRQcm9jZXNzKCk7CiAgW0RsbEltcG9ydCgia2VybmVsMzIuZGxsIildCiAgcHVibGljIHN0YXRpYyBleHRlcm4gaW50IFJ0bE50U3RhdHVzVG9Eb3NFcnJvcihpbnQgc3RhdHVzKTsKfQ==')))
      }
      $info = 1
      $st = [BrutalGuard]::NtSetInformationProcess([BrutalGuard]::GetCurrentProcess(), 29, [ref]$info, 4)  # ProcessBreakOnTermination=29
      if ($st -eq 0) { $note += '硬保护(蓝屏威慑)已启用' }
      else { $note += ('硬保护失败(' + [BrutalGuard]::RtlNtStatusToDosError($st) + ')') }
    } catch { $note += '硬保护异常' }
  }
  # 3) watchdog 守护: spawn bin/SelfGuard.ps1 (心跳自愈核心, 见 Ensure-Watchdog)
  if (Spawn-Watchdog) { $note += 'watchdog已启动(独立进程)' } else { $note += 'watchdog启动失败' }
  $note += '内核保护已暂停(源码保留于bin/,未启用)'
  Write-Host ("  [自保护] 进程保护: " + ($note -join ', ')) -ForegroundColor Gray
  Add-Content -Path $DebugLog -Value ("[自保护] 进程保护: " + ($note -join ', '))
}

# v1.52: 极端态参数处理 - 内核保护已搁置 (源码保留于 bin/ExtremeProtect.ps1 与 bin/drivers/, 不启用)
$extremeFlagPath = Join-Path $script:toolRoot 'sf_extreme.flag'
if ($script:ResetExtreme) {
  # 清除历史极端态标志 + 卸载可能遗留的内核驱动 (兼容从 v1.51 升级)
  try { Remove-Item -LiteralPath $extremeFlagPath -Force -ErrorAction SilentlyContinue } catch {}
  try { & sc.exe delete sfguard 2>$null } catch {}
  Write-Host '  [自保护] 极端态标志已清除 (内核保护本就未启用)' -ForegroundColor Yellow
  try { Add-Content -Path $DebugLog -Value '[自保护] 极端态标志已清除' -Encoding UTF8 } catch {}
}
if ($script:ForceExtreme) {
  # v1.52: 内核保护已搁置, /extremeprotect 不再加载驱动, 仅提示源码位置
  Write-Host '  [自保护] 极端自保护(内核驱动)已暂停启用 - 源码保留于 bin/ExtremeProtect.ps1 与 bin/drivers/, 暂不加载' -ForegroundColor Yellow
  try { Add-Content -Path $DebugLog -Value '[自保护] /extremeprotect 请求, 但内核保护已搁置未启用' -Encoding UTF8 } catch {}
}
if (Test-Path -LiteralPath $extremeFlagPath) {
  Write-Host '  [状态] 检测到历史极端态标志, 内核保护已暂停 (源码保留未启用)' -ForegroundColor Yellow
}

# ===================== v1.48: 双击 bat 即启动进程保护 (DACL + watchdog + 可选硬保护) =====================
# 引擎加载即调用 (早于参数解析/扫描), 满足"脚本双击打开时自保护就启动"
if ($script:SelfProtect) { try { Start-ProcessGuard } catch { Add-Content -Path $DebugLog -Value ("  [进程保护异常] " + $_.Exception.Message) } }



# ===================== 退出管理 v1.13 (纯 .NET SHA256 签名, 零 PS 操作符) =====================
# 目标: 所有退出都走统一受控路径, 留痕退出原因 + 写"受控退出标记",
#       防其他程序伪造标记冒充受控退出 (其他程序没有内置 salt, 算不出 hash)
#
# v1.13 关键变更: 彻底移除 v1.11/v1.12 的 XOR 加密 (在 PS 5.1 下 -bxor + byte[] 索引引发
#  "无法将 if 识别为 cmdlet" 错误). 改用纯 .NET SHA256 签名, 零 PS 操作符依赖.
$script:ExitReason = '未知'
$script:ExitCode = 0
$script:ExitSalt = 'SilverFoxDetector-v1.13-EXIT-SALT-!@#$%^&*'  # 内置私有盐 (其他程序无法伪造 hash)

# 签名: plaintext + salt -> SHA256 -> 取前 16 hex 字符
# 完全用 .NET API, 不用 PS 操作符 (-bxor/-band 等在 PS 5.1 偶发陷阱)
function Protect-Token {
  param([string]$Plain)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Plain + $script:ExitSalt))
  $hex = ([System.BitConverter]::ToString($bytes) -replace '-', '').ToLower()
  return ($Plain + '|h=' + $hex.Substring(0, 16))
}

# 生成退出标记文件路径: sf_exit_<pid>_<hash8>.flag (hash8 取自 salt 头 8 hex)
$sha = [System.Security.Cryptography.SHA256]::Create()
$saltHash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($script:ExitSalt))
$script:ExitFlagNonce = ([System.BitConverter]::ToString($saltHash) -replace '-', '').ToLower().Substring(0, 8)
$script:ExitFlag = Join-Path $script:EnvTmp ("sf_exit_" + $PID + "_" + $script:ExitFlagNonce + ".flag")
$script:ExitFlagged = $false
$script:ExitStartTime = Get-Date  # 用于验签时校验时间窗口

# ===================== v1.34: 关机拦截 (想法4) =====================
# 防银狐木马在检测期间强制关机/重启打断扫描
# 三层防护: ① 后台轮询发现 shutdown/reboot 进程即 kill + 记录
#           ② WMI 事件订阅 (Win32_ProcessStartTrace 捕获 shutdown.exe)
#           ③ ShutdownBlockReasonCreate API 阻止系统关机
# 限频: $ShutdownGuardWindowSec 秒内最多提示 $ShutdownGuardMaxPerWindow 次
$script:ShutdownGuardMaxPerWindow = 10   # 限频阈值 (只改这个数字即可调整)
$script:ShutdownGuardWindowSec     = 60  # 限频时间窗 (秒)
$script:ShutdownGuardEvents = @()        # 拦截事件列表 (写入报告)
$script:ShutdownGuardTipHistory = @()    # 限频用: 提示时间戳列表
$script:ShutdownGuardRunspace = $null
$script:ShutdownGuardWMI = $null
$script:ShutdownGuardStopSignal = $false
$script:ShutdownGuardInhibitHandle = [IntPtr]::Zero

# 关机相关进程名 (小写匹配)
$script:ShutdownProcNames = @('shutdown','reboot','poweroff','halt','init')

function Write-ShutdownGuardLog {
  # 记录一次关机拦截事件 (写入审计日志 + 报告列表 + 限频提示)
  param([string]$ProcName, [int]$ProcId, [string]$ImagePath, [string]$CmdLine)
  $now = Get-Date
  $evt = [PSCustomObject]@{
    Time      = $now.ToString('HH:mm:ss')
    ProcName  = $ProcName
    PID       = $ProcId
    ImagePath = $ImagePath
    CmdLine   = $CmdLine
  }
  $script:ShutdownGuardEvents += $evt
  # v1.35: 统一操作留痕
  try { Write-AuditLog -Type 'SHUTDOWN' -Msg ('拦截关机/重启: ' + $ProcName + ' PID=' + $ProcId + ' 路径=' + $ImagePath + ' 命令行=' + $CmdLine) } catch {}
  # 审计日志
  $auditLine = ("[$($now.ToString('yyyy-MM-dd HH:mm:ss'))] [关机拦截] 进程=$ProcName PID=$ProcId 路径=$ImagePath 命令行=$CmdLine")
  $auditFile = Join-Path $logDir 'sf_shutdown_guard.log'
  try { Add-Content -Path $auditFile -Value $auditLine -Encoding UTF8 } catch {}
  try { Add-Content -Path $DebugLog -Value $auditLine -Encoding UTF8 } catch {}
  # 限频提示: 时间窗内超过阈值则不再弹窗 (仍记录日志)
  $script:ShutdownGuardTipHistory = $script:ShutdownGuardTipHistory | Where-Object { $_ -gt $now.AddSeconds(-$script:ShutdownGuardWindowSec) }
  if ($script:ShutdownGuardTipHistory.Count -lt $script:ShutdownGuardMaxPerWindow) {
    $script:ShutdownGuardTipHistory += $now
    # 独立窗口提示 (mshta 弹窗, 不阻塞主窗口)
    $tipMsg = "已拦截一次关机/重启尝试!`n`n发起进程: $ProcName (PID=$ProcId)`n映像路径: $ImagePath`n命令行: $CmdLine`n`n检测仍在继续, 此窗口可关闭。"
    $tipEsc = $tipMsg -replace "'", "`''" -replace '"', '\"'
    try {
      Start-Process mshta.exe -ArgumentList ('vbscript:MsgBox("' + $tipEsc + '",48,"银狐特攻 - 关机拦截")') -WindowStyle Hidden -ErrorAction SilentlyContinue
    } catch {}
  }
  Write-Host ("  [关机拦截] 已阻止 $ProcName (PID=$ProcId) 的关机/重启尝试") -ForegroundColor Red
}

function Stop-ShutdownProcess {
  # 发现关机进程时尝试 kill (阻止其执行)
  param([string]$ProcName, [int]$ProcId)
  try {
    $proc = Get-Process -Id $ProcId -ErrorAction Stop
    $imgPath = try { $proc.Path } catch { '' }
    $cmdLine = ''
    try {
      $wmiProc = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcId" -ErrorAction Stop
      $cmdLine = $wmiProc.CommandLine
    } catch {}
    # 先记录再 kill
    Write-ShutdownGuardLog -ProcName $ProcName -ProcId $ProcId -ImagePath $imgPath -CmdLine $cmdLine
    # kill 关机进程 (阻止关机执行)
    try { Stop-Process -Id $ProcId -Force -ErrorAction SilentlyContinue } catch {}
  } catch {
    # 进程已退出, 仅记录
    Write-ShutdownGuardLog -ProcName $ProcName -ProcId $ProcId -ImagePath '' -CmdLine ''
  }
}

function Start-ShutdownGuard {
  if (-not $script:ShutdownGuard) { return }
  $script:ShutdownGuardStarted = $true   # v1.42: 标记本次启动了守护
  Write-Host "  [关机拦截] 已启动 - 检测期间将拦截 shutdown/reboot/poweroff/halt 等关机命令" -ForegroundColor Green
  try { Add-Content -Path $DebugLog -Value ("[关机拦截] 启动 PID=$PID") -Encoding UTF8 } catch {}

  # ---- 层1: 后台 Runspace 轮询进程列表 (Windows: Get-Process) ----
  # 直接在 runspace 内完成 kill + 写日志 (避免跨 runspace 信号文件机制)
  try {
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'
    $rs.Open()
    $rs.SessionStateProxy.SetVariable('ShutdownGuardStopSignal', $false)
    $rs.SessionStateProxy.SetVariable('ShutdownProcNames', $script:ShutdownProcNames)
    $rs.SessionStateProxy.SetVariable('EnvTmp', $script:EnvTmp)
    $rs.SessionStateProxy.SetVariable('LogDir', $logDir)
    $rs.SessionStateProxy.SetVariable('MaxPerWindow', $script:ShutdownGuardMaxPerWindow)
    $rs.SessionStateProxy.SetVariable('WindowSec', $script:ShutdownGuardWindowSec)
    $ps = [PowerShell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript({
      $seen = @{}
      $tipHistory = @()
      $logFile = Join-Path $LogDir 'sf_shutdown_guard.log'
      while (-not $ShutdownGuardStopSignal) {
        try {
          $procs = Get-Process -ErrorAction SilentlyContinue
          foreach ($p in $procs) {
            $name = $p.ProcessName.ToLower()
            if ($ShutdownProcNames -contains $name) {
              $key = "$($p.Id)"
              if (-not $seen.ContainsKey($key)) {
                $seen[$key] = $true
                $imgPath = try { $p.Path } catch { '' }
                $cmdLine = ''
                try {
                  $wmiProc = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)" -ErrorAction Stop
                  $cmdLine = $wmiProc.CommandLine
                } catch {}
                $now = Get-Date
                # v1.61: System32 下 shutdown/reboot 只记录不 kill 会放行用户关机(v1.40 防误杀过宽);
                #        改为: 命令行含工具自身标记(SilverFox/银狐/检测工具/安全模式/急救)放行, 否则 kill
                $isSelf = ($cmdLine -match '(?i)SilverFox|银狐|检测工具|安全模式|急救')
                $isSys = ($imgPath -match '(?i)\\system32\\' -or -not $imgPath)
                $action = if ($isSys -and $isSelf) { '记录(系统路径,工具自身)' } elseif ($isSys) { '已阻止(Sys32)' } else { '已阻止' }
                # 写审计日志
                $line = "[$($now.ToString('yyyy-MM-dd HH:mm:ss'))] [关机拦截] 进程=$($p.ProcessName) PID=$($p.Id) 路径=$imgPath 命令行=$cmdLine [$action]"
                try { Add-Content -Path $logFile -Value $line -Encoding UTF8 } catch {}
                # kill 关机进程 (仅非系统路径)
                if (-not ($isSys -and $isSelf)) {
                  try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
                }
                # 限频提示 (写提示文件让主线程输出弹窗)
                $tipHistory = $tipHistory | Where-Object { $_ -gt $now.AddSeconds(-$WindowSec) }
                if ($tipHistory.Count -lt $MaxPerWindow) {
                  $tipHistory += $now
                  $tipFile = Join-Path $EnvTmp ("sf_sg_tip_" + $p.Id + ".tmp")
                  try { Set-Content -Path $tipFile -Value "$($p.ProcessName)|$($p.Id)|$imgPath|$cmdLine" -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
                }
              }
            }
          }
        } catch {}
        Start-Sleep -Milliseconds 250   # v1.61: 800ms 抓不住毫秒级 shutdown.exe, 缩至 250ms 兜底
      }
    })
    $handle = $ps.BeginInvoke()
    $script:ShutdownGuardRunspace = @{ PS = $ps; Runspace = $rs; Handle = $handle }
  } catch {
    try { Add-Content -Path $DebugLog -Value ("[关机拦截] Runspace 启动失败: " + $_.Exception.Message) -Encoding UTF8 } catch {}
  }

  # ---- 层2: WMI 事件订阅 (捕获 shutdown.exe 启动) ----
  try {
    $query = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='shutdown.exe' OR ProcessName='reboot.exe' OR ProcessName='poweroff.exe' OR ProcessName='halt.exe'"
    # v1.62: CIM cmdlet 对 Win32_ProcessStartTrace 支持不佳(返回 null 导致后续 InputObject 绑定失败)
    #        改用 Register-WmiEvent -Action (WMI 事件订阅, 进程启动即触发, Action 内立即 kill)
    $script:ShutdownGuardWMI = Register-WmiEvent -Query $query -SourceIdentifier 'SilverFoxShutdownGuard' -Action {
      try {
        $procName = $Event.SourceEventArgs.NewEvent.ProcessName
        $procId = $Event.SourceEventArgs.NewEvent.ProcessID
        $sigFile = Join-Path $env:TEMP ("sf_sg_wmi_" + $procId + "_" + (Get-Random) + ".tmp")
        Set-Content -Path $sigFile -Value "$procName|$procId" -Encoding ASCII -ErrorAction SilentlyContinue
        try {
          $wcl = ''
          try { $wcl = (Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction Stop).CommandLine } catch {}
          if ($wcl -notmatch '(?i)SilverFox|银狐|检测工具|安全模式|急救') {
            try { Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue } catch {}
          }
        } catch {}
      } catch {}
    } -ErrorAction Stop
  } catch {
    try { Add-Content -Path $DebugLog -Value ("[关机拦截] WMI 订阅失败 (非致命): " + $_.Exception.Message) -Encoding UTF8 } catch {}
  }

  # ---- 层3: 隐藏窗口 + WM_QUERYENDSESSION=FALSE (真正阻止系统关机, v1.62) ----
  # 杀 shutdown.exe 无法撤销已提交的系统关机请求; 系统关机流程会向顶层窗口发 WM_QUERYENDSESSION,
  # 返回 FALSE 即阻止关机/注销/重启. 本层创建隐藏窗口 + 独立线程消息循环 + ShutdownBlockReasonCreate.
  try {
    $code = @"
using System;
using System.Runtime.InteropServices;
using System.Threading;
public class ShutdownGuardWindow {
  private const uint WM_QUERYENDSESSION = 0x0011;
  private const uint WM_ENDSESSION = 0x0016;
  private const uint WM_QUIT = 0x0012;
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct WNDCLASSEXW {
    public uint cbSize; public uint style; public IntPtr lpfnWndProc; public int cbClsExtra; public int cbWndExtra;
    public IntPtr hInstance; public IntPtr hIcon; public IntPtr hCursor; public IntPtr hbrBackground;
    [MarshalAs(UnmanagedType.LPWStr)] public string lpszMenuName; [MarshalAs(UnmanagedType.LPWStr)] public string lpszClassName;
    public IntPtr hIconSm;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam; public uint time; public int ptX; public int ptY; }
  [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern ushort RegisterClassExW(ref WNDCLASSEXW wc);
  [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern IntPtr CreateWindowExW(uint exStyle, string cls, string name, uint style, int x, int y, int w, int h, IntPtr parent, IntPtr menu, IntPtr inst, IntPtr param);
  [DllImport("user32.dll")] public static extern IntPtr DefWindowProcW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
  [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandleW(string name);   // v2.15.20: GetModuleHandleW 在 kernel32 不在 user32 (此前运行期找不到入口点)
  [DllImport("user32.dll")] public static extern int GetMessageW(ref MSG msg, IntPtr hWnd, uint min, uint max);
  [DllImport("user32.dll")] public static extern bool TranslateMessage(ref MSG msg);
  [DllImport("user32.dll")] public static extern IntPtr DispatchMessageW(ref MSG msg);
  [DllImport("user32.dll")] public static extern bool PostThreadMessageW(uint tid, uint msg, IntPtr wParam, IntPtr lParam);
  [DllImport("user32.dll")] public static extern bool DestroyWindow(IntPtr hWnd);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern bool ShutdownBlockReasonCreate(IntPtr hWnd, [MarshalAs(UnmanagedType.LPWStr)] string reason);
  [DllImport("user32.dll")] public static extern bool ShutdownBlockReasonDestroy(IntPtr hWnd);
  private delegate IntPtr WndProcDelegate(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
  private static WndProcDelegate _proc;
  public static volatile IntPtr Hwnd = IntPtr.Zero;
  private static uint _threadId;
  private static IntPtr WndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam) {
    if (msg == WM_QUERYENDSESSION) {
      try { System.IO.File.AppendAllText(System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sf_sg_query.log"),
        System.DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + " QUERYENDSESSION wParam=0x" + wParam.ToString("X") + " -> FALSE\n"); } catch {}
      return IntPtr.Zero;  // FALSE = 阻止关机/注销/重启
    }
    if (msg == WM_ENDSESSION) { return IntPtr.Zero; }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
  }
  public static IntPtr Start(string reason) {
    if (Hwnd != IntPtr.Zero) { return Hwnd; }
    _proc = new WndProcDelegate(WndProc);
    IntPtr hInst = GetModuleHandleW(null);
    Thread t = new Thread(delegate() {
      WNDCLASSEXW wc = new WNDCLASSEXW();
      wc.cbSize = (uint)Marshal.SizeOf(typeof(WNDCLASSEXW));
      wc.style = 0; wc.lpfnWndProc = Marshal.GetFunctionPointerForDelegate(_proc);
      wc.hInstance = hInst; wc.lpszClassName = "SilverFoxSgWndClass";
      RegisterClassExW(ref wc);
      IntPtr hwnd = CreateWindowExW(0, "SilverFoxSgWndClass", "SilverFoxGuard", 0, 0, 0, 0, 0, IntPtr.Zero, IntPtr.Zero, hInst, IntPtr.Zero);
      Hwnd = hwnd; _threadId = GetCurrentThreadId();
      if (hwnd != IntPtr.Zero) { ShutdownBlockReasonCreate(hwnd, reason); }
      MSG m = new MSG();   // v2.15.20: ref 实参必须显式初始化 (CS0165)
      while (GetMessageW(ref m, IntPtr.Zero, 0, 0) > 0) { TranslateMessage(ref m); DispatchMessageW(ref m); }
      if (hwnd != IntPtr.Zero) { DestroyWindow(hwnd); }
    });
    t.IsBackground = true; t.Start();
    int i = 0;
    while (Hwnd == IntPtr.Zero && i < 400) { Thread.Sleep(5); i++; }
    return Hwnd;
  }
  public static void Stop() {
    if (Hwnd != IntPtr.Zero) {
      try { ShutdownBlockReasonDestroy(Hwnd); } catch {}
      try { PostThreadMessageW(_threadId, WM_QUIT, IntPtr.Zero, IntPtr.Zero); } catch {}
    }
  }
}
"@
    $type = Add-Type -TypeDefinition $code -PassThru -ErrorAction SilentlyContinue
    if ($type) {
      $hwnd = [ShutdownGuardWindow]::Start("SilverFox 检测工具正在运行, 检测完成后关机才会生效")
      if ($hwnd -ne [IntPtr]::Zero) {
        $script:ShutdownGuardInhibitHandle = $hwnd
        try { Add-Content -Path $DebugLog -Value ("[关机拦截] 层3 窗口就绪 hwnd=0x" + $hwnd.ToString("X") + " (WM_QUERYENDSESSION=FALSE 阻止系统关机)") -Encoding UTF8 } catch {}
      } else {
        try { Add-Content -Path $DebugLog -Value "[关机拦截] 层3 窗口创建失败 (降级)" -Encoding UTF8 } catch {}
      }
    }
  } catch {
    try { Add-Content -Path $DebugLog -Value ("[关机拦截] 层3 初始化失败 (非致命): " + $_.Exception.Message) -Encoding UTF8 } catch {}
  }

  # ---- 信号文件轮询线程 (主 runspace 内, 处理后台发现的关机进程) ----
  # 后台 runspace 写信号文件, 主线程定期扫描并处理 (避免跨 runspace 函数调用问题)
}

function Stop-ShutdownGuard {
  if (-not $script:ShutdownGuard) { return }
  # v1.42: 本次未启动过守护 (如 /restore /mem 等分支) 时, 不回读历史日志, 防把上次拦截写进本次报告
  if (-not $script:ShutdownGuardStarted) { return }
  $script:ShutdownGuardStopSignal = $true
  try { Add-Content -Path $DebugLog -Value ("[关机拦截] 停止中...") -Encoding UTF8 } catch {}

  # 停止后台 Runspace
  if ($script:ShutdownGuardRunspace -and $script:ShutdownGuardRunspace.PS) {
    try {
      $script:ShutdownGuardRunspace.Runspace.SessionStateProxy.SetVariable('ShutdownGuardStopSignal', $true)
      $script:ShutdownGuardRunspace.PS.EndInvoke($script:ShutdownGuardRunspace.Handle) | Out-Null
      $script:ShutdownGuardRunspace.PS.Dispose()
      $script:ShutdownGuardRunspace.Runspace.Close()
      $script:ShutdownGuardRunspace.Runspace.Dispose()
    } catch {}
    $script:ShutdownGuardRunspace = $null
  }

  # 注销 WMI 事件
  try { Unregister-Event -SourceIdentifier 'SilverFoxShutdownGuardHandler' -ErrorAction SilentlyContinue } catch {}
  try { Unregister-Event -SourceIdentifier 'SilverFoxShutdownGuard' -ErrorAction SilentlyContinue } catch {}
  try { if ($script:ShutdownGuardWMI) { Remove-Job -InputObject $script:ShutdownGuardWMI -Force -ErrorAction SilentlyContinue } } catch {}

  # 销毁 ShutdownBlockReason + 关闭窗口消息循环 (v1.62)
  try {
    if ($script:ShutdownGuardInhibitHandle -ne [IntPtr]::Zero) {
      [ShutdownGuardWindow]::Stop()
      $script:ShutdownGuardInhibitHandle = [IntPtr]::Zero
    }
  } catch {}

  # 清理信号文件 + 处理未读的提示文件
  try {
    Get-ChildItem (Join-Path $script:EnvTmp 'sf_sg_tip_*.tmp') -ErrorAction SilentlyContinue | ForEach-Object {
      try {
        $parts = (Get-Content $_ -Raw -ErrorAction SilentlyContinue).Trim() -split '\|', 4
        if ($parts.Count -ge 4) {
          $evt = [PSCustomObject]@{ Time=(Get-Date).ToString('HH:mm:ss'); ProcName=$parts[0]; PID=[int]$parts[1]; ImagePath=$parts[2]; CmdLine=$parts[3] }
          $script:ShutdownGuardEvents += $evt
        }
      } catch {}
      Remove-Item -LiteralPath $_ -Force -ErrorAction SilentlyContinue
    }
  } catch {}
  # v1.42: WMI 层捕获的关机进程先并入事件再清理 (此前只删不解析, 结果丢失)
  try {
    $wmiFiles = @(Get-ChildItem (Join-Path $script:EnvTmp 'sf_sg_wmi_*.tmp') -ErrorAction SilentlyContinue)
    foreach ($wf in $wmiFiles) {
      try {
        $wmiInfo = (Get-Content $wf.FullName -Raw -ErrorAction SilentlyContinue).Trim()
        if ($wmiInfo -match '^(.+?)\|(\d+)$') {
          $wname = $Matches[1] -replace '\.exe$', ''
          $wid = [int]$Matches[2]
          # v1.61: 主线程兜底 kill (进程若尚存且非自身标记)
          try {
            $wcl2 = ''
            try { $wcl2 = (Get-CimInstance Win32_Process -Filter "ProcessId=$wid" -ErrorAction Stop).CommandLine } catch {}
            if ($wcl2 -notmatch '(?i)SilverFox|银狐|检测工具|安全模式|急救') {
              try { Stop-Process -Id $wid -Force -ErrorAction SilentlyContinue } catch {}
            }
          } catch {}
          if (-not ($script:ShutdownGuardEvents | Where-Object { $_.PID -eq $wid })) {
            $script:ShutdownGuardEvents += [PSCustomObject]@{
              Time = (Get-Date -Format 'HH:mm:ss'); ProcName = $wname; PID = $wid
              ImagePath = 'WMI事件'; CmdLine = '(WMI 进程启动事件)'
            }
            try { Add-Content -Path (Join-Path $logDir 'sf_shutdown_guard.log') -Value ("[" + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + "] [关机拦截] 进程=" + $wname + " PID=" + $wid + " 路径=WMI事件 命令行=(WMI 进程启动事件)") -Encoding UTF8 } catch {}
          }
        }
      } catch {}
      Remove-Item -LiteralPath $wf.FullName -Force -ErrorAction SilentlyContinue
    }
  } catch {}
  try { Get-ChildItem (Join-Path $script:EnvTmp 'sf_sg_wmi_*.tmp') -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue } catch {}
  # 从审计日志读取全部拦截记录 (runspace 直接写入的)
  try {
    $auditFile = Join-Path $logDir 'sf_shutdown_guard.log'
    if (Test-Path -LiteralPath $auditFile) {
      $lines = Get-Content $auditFile -Encoding UTF8 -ErrorAction SilentlyContinue
      foreach ($line in $lines) {
        if ($line -match '\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[关机拦截\] 进程=(\S+) PID=(\d+) 路径=(.*) 命令行=(.*)') {
          $evt = [PSCustomObject]@{
            Time      = ($Matches[1] -replace '^\d{4}-\d{2}-\d{2} ', '')
            ProcName  = $Matches[2]
            PID       = [int]$Matches[3]
            ImagePath = $Matches[4]
            CmdLine   = $Matches[5]
          }
          $exists = $false
          foreach ($e in $script:ShutdownGuardEvents) {
            if ($e.PID -eq $evt.PID) { $exists = $true; break }
          }
          if (-not $exists) { $script:ShutdownGuardEvents += $evt }
        }
      }
    }
  } catch {}

  # 汇总
  $cnt = $script:ShutdownGuardEvents.Count
  if ($cnt -gt 0) {
    Write-Host ("  [关机拦截] 检测期间共拦截 " + $cnt + " 次关机/重启尝试") -ForegroundColor Yellow
    Add-Report ""
    Add-Report "  ===== 关机拦截记录 ====="
    foreach ($evt in $script:ShutdownGuardEvents) {
      Add-Report ("    [" + $evt.Time + "] " + $evt.ProcName + " PID=" + $evt.PID + " 路径=" + $evt.ImagePath + " 命令行=" + $evt.CmdLine)
      # v1.35: 统一操作留痕 (后台 Runspace 拦截事件在此补写)
      try { Write-AuditLog -Type 'SHUTDOWN' -Msg ('拦截关机/重启: ' + $evt.ProcName + ' PID=' + $evt.PID + ' 路径=' + $evt.ImagePath + ' 命令行=' + $evt.CmdLine) } catch {}
    }
    Add-Report "  (以上为检测期间被拦截的关机/重启尝试, 银狐木马常用此手段打断查杀)"
  }
  try { Add-Content -Path $DebugLog -Value ("[关机拦截] 已停止, 共拦截 " + $cnt + " 次") -Encoding UTF8 } catch {}
}

# ===================== v1.35: 操作留痕 (想法5 统一审计) =====================
# 统一操作留痕: [yyyy-MM-dd HH:mm:ss] [类型] 描述
# 落盘: 工具根目录 操作留痕.log (UTF-8 追加, 与检测报告分开, 报告被清理也不丢审计)
# 类型: START/EXIT/MODE/SCAN/IOC/QUARANTINE/INTERACTIVE/SHUTDOWN/ERROR
$script:AuditLog = Join-Path $logDir '操作留痕.log'
$script:AuditStartTime = Get-Date

function Write-AuditLog {
  param([string]$Type, [string]$Msg)
  try {
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Type] $Msg"
    Add-Content -Path $script:AuditLog -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
  } catch {}
}

# ===================== v1.38: 威胁锁定 (检测出先锁定, 隔离/删除前解锁) =====================
# 防恶意程序在待处理期间自我修复/篡改/抢先删除被检出的文件
# 锁定清单: 工具根目录 锁定清单.txt (时间|路径|原因|方式), 供 /unlock 手动解锁
$script:LockListFile = Join-Path $logDir '锁定清单.txt'

function Add-ThreatLock {
  # 加锁: Win icacls deny 写入/删除 (需管理员); 失败降级 attrib +R 只读弱锁
  param([string]$Path, [string]$Reason)
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return }
  $method = 'icacls'
  try {
    & icacls $Path /deny '*S-1-1-0:(WD,AD,DE,DC)' 2>$null | Out-Null
    $chk = & icacls $Path 2>$null | Select-Object -Skip 1
    if (($chk -join ' ') -match '拒绝|Deny') { $method = 'icacls' }
    else { $method = 'attrib(弱锁)'; & attrib +R $Path 2>$null | Out-Null }
  } catch { $method = 'attrib(弱锁)'; try { & attrib +R $Path 2>$null | Out-Null } catch {} }
  # 记录锁定清单 (避免重复)
  $lines = @()
  if (Test-Path -LiteralPath $script:LockListFile) { $lines = Get-Content $script:LockListFile -Encoding UTF8 -ErrorAction SilentlyContinue }
  $exists = $false
  foreach ($l in $lines) { if ($l -match [regex]::Escape($Path) + '\|') { $exists = $true; break } }
  if (-not $exists) {
    try { Add-Content -Path $script:LockListFile -Value ((Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '|' + $Path + '|' + $Reason + '|' + $method) -Encoding UTF8 } catch {}
    Write-AuditLog -Type 'LOCK' -Msg ('已锁定: ' + $Path + ' [' + $Reason + '] 方式=' + $method)
  }
}

function Remove-ThreatLock {
  # 解锁: Win icacls /remove:d 移除拒绝 ACE (需管理员); attrib -R 解除弱锁
  param([string]$Path)
  if (-not $Path) { return }
  try {
    & icacls $Path /remove:d '*S-1-1-0' 2>$null | Out-Null
    & attrib -R $Path 2>$null | Out-Null
  } catch {}
  # 从锁定清单移除
  if (Test-Path -LiteralPath $script:LockListFile) {
    try {
      $lines = @(Get-Content $script:LockListFile -Encoding UTF8 -ErrorAction SilentlyContinue |
        Where-Object { $_ -notmatch [regex]::Escape($Path) + '\|' })
      if ($lines.Count -eq 0) { Clear-Content -Path $script:LockListFile -ErrorAction SilentlyContinue }
      else { $lines | Set-Content -Path $script:LockListFile -Encoding UTF8 }
    } catch {}
  }
  Write-AuditLog -Type 'LOCK' -Msg ('已解锁: ' + $Path)
}

function Show-LockList {
  # /unlock: 列出锁定清单, 手动选择解锁
  if (-not (Test-Path -LiteralPath $script:LockListFile)) {
    Write-Host "  [锁定] 没有已锁定的文件。" -ForegroundColor Green
    try { Write-ScanProgress "[lock] 没有已锁定的文件" } catch {}
    return
  }
  $lines = @(Get-Content $script:LockListFile -Encoding UTF8 -ErrorAction SilentlyContinue | Where-Object { $_ -and $_.Trim() })
  if ($lines.Count -eq 0) { Write-Host "  [锁定] 没有已锁定的文件。" -ForegroundColor Green; return }
  Write-Host ""
  Write-Host "============================================================" -ForegroundColor Yellow
  Write-Host ("  已锁定文件: " + $lines.Count + " 个 (检测出但尚未隔离/删除)") -ForegroundColor Yellow
  try { Write-ScanProgress ("[lock] 已锁定 " + $lines.Count + " 个文件, 输入序号可解锁") } catch {}
  Write-Host "  锁定原因: 防止恶意程序自我修复/篡改/抢先删除" -ForegroundColor Yellow
  Write-Host "============================================================" -ForegroundColor Yellow
  for ($i=0; $i -lt $lines.Count; $i++) {
    $parts = $lines[$i] -split '\|'
    Write-Host ("  [" + ($i+1) + "] " + $parts[1] + "  [" + $parts[2] + "] 方式=" + $parts[3]) -ForegroundColor Gray
  }
  Write-Host ""
  Write-Host "  说明: 解锁 = 让这些文件恢复可移动/可删除状态 (不动文件本身, 仅解除保护锁定)" -ForegroundColor Cyan
  Write-Host "  输入要解锁的序号 (单个 1 / 多个 1,3,5 / all 全部 / 0 返回; 数字 = 列表里的编号)"
  try { Write-ScanProgress ("[交互] 请在控制台窗口输入序号 (单个 1 / 多个 1,3 / 0返回)") } catch {}
  $choice = Read-Host "  选择"
  $idxList = @(Get-Selection -Choice $choice -Count $lines.Count)
  if ($idxList.Count -eq 1 -and $idxList[0] -eq -1) { Write-Host "  返回。"; return }
  if ($idxList.Count -eq 0) { Write-Host "  无有效选择。"; return }
  foreach ($idx in $idxList) {
    $parts = $lines[$idx] -split '\|'
    Write-Host ("  [解锁] " + $parts[1]) -ForegroundColor Cyan
    Remove-ThreatLock $parts[1]
  }
  Write-Host ("  已解锁 " + $idxList.Count + " 个文件。")
}

# ===================== v1.39: 恶意程序网络封锁 =====================
# 检出 C2 外联/域名命中后自动封禁其网络 (防火墙规则), 可 /netblock 查看/解除
# 封锁清单: 工具根目录 网络封锁清单.txt (时间|类型|目标|原因|规则名)
$script:NetBlockListFile = Join-Path $logDir '网络封锁清单.txt'

function Add-NetBlock {
  # 封禁恶意程序网络: Win 防火墙按 IP + 按进程路径; 记录清单 + 留痕
  param([string]$IP, [string]$ProcessPath, [string]$Reason)
  $added = @()
  $needAdmin = $false
  # 1) 封禁 C2 IP 出站
  if ($IP) {
    $ruleName = "SilverFoxBlock_" + ($IP -replace '[.:]', '_')
    try {
      $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
      if (-not $existing) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block -RemoteAddress $IP -Profile Any -ErrorAction Stop | Out-Null
        $added += ("IP:" + $IP)
      } else { $added += ("IP(已存在):" + $IP) }
    } catch { $needAdmin = $true }
  }
  # 2) 按进程路径封禁出站 (Win 专有)
  if ($ProcessPath -and (Test-Path -LiteralPath $ProcessPath)) {
    $h = [System.BitConverter]::ToString([System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ProcessPath.ToLower()))) -replace '-', ''
    $ruleName = "SilverFoxBlockProc_" + $h.Substring(0, 12)
    try {
      $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
      if (-not $existing) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block -Program $ProcessPath -Profile Any -ErrorAction Stop | Out-Null
        $added += ("程序:" + (Split-Path $ProcessPath -Leaf))
      } else { $added += ("程序(已存在):" + (Split-Path $ProcessPath -Leaf)) }
    } catch { $needAdmin = $true }
  }
  # 3) 记录清单 (防重复)
  if ($added.Count -gt 0) {
    $lines = @()
    if (Test-Path -LiteralPath $script:NetBlockListFile) { $lines = Get-Content $script:NetBlockListFile -Encoding UTF8 -ErrorAction SilentlyContinue }
    foreach ($a in $added) {
      $key = $a -replace '^(IP|程序)\(已存在\):', ''
      $exists = $false
      foreach ($l in $lines) { if ($l -match [regex]::Escape($key)) { $exists = $true; break } }
      if (-not $exists) {
        try { Add-Content -Path $script:NetBlockListFile -Value ((Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '|' + $a + '|' + $Reason + '|' + $ruleName) -Encoding UTF8 } catch {}
      }
    }
    Write-AuditLog -Type 'NETBLOCK' -Msg ('已封锁: ' + ($added -join ', ') + ' [' + $Reason + ']')
  } elseif ($needAdmin) {
    Write-AuditLog -Type 'NETBLOCK' -Msg ('封锁失败(需管理员): ' + $(if($IP){'IP=' + $IP + ' '}else{''}) + $(if($ProcessPath){'程序=' + $ProcessPath}else{''}) + ' [' + $Reason + ']')
    Write-Host "  [网络封锁] 需管理员权限, 请以管理员身份运行后重试" -ForegroundColor Yellow
  }
}

function Remove-NetBlock {
  # 解除封锁: 删除防火墙规则
  param([string]$RuleName, [string]$Target)
  try {
    Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
  } catch {}
  # 从清单移除
  if (Test-Path -LiteralPath $script:NetBlockListFile) {
    try {
      $lines = @(Get-Content $script:NetBlockListFile -Encoding UTF8 -ErrorAction SilentlyContinue |
        Where-Object { $_ -notmatch [regex]::Escape($Target) })
      if ($lines.Count -eq 0) { Clear-Content -Path $script:NetBlockListFile -ErrorAction SilentlyContinue }
      else { $lines | Set-Content -Path $script:NetBlockListFile -Encoding UTF8 }
    } catch {}
  }
  Write-AuditLog -Type 'NETBLOCK' -Msg ('已解除封锁: ' + $Target)
}

function Show-NetBlock {
  # /netblock: 查看封锁清单, 手动选择解除
  if (-not (Test-Path -LiteralPath $script:NetBlockListFile)) {
    Write-Host "  [网络封锁] 当前没有封锁规则。" -ForegroundColor Green
    try { Write-ScanProgress "[netblock] 当前没有封锁规则 (无需处理)" } catch {}
    return
  }
  $lines = @(Get-Content $script:NetBlockListFile -Encoding UTF8 -ErrorAction SilentlyContinue | Where-Object { $_ -and $_.Trim() })
  if ($lines.Count -eq 0) { Write-Host "  [网络封锁] 当前没有封锁规则。" -ForegroundColor Green; return }
  Write-Host ""
  Write-Host "============================================================" -ForegroundColor Yellow
  Write-Host ("  网络封锁清单: " + $lines.Count + " 条规则 (封禁恶意程序外联)") -ForegroundColor Yellow
  try { Write-ScanProgress ("[netblock] 封锁规则 " + $lines.Count + " 条, 输入序号可解除") } catch {}
  Write-Host "============================================================" -ForegroundColor Yellow
  for ($i=0; $i -lt $lines.Count; $i++) {
    $p = $lines[$i] -split '\|'
    $desc = if ($p.Count -ge 4) { $p[1] + "  [" + $p[2] + "] 规则=" + $p[3] } else { $lines[$i] }
    Write-Host ("  [" + ($i+1) + "] " + $desc) -ForegroundColor Gray
  }
  Write-Host ""
  Write-Host "  说明: 网络封锁 = 阻止恶意程序连接网络(病毒 C2 服务器); 解除 = 允许它联网(仅当你确认该程序无害时)" -ForegroundColor Cyan
  Write-Host "  输入要解除的序号 (单个 1 / 多个 1,3,5 / all 全部 / 0 返回; 数字 = 列表里的编号)"
  try { Write-ScanProgress ("[交互] 请在控制台窗口输入序号 (单个 1 / 多个 1,3 / 0返回)") } catch {}
  $choice = Read-Host "  选择"
  $idxList = @(Get-Selection -Choice $choice -Count $lines.Count)
  if ($idxList.Count -eq 1 -and $idxList[0] -eq -1) { Write-Host "  返回。"; return }
  if ($idxList.Count -eq 0) { Write-Host "  无有效选择。"; return }
  foreach ($idx in $idxList) {
    $p = $lines[$idx] -split '\|'
    $rule = if ($p.Count -ge 4) { $p[3] } else { '' }
    $target = if ($p.Count -ge 2) { $p[1] } else { $lines[$idx] }
    Write-Host ("  [解除] " + $target) -ForegroundColor Cyan
    Remove-NetBlock -RuleName $rule -Target $target
  }
  Write-Host ("  已解除 " + $idxList.Count + " 条封锁。")
}


function Get-Selection {
  # 解析交互序号选择: 单个 1 / 多个 1,3,5 / 范围 1-3 / all 全部 / 0 或空=取消
  # 返回 0-based 序号数组; 取消返回 @(-1)
  param([string]$Choice, [int]$Count)
  $sel = @()
  $choice = $Choice.Trim().ToLower()
  if ($choice -eq '0' -or $choice -eq '') { return @(-1) }
  if ($choice -eq 'all') { return @(0..($Count-1)) }
  foreach ($part in ($choice -split ',')) {
    $part = $part.Trim()
    if ($part -match '^\d+$') {
      $n = [int]$part
      if ($n -ge 1 -and $n -le $Count) { $sel += ($n-1) }
    } elseif ($part -match '^(\d+)-(\d+)$') {
      $s2 = [int]$Matches[1]; $e2 = [int]$Matches[2]
      for ($n=$s2; $n -le $e2; $n++) { if ($n -ge 1 -and $n -le $Count) { $sel += ($n-1) } }
    }
  }
  return @($sel | Sort-Object -Unique)
}

function Exit-Tool {
  param([int]$Code = 0, [string]$Reason = '正常完成')
  $script:ExitCode = $Code
  $script:ExitReason = $Reason
  try {
    # 1) 写受控退出标记 (明文 + SHA256 签名) - 其他程序没有 salt, 算不出正确 hash
    # v1.25: reason 先做 ASCII 净化 - Set-Content -Encoding ASCII 会丢弃中文成 '?',
    #        导致文件内容与签名内容不一致, 验签必失败 (v1.13 以来的隐藏 bug!)
    $safeReason = ($Reason -replace '[^\x20-\x7E]', '_')
    $plain = '{"pid":' + $PID + ',"time":"' + (Get-Date).ToString('o') + '","code":' + $Code + ',"reason":"' + ($safeReason -replace '"', '\\"') + '","ver":"1.13"}'
    $token = Protect-Token $plain
    # 防符号链接攻击: CreateNew 要求目标不存在 (预置 symlink 会失败), 失败则换随机名
    try {
      $fs = [System.IO.File]::Open($script:ExitFlag, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
      try {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($token)
        $fs.Write($bytes, 0, $bytes.Length)
      } finally { $fs.Close() }
      $script:ExitFlagged = $true
    } catch {
      try {
        $alt = Join-Path $script:EnvTmp ("sf_exit_" + $PID + "_" + [guid]::NewGuid().ToString("N").Substring(0,8) + ".flag")
        Set-Content -Path $alt -Value $token -Encoding ASCII -ErrorAction SilentlyContinue
        $script:ExitFlag = $alt
        $script:ExitFlagged = $true
      } catch {}
    }
  } catch {}
  # 2) 清理本进程临时标记残留 (仅清理 5 分钟前的)
  try {
    Get-ChildItem (Join-Path $script:EnvTmp 'sf_exit_*.flag') -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -ne (Split-Path $script:ExitFlag -Leaf) -and $_.LastWriteTime -lt (Get-Date).AddMinutes(-5) } |
      Remove-Item -Force -ErrorAction SilentlyContinue
  } catch {}
  # 3) 留痕
  # v1.34: 先停止关机拦截 (解除拦截, 恢复系统正常关机能力)
  try { Stop-ShutdownGuard } catch {}
  # v1.35: 操作留痕 - 退出 (在关机拦截汇总之后, 保证日志顺序: ...SHUTDOWN -> EXIT)
  try {
    $elapsed = [int]((Get-Date) - $script:AuditStartTime).TotalSeconds
    Write-AuditLog -Type 'EXIT' -Msg ($Reason + ' (code=' + $Code + ') 耗时=' + $elapsed + 's')
  } catch {}
  # 待办3: 删除运行标记 (正常退出) - 先关闭互斥锁句柄再删
  try { if ($script:RunLockFS) { $script:RunLockFS.Close(); $script:RunLockFS.Dispose() } } catch {}
  try { Remove-Item -Path $script:RunMark -Force -ErrorAction SilentlyContinue } catch {}
  Add-Content -Path $DebugLog -Value ("[退出] code=" + $Code + " 原因: " + $Reason + " 标记=" + $script:ExitFlag) -Encoding UTF8
  Write-Host ("`n[退出] " + $Reason + "  (code=" + $Code + ")") -ForegroundColor Cyan
  exit $Code
}

# ===================== 白名单 + 数字签名检测 (v1.24) =====================
# 白名单文件: bin/whitelist.txt (签名者/目录/路径/名称)
$script:WL = @{ Signers=@{}; Dirs=@{}; Paths=@{}; Names=@{} }
function Load-Whitelist {
  param([string]$f)
  if (-not (Test-Path -LiteralPath $f)) { return }
  Get-Content $f -Encoding UTF8 -ErrorAction SilentlyContinue | Where-Object { $_ -and -not $_.Trim().StartsWith('#') } | ForEach-Object {
    $line = $_.Trim()
    if (-not $line) { return }
    if ($line -match '^signer:(.+)$')      { $script:WL.Signers[$Matches[1].Trim().ToLower()] = $true }
    elseif ($line -match '^dir:(.+)$')      { $script:WL.Dirs[$Matches[1].Trim().ToLower()] = $true }
    elseif ($line -match '^[a-zA-Z]:\\')    { $script:WL.Paths[$line.ToLower()] = $true }   # v1.42: 兼容大写盘符
    else                                    { $script:WL.Names[$line.ToLower()] = $true }
  }
}
function Test-Whitelist {
  param([string]$Path, [string]$Name)
  if ($Name -and $script:WL.Names.ContainsKey($Name.ToLower())) { return $true }
  if ($Path) {
    $pl = $Path.ToLower()
    if ($script:WL.Paths.ContainsKey($pl)) { return $true }
    foreach ($d in $script:WL.Dirs.Keys) {
      # v1.40: 前缀匹配必须补分隔符, 防止 /path/Foo 匹配 /path/FooEvil
      $dp = $d.TrimEnd('\', '/') + '\'   # v1.61: '\\' 是双反斜杠字符串 -> char 转换失败, 改 '\'
      if ($pl.StartsWith($dp)) { return $true }
    }
  }
  return $false
}
function Get-SignatureStatus {
  param([string]$Path)
  # v2.15.33: LiteralPath 防 [ ] 文件名通配符异常
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return @{ Valid=$false; Signer=''; Raw='无签名' } }
  try {
    $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
    if (-not $sig) { return @{ Valid=$false; Signer=''; Raw='无签名' } }
    $signer = ''
    if ($sig.SignerCertificate) { $signer = ($sig.SignerCertificate.Subject -replace '^CN=', '') }
    return @{ Valid=($sig.Status -eq 'Valid'); Signer=$signer; Raw=$sig.Status.ToString() }
  } catch { return @{ Valid=$false; Signer=''; Raw='错误' } }
}
function Test-TrustedSigner {
  param([string]$Path)
  if (-not $Path) { return $false }
  $s = Get-SignatureStatus $Path
  if (-not $s.Valid -or -not $s.Signer) { return $false }
  $sn = $s.Signer.ToLower()
  foreach ($ts in $script:WL.Signers.Keys) {
    # 整体匹配 (老逻辑)
    if ($sn -like ('*' + $ts + '*') -or $ts -like ('*' + $sn + '*')) { return $true }
    # v1.26: token 子集匹配 - whitelist 任意一个 token 出现在 signer 中
    # 例: whitelist 'kingsoft' 匹配 'zhuhai kingsoft office software co., ltd.'
    $tsTokens = $ts -split '[\s,]+' | Where-Object { $_ -and $_.Length -ge 6 }
    foreach ($tok in $tsTokens) {
      if ($sn -like ('*' + $tok + '*')) { return $true }
    }
  }
  return $false
}
# ===================== v1.60: 签名安全港 (降误报核心) =====================
# C:\Program Files\* / C:\Program Files (x86)\* 下且带有效 Authenticode 签名的可执行文件,
# 跳过启发式/随机名/隐藏属性观察噪音 (正常安装软件); 但仍保留哈希比对 ——
# 已知恶意哈希命中仍会报高危并隔离 (安全港只豁免启发式噪音, 不豁免确证 IoC).
function Test-SafeHarbor {
  param([string]$Path)
  if (-not $Path) { return $false }
  $p = $Path.ToLower()
  if (-not ($p.StartsWith('c:\program files\') -or $p.StartsWith('c:\program files (x86)\'))) { return $false }
  $s = Get-SignatureStatus $Path
  return ($s.Valid -and $s.Signer)
}
# ===================== v1.95: PE 结构启发 (静态识别"双段 overlay / 加壳节") =====================
# 背景: 银狐"白签名双段捆绑"样本(如 WeChatWin_4.1.13.exe, 244MB) —— 前置小存根PE + 尾部
#       巨量 overlay(NSIS/真程序) + 前置加壳(.ndata/UPX/零尺寸节)。旧版只读 MZ 2 字节判 PE,
#       不加解析 e_lfanew/节表, 对这类"依赖结构深读才可见"的样本完全漏过; 且 >50MB 连验签都跳过。
# 本函数只读文件头(≤4096B)轻量解析: 算 overlay(尾部附加)大小/占比 + 加壳节(壳名/零原尺寸节)。
# 任何解析失败均返回 $null, 安全降级不误报。
function Get-PEStruct {
  param([string]$Path, [long]$Length)
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
  $r = @{ Overlay=0L; OverlayRatio=0.0; Packed=$false; Sections=@(); SecCount=0 }
  try {
    $fs = [System.IO.File]::OpenRead($Path)
    $n = [Math]::Min(4096L, $fs.Length)
    $buf = New-Object byte[] $n
    [void]$fs.Read($buf, 0, $n)
    $fs.Close()
    if ($buf.Length -lt 0x40) { return $null }
    $peOff = [BitConverter]::ToInt32($buf, 0x3C)
    if ($peOff -lt 0 -or ($peOff + 24) -gt $buf.Length) { return $null }
    if ($buf[$peOff] -ne 0x50 -or $buf[$peOff+1] -ne 0x45) { return $null }   # 'P','E'
    $numSec = [BitConverter]::ToUInt16($buf, $peOff+6)
    $optSize = [BitConverter]::ToUInt16($buf, $peOff+20)
    $secTable = $peOff + 24 + $optSize
    $maxRawEnd = 0L
    $packedSec = $false
    $secNames = @()
    $parsedSec = 0
    if ($numSec -gt 0 -and $secTable -gt 0 -and $secTable -lt $buf.Length) {
      for ($i=0; $i -lt $numSec; $i++) {
        $o = $secTable + $i*40
        if (($o + 40) -gt $buf.Length) { break }
        $parsedSec++
        $name = ([System.Text.Encoding]::ASCII.GetString($buf, $o, 8)).TrimStart([char]0) -replace '\0',''
        $rawSize = [BitConverter]::ToUInt32($buf, $o+16)
        $rawPtr  = [BitConverter]::ToUInt32($buf, $o+20)
        $secNames += $name
        $end = [long]$rawPtr + [long]$rawSize
        if ($end -gt $maxRawEnd) { $maxRawEnd = $end }
        if (-not $packedSec) {
          $up = $name.TrimStart('.').ToLower()
          # 已知壳/内存解压节名; .bss 类零尺寸节是合法未初始化数据, 排除
          if ($up -in @('upx0','upx1','upx2','vmp','packed','ri5','mpr1','aspack','adata','petite','nsp','enigma','ndata','themida','cryptone','tls0')) { $packedSec = $true }
          elseif ($rawSize -eq 0 -and $name -notin @('.bss','.idata','.tls','.stab','.stabstr')) { $packedSec = $true }   # 零原始尺寸 -> 内存解压迹象
        }
      }
    }
    if ($parsedSec -eq 0) { return $null }   # 连节表都解析不出, 当非标准PE, 不报
    $ov = 0L
    if ($Length -gt $maxRawEnd) { $ov = $Length - $maxRawEnd }
    $r.Overlay = $ov
    $r.OverlayRatio = if ($Length -gt 0) { [double]$ov / $Length } else { 0.0 }
    $r.Packed = $packedSec
    $r.Sections = $secNames
    $r.SecCount = $parsedSec
    return $r
  } catch { return $null }
}
# ===================== v1.95: 导入表敏感 API 扫描 (keylogger/剪贴板/注入/下载执行) =====================
# 默认由 /deep-pe 开关控制(默认关)。解析导入目录, 把被导入 DLL 的函数名(IMPORT_NAME)与敏感集合比对,
# 返回命中的敏感"类"列表。为零返回空数组, 解析失败(无导入表/截断/畸形)同样返回空, 安全降级不误报。
# 作用: 识别"存根导入表含键盘钩子/剪贴板/注入 API"的投递脚本(白签名样本的典型暗桩)。
function Get-ImportSensitive {
  param([string]$Path)
  $sensMap = [ordered]@{
    KEYBOARD  = @('getasynckeystate','sethookswin32','setwindowshookex','getkeystate','setwindowshookexw','setwindowshookexa')
    CLIPBOARD = @('openclipboard','getclipboarddata','setclipboarddata','emptyclipboard')
    INJECT    = @('virtualallocex','writeprocessmemory','createremotethread','ntmapviewofsection','queueuserapc')
    DOWNLOAD  = @('urldownloadtofile','urlmon','winexec','shellexecute','shellexecuteexw','wscript.shell','msxml2.xmlhttp','winhttp')
  }
  $hitClasses = [System.Collections.Generic.List[string]]::new()
  try {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return @() }
    $fs = [System.IO.File]::OpenRead($Path)
    $n = [Math]::Min([int]([Math]::Min(262144L, $fs.Length)), $fs.Length)   # 前 256KB 一般含 DOS/PE头/节表/导入表
    $buf = New-Object byte[] $n
    [void]$fs.Read($buf, 0, $n)
    $fs.Close()
    if ($buf.Length -lt 0x40) { return @() }
    $peOff = [BitConverter]::ToInt32($buf, 0x3C)
    if ($peOff -lt 0 -or ($peOff + 24) -gt $buf.Length) { return @() }
    if ($buf[$peOff] -ne 0x50 -or $buf[$peOff+1] -ne 0x45) { return @() }
    $magic = [BitConverter]::ToUInt16($buf, $peOff+24)
    if ($magic -ne 0x10B -and $magic -ne 0x20B) { return @() }   # PE32 / PE32+
    $numSec = [BitConverter]::ToUInt16($buf, $peOff+6)
    $optSize = [BitConverter]::ToUInt16($buf, $peOff+20)
    $secTable = $peOff + 24 + $optSize
    # 数据目录: PE32 offset=96, PE32+ offset=112 (index1 = 导入表)
    $ddOff = $peOff + 24 + $(if ($magic -eq 0x10B) { 96 } else { 112 })
    # RVA -> 文件偏移 映射 (构建节映射)
    $impRva = 0; $impSize = 0
    if (($ddOff + 16) -le $buf.Length) {
      $impRva = [BitConverter]::ToUInt32($buf, $ddOff + 1*8)
      $impSize = [BitConverter]::ToUInt32($buf, $ddOff + 1*8 + 4)
    }
    if ($impRva -eq 0) { return @() }
    function Rva2Off([uint32]$rva) {
      for ($i=0; $i -lt $numSec; $i++) {
        $o = $secTable + $i*40
        if (($o+40) -gt $buf.Length) { return -1 }
        $va = [BitConverter]::ToUInt32($buf, $o+12)
        $vs = [BitConverter]::ToUInt32($buf, $o+8)
        $rp = [BitConverter]::ToUInt32($buf, $o+20)
        $rs = [BitConverter]::ToUInt32($buf, $o+16)
        if ($rva -ge $va -and $rva -lt ($va + $vs)) {
          return ($rp + ($rva - $va))
        }
      }
      return -1
    }
    $impOff = Rva2Off $impRva
    if ($impOff -lt 0 -or $impOff -ge $buf.Length) { return @() }
    # 遍历 IMAGE_IMPORT_DESCRIPTOR (20B each, 以全 0 结束)
    $o = $impOff
    while (($o + 20) -le $buf.Length) {
      $oft = [BitConverter]::ToUInt32($buf, $o+0)    # OriginalFirstThunk
      $nt  = [BitConverter]::ToUInt32($buf, $o+16)   # FirstThunk
      $nameRva = [BitConverter]::ToUInt32($buf, $o+12)
      $dllName = ''
      if ($nameRva -ne 0) {
        $nOff = Rva2Off $nameRva
        if ($nOff -ge 0 -and $nOff -lt $buf.Length) {
          $e = $nOff
          while ($e -lt $buf.Length -and $buf[$e] -ne 0) { $e++ }
          if ($e -gt $nOff) { $dllName = [System.Text.Encoding]::ASCII.GetString($buf, $nOff, $e-$nOff) }
        }
      }
      $thunkRva = if ($oft -ne 0) { $oft } else { $nt }
      if ($thunkRva -ne 0) {
        $tOff = Rva2Off $thunkRva
        $step = if ($magic -eq 0x10B) { 4 } else { 8 }
        if ($tOff -ge 0 -and $tOff -lt $buf.Length) {
          $to = $tOff
          $guard = 0
          while ($guard -lt 2000 -and ($to + $step) -le $buf.Length) {
            $hn = if ($magic -eq 0x10B) { [BitConverter]::ToUInt32($buf, $to) } else { [BitConverter]::ToUInt64($buf, $to) }
            $hnU = [uint64]$hn
            if ($hnU -eq 0) { break }   # 数组结束
            if (($hnU -band 0x80000000) -eq 0) {   # 非导入序号(高位置0) -> 指向 Hint/Name
              $nameRva2 = if ($magic -eq 0x10B) { [uint32]$hnU } else { [uint32]($hnU -band 0xFFFFFFFF) }
              $no = Rva2Off $nameRva2
              if ($no -ge 0 -and $no -lt $buf.Length -and ($no+2) -lt $buf.Length) {
                $s = $no + 2   # 跳过 2 字节 Hint
                $e = $s
                while ($e -lt $buf.Length -and $buf[$e] -ne 0) { $e++ }
                if ($e -gt $s) {
                  $fname = [System.Text.Encoding]::ASCII.GetString($buf, $s, $e-$s).ToLower()
                  foreach ($k in $sensMap.Keys) {
                    if ($hitClasses -notcontains $k -and ($sensMap[$k] -contains $fname)) { $hitClasses.Add($k) }
                  }
                }
              }
            }
            $to += $step; $guard++
          }
        }
      }
      $z = [BitConverter]::ToUInt32($buf, $o+0) -bor [BitConverter]::ToUInt32($buf, $o+4) -bor [BitConverter]::ToUInt32($buf, $o+8) -bor [BitConverter]::ToUInt32($buf, $o+12) -bor [BitConverter]::ToUInt32($buf, $o+16)
      if ($z -eq 0) { break }
      $o += 20
      if ($o -gt ($impOff + $impSize + 40)) { break }   # 防御: 超出导入表区域
    }
    return @($hitClasses)
  } catch { return @() }
}
# ===================== v1.53: 风险评分关联引擎 (降误报核心) =====================
# 设计动机: 旧版任何单一弱启发式(命令行含 -w hidden / 计划任务指向 appdata / WMI 筛选器)
#            都直接判"高危"(Flag+隔离), 导致大量误报(正常软件更新任务/监控Agent等).
#            新版改为按权重累积风险分, 仅当总分越过阈值才升为"威胁"(隔离/锁定);
#            中等分数降为"待核实"(仅观察, 不隔离); 低分直接忽略.
#            强弱信号可叠加: 多个弱信号同时出现(auto-escalate)才会升级, 单一弱信号不再误杀.
$RISK = @{
  KNOWN_HASH      = 100   # 已知恶意哈希 (SHA256/MD5) - 确证
  IMPERSONATE_SYS = 90    # 伪装系统进程名且不在系统目录
  DOUBLE_EXT      = 85    # 双扩展名伪装 (.png.exe)
  MZ_IN_NONEXEC   = 70    # 图片/无扩展名文件含 MZ 头 (伪装可执行)
  C2_IP_CONN      = 80    # 实际外联到已知 C2 IP (网络层确证)
  C2_DOMAIN_CMD   = 45    # 命令行引用已知 C2 域名 (上下文弱, 可能是研究/防御)
  DL_EXEC_WEB     = 50    # 从网络下载并执行 (downloadstring/mshta/reg/bit/bitsadmin/certutil)
  ENCODED_CMD     = 20    # 编码命令 (-enc/encodedcommand, 合法编译脚本也常用)
  HIDDEN_PE       = 15    # 隐藏属性可执行 (配合其他信号)
  RANDOM_NAME_EXE = 5     # 随机名 exe (弱)
  PERSIST_TEMP    = 40    # 自启/任务/服务指向 temp (非 appdata)
  PERSIST_APPDATA = 5     # 指向 appdata (正常软件极常见, 弱)
  PERSIST_RANDNAME= 20    # 持久化目标为随机名 exe
  UNSIGNED_PERSIST= 30    # 持久化目标无有效签名/不在白名单
  WMI_FILTER      = 30    # WMI 事件筛选器 (监控类软件常建, 中)
  WIN_HIDDEN      = 5     # 仅 -w hidden / -nop -w hidden (常见合法)
  IEX_GENERIC     = 5     # 仅 iex (常见合法)
  BASE64_GENERIC  = 2     # 仅 base64 (噪声, 几乎不单独成立)
}
$RISK_THRESHOLD_THREAT = 80
$RISK_THRESHOLD_WARN   = 30

function Get-RiskVerdict {
  param([hashtable]$Signals)
  $total = 0; $reasons = @()
  if ($Signals) {
    foreach ($k in @($Signals.Keys)) {
      $w = [int]$Signals[$k]
      if ($w -gt 0) { $total += $w; $reasons += ($k + '(+' + $w + ')') }
    }
  }
  $v = if ($total -ge $RISK_THRESHOLD_THREAT) { 'THREAT' } elseif ($total -ge $RISK_THRESHOLD_WARN) { 'WARNING' } else { 'CLEAN' }
  return @{ Score=$total; Verdict=$v; Reasons=$reasons }
}

# 据评分裁决处置: 威胁->Flag+锁定+隔离; 待核实->Observe(仅观察); 干净->跳过
function Invoke-Verdict {
  param([hashtable]$Verdict, [string]$Label, [string]$Path, [string]$QuarantineReason, [switch]$NoQuarantine)
  if ($null -eq $Verdict -or $Verdict.Verdict -eq 'CLEAN') { return $false }
  $detail = if ($Verdict.Reasons -and $Verdict.Reasons.Count -gt 0) { ($Verdict.Reasons -join ', ') } else { '' }
  if ($Verdict.Verdict -eq 'THREAT') {
    if (-not $NoQuarantine) {
      try { Add-ThreatLock $Path $QuarantineReason } catch {}
      try { Quarantine $Path $QuarantineReason | Out-Null } catch {}
    }
    Flag ("  [高危-$QuarantineReason] " + $Label + " 风险分=" + $Verdict.Score + $(if($detail){" ("+$detail+")"}))
    return $true
  } else {
    # v1.71: 待核实明细同时写入报告 (用户报告里看到统计数字但未列出具体项)
    $revLine = "  [待核实-$QuarantineReason] " + $Label + " 风险分=" + $Verdict.Score + $(if($detail){" ("+$detail+")"})
    Observe $revLine
    Add-Report $revLine
    return $false
  }
}

# 命令行风险分类 (分阶段加权, 避免单一通用 token 误判高危)
function Get-CmdRisk([string]$cmd) {
  $s = @{}
  if (-not $cmd) { return $s }
  $c = [string]$cmd
  $hasHttp = $c -match 'https?://'
  # 下载并执行 (来自网络的载荷) - 高置信
  if ($c -match '(?i)downloadstring|invoke-webrequest|\biwr\b|net\.webclient|\bwget\b') { $s['DL_EXEC_WEB'] = 50 }
  elseif ($c -match '(?i)frombase64|convert::frombase64' -and $hasHttp) { $s['DL_EXEC_WEB'] = 50 }
  elseif ($c -match '(?i)mshta\b.*https?://') { $s['DL_EXEC_WEB'] = 50 }
  elseif ($c -match '(?i)bitsadmin\b.*/transfer') { $s['DL_EXEC_WEB'] = 50 }
  elseif ($c -match '(?i)regsvr32\b.*(scrobj\.dll|https?://)') { $s['DL_EXEC_WEB'] = 50 }
  elseif ($c -match '(?i)certutil\b.*(-urlcache|-decode).*https?://') { $s['DL_EXEC_WEB'] = 50 }
  elseif ($c -match '(?i)powershell\b.*-enc\b.*https?://') { $s['DL_EXEC_WEB'] = 50 }
  # 编码命令 (中等, 合法编译脚本也常用)
  if ($c -match '(?i)(-enc\b|encodedcommand)') {
    if (-not $s.ContainsKey('DL_EXEC_WEB')) { $s['ENCODED_CMD'] = 20 }
  }
  # 隐藏窗口 (常见合法: GUI 程序/安装包/计划任务)
  if ($c -match '(?i)(-w\s+hidden|-windowstyle\s+hidden|-nop\s+-w\s+hidden)') { $s['WIN_HIDDEN'] = 5 }
  # 通用 iex (常见合法)
  if ($c -match '(?i)\biex\b') {
    if (-not $s.ContainsKey('DL_EXEC_WEB')) { $s['IEX_GENERIC'] = 5 }
  }
  # 通用 base64 (噪声)
  if ($c -match '(?i)\bbase64\b') {
    if (-not $s.ContainsKey('DL_EXEC_WEB')) { $s['BASE64_GENERIC'] = 2 }
  }
  return $s
}

# 边界感知的 C2 域名匹配: 仅当域名作为独立 host token 出现才命中, 防止子串误报
# 例: C2='mal.com' 不会误命中 'notmal.com' / 'mal.com.evil' / 'xmal.com'
function Test-C2DomainInText([string]$text) {
  $hits = @()
  if (-not $text -or $script:c2Domains.Count -eq 0) { return $hits }
  foreach ($d in @($script:c2Domains.Keys)) {
    $pat = '(?i)(?<![a-z0-9.-])' + [regex]::Escape($d) + '(?![a-z0-9.-])'
    if ($text -match $pat) { $hits += $d }
  }
  return $hits
}

# 从命令/值字符串中正确提取可执行路径: 处理引号与含空格路径(如 "Program Files")
# 旧版用 -split ' ' 会把 "C:\Program Files\X\a.exe" 截断成 "C:\Program" 导致签名校验/白名单失效 -> 误报
function Get-ExecPath([string]$Raw) {
  $out = ''
  if ($Raw -match '"([^"]+)"') { $out = $Matches[1] }   # 引号路径优先
  else {
    $parts = ([string]$Raw).Trim() -split ' '
    $acc = ''
    foreach ($p in $parts) {
      $acc = if ($acc) { $acc + ' ' + $p } else { $p }
      if ($acc -match '\.exe$') { $out = $acc; break }
    }
    if (-not $out) { $out = $parts[0] }
  }
  # v1.79: 环境变量展开 (服务/计划任务 PathName 可能用 %SystemRoot%\system32\xxx.exe 形式)
  if ($out -match '^%([^%]+)%') {
    try {
      $envVal = [Environment]::GetEnvironmentVariable($Matches[1])
      if ($envVal) { $out = $out -replace '^%[^%]+%', $envVal }
    } catch {}
  }
  # v2.15.33: 相对路径补全 (系统服务 PathName 常为 "system32\svchost.exe -k ..." 无盘符前缀,
  #   否则 Test-Path 失败 -> 误判"无签名" + IMPERSONATE_SYS +90)
  if ($out -and -not ($out -match '^[a-zA-Z]:\\')) {
    $out = $out.Trim('/', ' ')
    if ($out -match '^(?i)(system32|syswow64)\\') {
      $out = (Join-Path $env:SystemRoot $out)
    }
  }
  return $out
}

# 持久化风险评分 (注册表Run/计划任务/服务共用): 把"位置+随机名+无签名+下载执行+伪装系统名"解耦加权
# 可信签名/白名单的条目在调用处直接跳过; 其余按权重累积, 单一弱信号(如仅指向 appdata)不再必报高危.
function Get-PersistRisk([string]$Exec, [string]$Value) {
  $s = @{}
  $exClean = Get-ExecPath $Exec
  $leaf = Split-Path $exClean -Leaf
  $v = [string]$Value
  # 下载执行特征 (高)
  if ($v -match '(?i)downloadstring|invoke-webrequest|frombase64|mshta\b|bitsadmin.*/transfer|regsvr32.*(scrobj\.dll|http)|certutil.*(-urlcache|-decode)|powershell.*-enc') { $s['DL_EXEC_WEB'] = 50 }
  # 伪装系统进程名 (exec 落点, 且不在系统目录)
  $sysNames = @('svchost.exe','explorer.exe','lsass.exe','services.exe','csrss.exe','winlogon.exe','smss.exe','taskhost.exe')
  if (($sysNames -contains $leaf.ToLower()) -and ($exClean -notmatch '(?i)\\system32\\|\\syswow64\\')) { $s['IMPERSONATE_SYS'] = 90 }
  # 落点位置
  if ($exClean -match '(?i)\\temp\\|\\tmp\\') { $s['PERSIST_TEMP'] = 40 }
  elseif ($exClean -match '(?i)\\appdata\\') { $s['PERSIST_APPDATA'] = 5 }
  # 随机名 exe
  if ($leaf -match '^[a-z0-9]{9,}\.exe$') { $s['PERSIST_RANDNAME'] = 20 }
  # 无有效签名且不在白名单 (附加信号, 25<阈值, 需佐证才升级)
  if ($exClean -and -not (Test-Whitelist -Path $exClean -Name $leaf) -and -not (Test-TrustedSigner $exClean)) {
    $s['UNSIGNED_PERSIST'] = 25
  }
  return @{ Signals=$s; ExecClean=$exClean; Leaf=$leaf }
}

# v1.23: 自定义文件枚举, 跳过大型缓存目录 (node_modules/.git/.cache 等)
function Global:Get-ChildItemSafe {
  param([string]$Path, [int]$Depth, [string[]]$IncludeExt)
  # v1.28: 枚举全部文件 (不再按扩展名过滤!) - 银狐可伪装成任意格式 (图片/驱动/无扩展名等)
  #        是否是可执行内容由调用方读文件头 (MZ) 判定
  $results = @()
  if ($Depth -lt 0 -or -not (Test-Path -LiteralPath $Path)) { return $results }
  $skipDirs = @('node_modules','.git','.cache','.vs','.idea','__pycache__','venv','.venv','dist','build','.next','.nuxt','.parcel-cache','.pnpm-store','.svelte-kit','.cache','bower_components','jspm_packages')
  try {
    $di = [System.IO.DirectoryInfo]::new($Path)
    foreach ($f in $di.GetFiles()) {
      $results += $f
    }
    if ($Depth -gt 0) {
      foreach ($d in $di.GetDirectories()) {
        if ($d.Name.StartsWith('.') -or $skipDirs -contains $d.Name.ToLower()) { continue }
        $results += @(Get-ChildItemSafe -Path $d.FullName -Depth ($Depth - 1) -IncludeExt $IncludeExt)
      }
    }
  } catch {}
  return $results
}

# ===================== 参数解析 =====================
# v1.12: 用 $PSCommandPath 自动定位 bin/ 目录, 不再依赖 bat 传 SF_SCRIPTDIR
$ScriptDir = if ($PSCommandPath) { Split-Path $PSCommandPath -Parent } else { Join-Path $script:toolRoot 'bin' }  # v1.31/1.2: 内存加载兜底
$Update=$false; $Full=$false; $NoHash=$false; $NoQuarantine=$false; $AutoUpdate=$false; $Restore=$false; $Purge=$false; $Rollback=$false; $Quick=$false; $Threads=4
# v1.7: 默认不自动隔离! 需要自动隔离时显式加 /quarantine
$QuarantineMode=$false
$Interactive=$false
# v1.43: 默认有文件类高危就弹交互菜单 (用户无需记 /interactive); 加 /noask 关闭
$AutoAsk=$true
$Ring0=$false
$script:SelfProtect=$true
$script:BreakOnTerm=$false    # v1.50: 蓝屏仅 /bruteprotect 显式开启
$ZeroTrust=$false
$StructPolicy=1          # v1.95: PE结构启发处置档位 1仅观察(默认)/2多信号叠加升级/3高危即隔离
$DeepPE=$false           # v1.95: 导入表敏感API扫描 - 默认关, /deep-pe 开启
$Safe=$false
$Offline=$false
$Immune=$false
$Repair=$false
$Trace=$false
$Rebuild=$false
$Drivers=$false   # v1.36: 驱动审计
$Unlock=$false    # v1.38: 解锁锁定清单
$NetBlock=$true   # v1.39: 默认自动封锁恶意程序网络
$MemScan=$false   # v1.42: 内存内容检测 (/mem)
$NetBlockMode=$false  # v1.39: /netblock 查看/解除模式
$script:ShutdownGuard=$true   # v1.34: 默认开启关机拦截 (防银狐强制重启)
$script:PathArgs = @()  # 非开关参数(如 /ring0 后的文件路径)

# ===================== v1.55: i18n 国际化框架 (系统语言优先, 英文兜底) =====================
# 语言优先级: /lang=xx 显式参数 > 系统 UI 语言 (zh/en) > 英文(en)
# 默认以系统语言为主, 未知语言回退英文 (开始适配英文)
# Language priority: /lang=xx > system UI language (zh/en) > English (en)
# Defaults to system language; falls back to English for unknown locales.
$script:_uiLang = 'en'
function Get-UILang {
  # 返回 'zh' 或 'en' (未知/出错 -> 'en')
  $sys = 'en'
  try {
    if ($Host -and $Host.CurrentUICulture -and $Host.CurrentUICulture.Name -match '^zh') { $sys = 'zh' }
  } catch {}
  if ($sys -eq 'en') {
    try { if ((Get-Culture).Name -match '^zh') { $sys = 'zh' } } catch {}
  }
  # 环境变量 (Linux/跨平台常见 LANG=zh_CN.UTF-8)
  foreach ($e in @($env:LANG, $env:LC_ALL, $env:LANGUAGE)) {
    if ($e -and $e -match 'zh') { $sys = 'zh'; break }
  }
  return $sys
}
# 双语消息表 (持续补全; 未覆盖的串维持中文原样)
# Bilingual message table (will be extended; uncovered strings stay in Chinese)
$script:MSG = @{
  zh = @{
    'INTEG_MISSING'       = '未找到完整性清单 integrity.manifest (可能被删除或为旧版)'
    'INTEG_REPORT_MISS'   = '警告: 未找到完整性清单, 工具完整性无法校验(建议重新解压工具包)'
    'INTEG_FMT_BAD'       = '完整性清单格式异常!'
    'INTEG_SIG_INVALID'   = '完整性清单签名无效(清单可能被篡改)!'
    'INTEG_REPORT_SIG'    = '警告: 完整性清单签名无效, 请检查工具是否被篡改'
    'INTEG_TAMPERED'      = '检测到工具文件被篡改或被替换!'
    'INTEG_REPORT_TAMPER' = '警告! 以下工具文件哈希不符(可能被篡改): '
    'INTEG_PASS'          = '工具完整性校验通过 ({0} 个文件), 签名日期: {1}'
    'INTEG_EXC'           = '完整性校验异常: '
    'INTEG_DATE_FUTURE'   = '签名日期在未来 ({0}), 可能是时钟异常或清单被篡改!'
    'INTEG_DATE_BAD'      = '签名日期格式异常: {0}'
    'START_BANNER'        = '银狐特攻引擎启动 (语言: {0})'
  }
  en = @{
    'INTEG_MISSING'       = 'Integrity manifest integrity.manifest not found (may be deleted or an old build)'
    'INTEG_REPORT_MISS'   = 'WARN: integrity manifest missing, tool integrity cannot be verified (re-extract the package)'
    'INTEG_FMT_BAD'       = 'Integrity manifest format error!'
    'INTEG_SIG_INVALID'   = 'Integrity manifest signature invalid (manifest may be tampered)!'
    'INTEG_REPORT_SIG'    = 'WARN: integrity manifest signature invalid, check whether the tool was tampered'
    'INTEG_TAMPERED'      = 'Tool files were tampered or replaced!'
    'INTEG_REPORT_TAMPER' = 'WARN! following tool files hash mismatch (may be tampered): '
    'INTEG_PASS'          = 'Tool integrity verified ({0} files), signed on: {1}'
    'INTEG_EXC'           = 'Integrity check error: '
    'INTEG_DATE_FUTURE'   = 'Signature date is in the future ({0}); clock anomaly or manifest tampering!'
    'INTEG_DATE_BAD'      = 'Signature date format error: {0}'
    'START_BANNER'        = 'SilverFox engine started (language: {0})'
  }
}
function T($key) {
  $m = $null
  if ($script:MSG -and $script:MSG.ContainsKey($script:_uiLang)) { $m = $script:MSG[$script:_uiLang] }
  if (-not $m -and $script:MSG.ContainsKey('en')) { $m = $script:MSG['en'] }
  if ($m -and $m.ContainsKey($key)) { return $m[$key] }
  return $key
}
$script:_uiLang = Get-UILang

foreach ($a in $args) {
  # v1.55 i18n: /lang=en|zh 或 --lang=en|zh 显式切换语言 (用 if 以正确捕获 $Matches)
  if ($a -match '^[-/]-?lang[=:](zh|en)$') { $script:_uiLang = $Matches[1] }
  switch ($a.ToLower()) {
    { $_ -in '/update','-update' }            { $Update=$true }
    { $_ -in '/full','-full' }                { $Full=$true }
    { $_ -in '/nohash','-nohash' }            { $NoHash=$true }
    { $_ -in '/noquarantine','-noquarantine' } { $NoQuarantine=$true }
    { $_ -in '/quarantine','-quarantine' }     { $QuarantineMode=$true }
    { $_ -in '/interactive','-interactive' }   { $Interactive=$true }
    { $_ -in '/ask','-ask' }                   { $AutoAsk=$true }   # v1.43 默认开启, 此开关显式启用
    { $_ -in '/noask','-noask' }               { $AutoAsk=$false }  # v1.43 关闭默认交互菜单
    { $_ -in '/ring0','-ring0' }                 { $Ring0=$true }
    { $_ -in '/zerotrust','-zerotrust' }         { $ZeroTrust=$true }
    { $_ -in '/safe','-safe' }                   { $Safe=$true }
    { $_ -in '/offline','-offline' }             { $Offline=$true }
    { $_ -in '/immune','-immune' }               { $Immune=$true }
    { $_ -in '/repair','-repair' }               { $Repair=$true }
    { $_ -in '/restoreav','-restoreav' }         { $RestoreAV=$true }   # v1.71 恢复杀毒软件
    { $_ -in '/trace','-trace' }                 { $Trace=$true }
    { $_ -in '/rebuild','-rebuild' }             { $Rebuild=$true }
    { $_ -in '/noselfprotect','-noselfprotect' } { $script:SelfProtect=$false }
    { $_ -in '/bruteprotect','-bruteprotect' }   { $script:BreakOnTerm=$true }   # v1.44 硬保护 (显式开启)
    { $_ -in '/softprotect','-softprotect' }   { $script:BreakOnTerm=$false }  # v1.49 软保护 (降级: 蓝屏关, 仅 watchdog 复活)
    { $_ -in '/drivers','-drivers' }             { $Drivers=$true }   # v1.36 驱动审计
    { $_ -in '/unlock','-unlock' }               { $Unlock=$true }    # v1.38 解锁清单
    { $_ -in '/netblock','-netblock' }         { $NetBlockMode=$true } # v1.39 查看/解除网络封锁
    { $_ -in '/mem','-mem' }                   { $MemScan=$true }    # v1.42 内存内容检测
    { $_ -in '/nonetblock','-nonetblock' }     { $NetBlock=$false }    # v1.39 关闭自动封锁
    { $_ -in '/noshutdownguard','-noshutdownguard' } { $script:ShutdownGuard=$false }  # v1.34
    { $_ -in '/autoupdate','-autoupdate' }     { $AutoUpdate=$true }
    { $_ -in '/restore','-restore' }           { $Restore=$true }
    { $_ -in '/purge','-purge' }               { $Purge=$true }
    { $_ -in '/rollback','-rollback' }         { $Rollback=$true }
    { $_ -in '/quick','-quick' }               { $Quick=$true }
    { $_ -in '/deep-pe','-deep-pe' }           { $DeepPE=$true }   # v1.95: 开启导入表敏感API扫描
    }
    if ($a -match '^/threads=(\d+)$') { $Threads = [int]$Matches[1]; if ($Threads -lt 1) { $Threads = 1 }; if ($Threads -gt 16) { $Threads = 16 } }
    if ($a -match '^/struct=([123])$') { $StructPolicy = [int]$Matches[1] }   # v1.95: /struct=1|2|3
  if ($a -notmatch '^/[-a-zA-Z0-9]+$' -and $a -notmatch '^/threads=' -and $a -notmatch '^/struct=') { $script:PathArgs += $a }
  }
# v1.42/v1.13: 统计容器显式初始化 (此前未初始化, $null+= 导致汇总恒 1 项/观察数据丢失)
$script:susp = @()
$script:observe = @()
$script:qcount = 0
# v1.44: 保存脚本参数供 watchdog 重启透传 (函数作用域内 $args 会被遮蔽; 顶层 $args 保持原值)
$script:ScriptArgs = @($args)
# v1.44: 进程级自保护 (DACL + 可选硬保护 + watchdog) - 任何模式分支/扫描之前, 引擎一启动即生效
$ErrorActionPreference = 'SilentlyContinue'
Add-Content -Path $DebugLog -Value ("  ScriptDir=$ScriptDir  Args=" + ($args -join ',') + "  QuarantineMode=$QuarantineMode")
# v1.35: 操作留痕 - 引擎启动
try {
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  Write-AuditLog -Type 'START' -Msg ("引擎启动 v1.94 PID=" + $PID + " 用户=" + $env:USERNAME + " 管理员=" + $isAdmin + " 语言=" + $script:_uiLang + " 参数=" + ($args -join ' '))
} catch {}





# ===================== 恢复模式 (调用 Restore.ps1) =====================
if ($Restore) {
  Write-AuditLog -Type 'MODE' -Msg '进入恢复模式 (/restore)'
  $restoreScript = Join-Path $ScriptDir 'Restore.ps1'
  if (Test-Path -LiteralPath $restoreScript) {
    Write-Host "检测到 /restore 参数, 进入隔离文件恢复模式..."
    # v1.42: 转发用户附加参数 (bat 透传的路径/-Recycle 等在 PathArgs)
    if ($script:PathArgs.Count -gt 0) { & $restoreScript -ManifestPath $null @($script:PathArgs) } else { & $restoreScript -ManifestPath $null }
  } else {
    Write-Host "[错误] 未找到 Restore.ps1, 请将其与本工具放在同一目录。" -ForegroundColor Red
  }
  Exit-Tool -Code 0 -Reason '恢复模式完成'
}

# ===================== 回滚模式 (调用 Rollback.ps1) =====================
if ($Rollback) {
  Write-AuditLog -Type 'MODE' -Msg '进入回滚模式 (/rollback)'
  $rollbackScript = Join-Path $ScriptDir 'Rollback.ps1'
  if (Test-Path -LiteralPath $rollbackScript) {
    Write-Host "检测到 /rollback 参数, 进入回滚恢复模式..."
    # v1.42: 转发用户附加参数
    if ($script:PathArgs.Count -gt 0) { & $rollbackScript @($script:PathArgs) } else { & $rollbackScript }
  } else {
    Write-Host "[错误] 未找到 Rollback.ps1, 请将其与本工具放在同一目录。" -ForegroundColor Red
  }
  Exit-Tool -Code 0 -Reason '回滚模式完成'
}

# ===================== 隔离区清理模式 (调用 Purge.ps1) =====================
if ($Purge) {
  Write-AuditLog -Type 'MODE' -Msg '进入清理模式 (/purge)'
  $purgeScript = Join-Path $ScriptDir 'Purge.ps1'
  if (Test-Path -LiteralPath $purgeScript) {
    Write-Host "检测到 /purge 参数, 进入隔离区清理模式..."
    # v1.42: 转发用户附加参数
    if ($script:PathArgs.Count -gt 0) { & $purgeScript @($script:PathArgs) } else { & $purgeScript }
  } else {
    Write-Host "[错误] 未找到 Purge.ps1, 请将其与本工具放在同一目录。" -ForegroundColor Red
  }
  Exit-Tool -Code 0 -Reason '清理模式完成'
}




# ===================== 报告路径兜底 =====================
try {
  $desktop = [Environment]::GetFolderPath('Desktop')
} catch {
  $desktop = $null
}
if (-not $desktop -or -not (Test-Path -LiteralPath $desktop)) { $desktop = $script:EnvUser }
if (-not $desktop) { $desktop = $script:EnvTmp }
$ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$outputDir = $script:toolRoot
try {
  if (-not (Test-Path -LiteralPath $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force -ErrorAction Stop | Out-Null }
  New-Item -ItemType File -Path (Join-Path $outputDir "_test.txt") -Force -ErrorAction Stop | Out-Null
  Remove-Item (Join-Path $outputDir "_test.txt") -Force -ErrorAction Stop
  # 写入报告文件
$log = Join-Path $outputDir ("银狐特攻扫描报告_" + $stamp + ".txt")
$qdir = Join-Path $outputDir ("银狐特攻隔离区_" + $stamp)
$obsFile = Join-Path $outputDir ("进程观察清单_" + $stamp + ".txt")
  Set-Content -Path $log -Value ("银狐特攻扫描报告已启动  [作者: 莫问QWQ v2.15.74] (" + (Get-Date) + ")`n若此文件之后无内容，说明引擎在初始化阶段异常，请查看 " + $DebugLog) -Encoding UTF8 -ErrorAction SilentlyContinue
  Add-Content -Path $DebugLog -Value ("  Report file: $log")
} catch {
  Add-Content -Path $DebugLog -Value ("  WARN: cannot create report file at $log : " + $_.Exception.Message)
}

# ===================== 全局 trap (v1.26 加强诊断) =====================
trap {
  try {
    # v1.35: 操作留痕 - 异常
    try { Write-AuditLog -Type 'ERROR' -Msg ('异常终止: ' + $_.Exception.Message + ' 行号=' + $_.InvocationInfo.ScriptLineNumber) } catch {}
    # v1.26: 完整诊断信息 - 必须能让用户看到精确行号才能定位
    $msg = "===== FATAL " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') + " =====`n"
    $msg += "Message         : " + $_.Exception.Message + "`n"
    $msg += "Category        : " + $_.CategoryInfo + "`n"
    $msg += "ErrorId         : " + $_.FullyQualifiedErrorId + "`n"
    $msg += "ScriptName      : " + $_.InvocationInfo.ScriptName + "`n"
    $msg += "ScriptLineNumber: " + $_.InvocationInfo.ScriptLineNumber + "`n"
    $msg += "OffsetInLine    : " + $_.InvocationInfo.OffsetInLine + "`n"
    $msg += "PositionMessage : `n" + $_.InvocationInfo.PositionMessage + "`n"
    $msg += "--- ScriptStackTrace ---`n" + $_.ScriptStackTrace + "`n"
    $msg += "--- ScriptLine (出错的行内容) ---`n" + $_.InvocationInfo.Line + "`n"
    $msg += "===== END FATAL =====`n"
    Add-Content -Path $DebugLog -Value $msg -Encoding UTF8
    Add-Content -Path $log -Value ("[FATAL] " + $_.Exception.Message) -Encoding UTF8 -ErrorAction SilentlyContinue
    # 屏幕也输出诊断关键行(用户能直接截图给我看)
    Write-Host ""
    Write-Host "===== FATAL 详细信息 (供开发者定位) =====" -ForegroundColor Red
    Write-Host ("  错误     : " + $_.Exception.Message) -ForegroundColor Red
    Write-Host ("  行号     : " + $_.InvocationInfo.ScriptLineNumber) -ForegroundColor Yellow
    Write-Host ("  错误行   : " + $_.InvocationInfo.Line) -ForegroundColor Yellow
    Write-Host ("  详见日志 : $DebugLog") -ForegroundColor Yellow
  } catch {}
  try { Exit-Tool -Code 1 -Reason ('异常终止: ' + $_.Exception.Message) } catch { exit 1 }
}

Write-Host "  ScriptDir: $ScriptDir" -ForegroundColor Gray
Write-Host "  Report   : $log"        -ForegroundColor Gray
Write-Host ""

# ===================== 内置种子库 =====================
$BuiltinHashes = @(
  '13aff4f82171d42e7f0a72dc96346c45',
  'f6c69d8026d2114e5322f06f69471a6c',
  '9913b09fddbe47d4459c1ae0aa8c4953',
  'e32797efc17c8a9a663f6f0e64fcfa08',
  # v1.31: 内置测试样本哈希(无害样本, 随更新同步; 命中后按已知恶意MD5/SHA256报告)
  'a6b425ce27bc6b1e109e13cf5b87b2db',  # 测试样本 发票_2026.png MD5
  'd5c36a5c601c1070dd91456e47e1e3da337821f6cdcef8b45733dae93226588b',  # 测试样本 发票_2026.png SHA256
  'de0d841b37a93750da276ca8c83bed23',  # 测试样本 2026工资表.doc.exe MD5
  '7be46b2c065d8f69c941b2500ee8632d01b87479dfce6950ce8d921717f50643'   # 测试样本 2026工资表.doc.exe SHA256
)
$BuiltinC2Domains = @('skystackservice.com','fast-cloud-node.com','nd9c887r.com','damaix9k.com','vaeth.cn','kkuu8899.org','cn-mumu.com.cn')
$BuiltinC2IPs = @('182.16.88.242')

# ===================== IOC 更新程序 =====================
function Update-IOC {
  param([string]$ScriptDir, [bool]$Full, [bool]$Quick)
  # v1.35: 操作留痕 - IOC 更新开始
  Write-AuditLog -Type 'IOC' -Msg ('IOC 更新开始 (Full=' + $Full + ' Quick=' + $Quick + ' 离线=' + $Offline + ')')
  $hashFile = Join-Path $ScriptDir "ioc\auto_hashes.txt"
  $c2File   = Join-Path $ScriptDir "ioc\auto_c2.txt"
  $H = @{}; $C = @{}
  $ua = "SilverFox-Detector/1.30"
  $srcStatus = @()
  $jobs = @(
    @{kind='local';  path=Join-Path $ScriptDir "update\update.json"},
    @{kind='remote'; url='https://raw.githubusercontent.com/YD-Shell/Silverfox_Detector/main/iocs.py'},
    @{kind='remote'; url='https://raw.githubusercontent.com/YD-Shell/Silverfox_Detector/main/update/update.json'}
  )
  if ($Full) { $jobs += @{kind='urlhaus'; url='https://urlhaus.abuse.ch/downloads/csv/'} }
  # v1.32 离线模式: 只用本地离线包, 不联网
  if ($Offline) { $jobs = @($jobs | Where-Object { $_.kind -eq 'local' }) }
  foreach ($j in $jobs) {
    try {
      $txt = $null
      if ($j.kind -eq 'local') {
        if (-not (Test-Path -LiteralPath $j.path)) { $srcStatus += "[跳过] 本地离线包不存在: $($j.path)"; continue }
        $txt = Get-Content $j.path -Raw
        $srcStatus += "[OK] 本地离线包: $($j.path)"
      } else {
        # v1.11: 超时 15s(Quick=5s), 静默进度条, 单次失败立即跳过(不重试)
        $to = if ($Quick) { 5 } else { 15 }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
          $r = Invoke-WebRequest -Uri $j.url -UserAgent $ua -TimeoutSec $to -UseBasicParsing -ErrorAction Stop
          $sw.Stop()
          $txt = $r.Content
          $srcStatus += ("[OK] 远程源 ({0}s): {1} ({2} 字节)" -f [int]$sw.Elapsed.TotalSeconds, $j.url, $r.RawContentLength)
        } catch {
          $sw.Stop()
          $srcStatus += ("[超时/失败 {0}s] {1}" -f [int]$sw.Elapsed.TotalSeconds, $j.url)
          continue
        }
      }
      if ($j.kind -eq 'urlhaus') {
        $tmp = Join-Path $script:EnvTmp ("uh_" + [guid]::NewGuid().ToString("N") + ".dl")
        Invoke-WebRequest -Uri $j.url -OutFile $tmp -UserAgent $ua -TimeoutSec 15 -UseBasicParsing
        $buf = New-Object byte[] 2
        $fs = New-Object System.IO.FileStream($tmp,'Open'); $fs.Read($buf,0,2) | Out-Null; $fs.Close()
        if ($buf[0] -eq 0x1f -and $buf[1] -eq 0x8b) {
          $fs = New-Object System.IO.FileStream($tmp,'Open')
          $gz = New-Object System.IO.Compression.GzipStream($fs,[System.IO.Compression.CompressionMode]::Decompress)
          $sr = New-Object System.IO.StreamReader($gz); $csv = $sr.ReadToEnd(); $sr.Close()
        } else {
          $zip = [System.IO.Compression.ZipArchive]::new([System.IO.FileStream]::new($tmp,'Open'))
          $sr = New-Object System.IO.StreamReader($zip.Entries[0].Open()); $csv = $sr.ReadToEnd(); $sr.Close()
        }
        foreach ($m in [regex]::Matches($csv,'[0-9a-fA-F]{64}')) { $H[$m.Value.ToLower()] = 'urlhaus' }
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
      } else {
        $md5blk = [regex]::Match($txt,'(KNOWN_MD5|md5s)"?\s*[=:]\s*[\{\[]([\s\S]*?)[\}\]]').Groups[2].Value   # v1.42: 兼容 JSON 引号
        foreach ($m in [regex]::Matches($md5blk,'[0-9a-fA-F]{32}')) { $H[$m.Value.ToLower()] = 'silverfox' }
        foreach ($m in [regex]::Matches($txt,'[0-9a-fA-F]{64}')) { $H[$m.Value.ToLower()] = 'silverfox' }
        $c2blk = [regex]::Match($txt,'(C2_DOMAINS|FISHING_DOMAINS|c2_domains|c2_ips)"?\s*[=:]\s*[\{\[]([\s\S]*?)[\}\]]').Groups[2].Value   # v1.42: 兼容 JSON 引号
        foreach ($m in [regex]::Matches($c2blk,'([a-z0-9.-]+\.(com|cn|org|net|info|top|xyz|ru|cc|tv|biz|wang|vip|shop|site|online|live|fun|club|link|pro))')) { $C[$m.Value.ToLower()] = 'silverfox' }
        foreach ($m in [regex]::Matches($c2blk,'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')) { $C[$m.Value] = 'silverfox' }
      }
    } catch {
      $srcStatus += "[失败] 源不可用: $($j.url)"
    }
  }
  $hdr = "# 自动更新生成，请勿手改。运行 银狐木马检测.bat /update 刷新`n# 生成时间: " + (Get-Date) + "`n"
  # v1.42: 全源失败/解析 0 条时不覆盖旧文件 (此前无条件写空表头)
  if ($H.Count -gt 0) { ($hdr + (($H.Keys | Sort-Object) | ForEach-Object { $_ + " # " + $H[$_] }) -join "`n") | Set-Content -Path $hashFile -Encoding UTF8 }
  else { Write-Host "  [警告] 本次更新未获取到哈希, 保留旧 auto_hashes.txt" -ForegroundColor Yellow }
  if ($C.Count -gt 0) { ($hdr + (($C.Keys | Sort-Object) -join "`n")) | Set-Content -Path $c2File -Encoding UTF8 }
  else { Write-Host "  [警告] 本次更新未获取到 C2, 保留旧 auto_c2.txt" -ForegroundColor Yellow }
  Write-Host "  [更新] 各数据源状态:"
  foreach ($s in $srcStatus) { Write-Host ("        " + $s) }
  Write-Host ("  [更新] 哈希 " + $H.Count + " 条 / C2 " + $C.Count + " 条 -> auto_hashes.txt / auto_c2.txt")
  # v1.35: 操作留痕 - IOC 更新完成
  Write-AuditLog -Type 'IOC' -Msg ('IOC 更新完成: 哈希 ' + $H.Count + ' 条 / C2 ' + $C.Count + ' 条')
  foreach ($s in $srcStatus) { Write-AuditLog -Type 'IOC' -Msg ('数据源: ' + $s) }
}

function Need-Update($ScriptDir){
  $f = Join-Path $ScriptDir "ioc\auto_hashes.txt"
  if (-not (Test-Path -LiteralPath $f)) { return $true }
  return ((Get-Date) - (Get-Item $f).LastWriteTime).TotalDays -gt 7
}

# ===================== 仅更新模式 =====================
if ($Update) {
  if (-not $ScriptDir) { $ScriptDir = $PWD }
  Update-IOC -ScriptDir $ScriptDir -Full $true -Quick $Quick
  Write-Host "IOC 更新完成。"
  Exit-Tool -Code 0 -Reason 'IOC更新完成'
}

# ===================== 自动轻量更新 =====================
if (-not $ScriptDir) { $ScriptDir = $PWD }
if (-not ($Immune -or $Repair -or $Trace) -and ($AutoUpdate -or (Need-Update $ScriptDir))) {
  $quicksuffix = if ($Quick) { " (Quick模式, 5s超时)" } else { " (15s/源)" }
  Write-Host ("正在检查 IOC 更新" + $quicksuffix + "...")
  try {
  Update-IOC -ScriptDir $ScriptDir -Full $AutoUpdate -Quick $Quick
} catch {
  Write-Host "自动更新失败，使用内置/本地库继续。"
}
}

# ===================== 加载 IOC 库 =====================
$hashMD5 = @{}; $hashSHA = @{}
function Load-Hashes($f){
  if (Test-Path -LiteralPath $f) {
    Get-Content $f | Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object {
      if ($_ -match '([0-9a-fA-F]{64})') { $hashSHA[$Matches[1].ToLower()] = $true }
      elseif ($_ -match '([0-9a-fA-F]{32})') { $hashMD5[$Matches[1].ToLower()] = $true }
    }
  }
}
Load-Hashes (Join-Path $ScriptDir "ioc\known_hashes.txt")
Load-Hashes (Join-Path $ScriptDir "ioc\auto_hashes.txt")
foreach ($h in $BuiltinHashes) { if ($h.Length -eq 32) { $hashMD5[$h.ToLower()] = $true } else { $hashSHA[$h.ToLower()] = $true } }

$c2Domains = @{}; $c2IPs = @{}
function Load-C2($f){
  if (Test-Path -LiteralPath $f) {
    Get-Content $f | Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object {
      $t = $_.Trim()
      if ($t -match '^\d{1,3}(\.\d{1,3}){3}$') { $c2IPs[$t] = $true }
      elseif ($t) { $c2Domains[$t.ToLower()] = $true }
    }
  }
}
Load-C2 (Join-Path $ScriptDir "ioc\known_c2.txt")
Load-C2 (Join-Path $ScriptDir "ioc\auto_c2.txt")
foreach ($d in $BuiltinC2Domains) { $c2Domains[$d.ToLower()] = $true }
foreach ($ip in $BuiltinC2IPs) { $c2IPs[$ip] = $true }

# ===================== 加载白名单 (v1.24) =====================
Load-Whitelist (Join-Path $ScriptDir 'whitelist.txt')

# ===================== 报告函数 =====================
function Add-Report($s){ if (-not $log) { return }; Add-Content -Path $log -Value $s -Encoding UTF8 }

# ===================== 扫描进度文件 (v1.68: GUI 实时展示) =====================
# 引擎把进度逐行写入 legacy\sf_scan_progress.log, GUI 主程序轮询刷新到界面.
$script:ProgressLog = Join-Path $script:toolRoot 'sf_scan_progress.log'
function Write-ScanProgress([string]$msg) {
  try { Add-Content -LiteralPath $script:ProgressLog -Value $msg -Encoding UTF8 } catch {}
}
function Clear-ScanProgress {
  try { if (Test-Path -LiteralPath $script:ProgressLog) { Clear-Content -LiteralPath $script:ProgressLog -ErrorAction SilentlyContinue } } catch {}
}

function Flag($s){ $script:susp += $s; Add-Report $s }

# ===================== 免疫 / 修复 / 追踪 (v1.33, 急救箱式) =====================
# 文件免疫: 关键系统文件哈希基线; Hosts免疫: 劫持检测+基线+只读加固
# 开机免疫: 启动项(Run/启动文件夹)基线 diff; /repair 修复; /trace 追踪银狐落点
$ImmuneState = Join-Path $script:toolRoot 'immune_state.txt'
$ImmuneSalt = 'SilverFoxDetector-IMMUNE-SALT-v1-!@#$%^&*2026'
$ImmuneFiles = @()
if ($env:WINDIR) {
  $wd = $env:WINDIR
  $ImmuneFiles = @(
    (Join-Path $wd 'System32\drivers\etc\hosts'),
    (Join-Path $wd 'System32\drivers\etc\networks'),
    (Join-Path $wd 'System32\drivers\etc\protocol'),
    (Join-Path $wd 'System32\drivers\etc\services'),
    (Join-Path $wd 'System32\kernel32.dll'),
    (Join-Path $wd 'System32\ntdll.dll'),
    (Join-Path $wd 'System32\user32.dll'),
    (Join-Path $wd 'System32\winlogon.exe'),
    (Join-Path $wd 'System32\svchost.exe'),
    (Join-Path $wd 'explorer.exe')
  )
}
$HostsPath = if ($env:WINDIR) { Join-Path $env:WINDIR 'System32\drivers\etc\hosts' } else { '' }
$BootRunKeys = @(
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
function Save-ImmuneState {
  param([string[]]$Lines)
  try {
    $payload = ($Lines -join "`n") + $ImmuneSalt
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $sig = ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payload))) -replace '-', '').ToLower().Substring(0, 16)
    Set-Content -Path $ImmuneState -Value ($Lines + @("sig=$sig")) -Encoding UTF8
  } catch {}
}
function Get-ImmuneLines {
  # 读基线并验签, 返回条目行(不含 sig)
  $out = @()
  try {
    if (Test-Path -LiteralPath $ImmuneState) {
      $ls = @(Get-Content $ImmuneState -Encoding UTF8 | Where-Object { $_ -and -not $_.Trim().StartsWith('#') })
      $sigLine = $ls | Where-Object { $_ -match '^sig=' } | Select-Object -First 1
      $entries = @($ls | Where-Object { $_ -notmatch '^sig=' })
      if ($sigLine -and $entries.Count -gt 0) {
        $payload = ($entries -join "`n") + $ImmuneSalt
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $h = ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payload))) -replace '-', '').ToLower()
        if ($h.StartsWith(($sigLine -replace '^sig=', '').Trim().ToLower())) { $out = $entries }
      }
    }
  } catch {}
  return $out
}
function Invoke-Immune {
  param([bool]$Rebuild)
  Write-Host ""
  Write-Host "============================================================" -ForegroundColor Cyan
  Write-Host "  系统免疫检查 (文件 / Hosts / 开机)  v1.33"                -ForegroundColor Cyan
  Write-Host "============================================================" -ForegroundColor Cyan
  $hasState = (Get-ImmuneLines).Count -gt 0
  $state = @(Get-ImmuneLines)
  # ---- 1) 文件免疫 ----
  Write-Host "  [1/3] 文件免疫: 关键系统文件哈希基线" -ForegroundColor Yellow
  $badFiles = @(); $okFiles = 0; $newFiles = 0
  foreach ($fp in $ImmuneFiles) {
    if (-not (Test-Path -LiteralPath $fp)) { continue }
    $h = (Get-FileHash -LiteralPath $fp -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    if (-not $h) { continue }
    $h = $h.ToLower()
    $key = 'F|' + $fp.ToLower()
    $prev = @($state | Where-Object { $_.Split('|')[0] -eq 'F' -and $_.Split('|')[1] -eq $fp.ToLower() })
    if ($Rebuild -or $prev.Count -eq 0) {
      $state = @($state | Where-Object { -not ($_.Split('|')[0] -eq 'F' -and $_.Split('|')[1] -eq $fp.ToLower()) })
      $state += ($key + '|' + $h)
      $newFiles++
    } elseif ($prev[0].Split('|')[2] -eq $h) { $okFiles++ }
    else { $badFiles += $fp }
  }
  if ($badFiles.Count -gt 0) {
    Write-Host "  [免疫] 关键系统文件被篡改或被替换!" -ForegroundColor Red
    foreach ($b in $badFiles) { Write-Host ("    ! " + $b) -ForegroundColor Red }
    Flag ("  [文件免疫] 警告! 关键文件哈希与基线不符: " + ($badFiles -join ', '))
  } elseif ($Rebuild -or -not $hasState) {
    Write-Host ("  [免疫] 文件基线已建立 (" + $newFiles + " 个文件)") -ForegroundColor Green
    Add-Report ("  [文件免疫] 基线已建立: " + $newFiles + " 个关键文件")
  } else {
    Write-Host ("  [免疫] 文件基线校验通过 (" + $okFiles + " 个)") -ForegroundColor Green
    Add-Report ("  [文件免疫] 校验通过: " + $okFiles + " 个关键文件")
  }
  # ---- 2) Hosts 免疫 ----
  Write-Host ""
  Write-Host "  [2/3] Hosts 免疫: 劫持检测 + 基线 + 加固" -ForegroundColor Yellow
  if (Test-Path -LiteralPath $HostsPath) {
    $hijack = @(); $obsHosts = @()
    foreach ($ln in @(Get-Content $HostsPath -ErrorAction SilentlyContinue)) {
      $t = $ln.Trim()
      if (-not $t -or $t.StartsWith('#')) { continue }
      foreach ($d in $BuiltinC2Domains) {
        if ($t -match [regex]::Escape($d)) { $hijack += ($t + "   [命中C2: $d]"); break }
      }
      if ($t -match '^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+([a-z0-9.-]+)\s*$' -and $t -notmatch '^\s*127\.0\.0\.1\s+localhost') {
        # 公网/内网 IP 映射域名(非本机回环) -> 可疑, 观察
        if ($t -notmatch '^\s*(127\.|::1|0\.0\.0\.0|255\.255\.255\.255)') { $obsHosts += ($t + "   [非回环映射]") }
      }
    }
    if ($hijack.Count -gt 0) {
      Write-Host "  [Hosts免疫] 检测到可疑 hosts 条目!" -ForegroundColor Red
      foreach ($h2 in $hijack) { Write-Host ("    ! " + $h2) -ForegroundColor Red }
      Flag ("  [Hosts免疫] hosts 存在可疑条目: " + ($hijack -join ' | '))
      Write-Host "  提示: 可用 /repair 选择修复 hosts 文件。" -ForegroundColor Yellow
    } elseif ($obsHosts.Count -gt 0) {
      Write-Host "  [Hosts免疫] 未发现劫持, 以下非回环映射仅供参考(内网环境常见):" -ForegroundColor Gray
      foreach ($o in $obsHosts) { Write-Host ("      " + $o) -ForegroundColor Gray }
    } else { Write-Host "  [Hosts免疫] 未发现劫持条目" -ForegroundColor Green }
    # 只读加固
    try {
      $attrs = (Get-Item $HostsPath -Force -ErrorAction Stop).Attributes
      if (($attrs -band [IO.FileAttributes]::ReadOnly) -eq 0) {
        Write-Host "  [Hosts免疫] hosts 当前可写, 建议加固为只读" -ForegroundColor Yellow
        $ans = Read-Host "  是否立即加固 (只读, 防病毒篡改; 仅管理员可改)? [y/N]"
        if ($ans.Trim().ToLower() -eq 'y') {
          attrib.exe +R $HostsPath 2>$null
          try { icacls.exe $HostsPath /inheritance:r /grant:r "SYSTEM:(F)" "Administrators:(F)" "Users:(RX)" 2>$null | Out-Null } catch {}
          Write-Host "  [OK] hosts 已加固为只读 (恢复: attrib -R 后再改)" -ForegroundColor Green
          Add-Report "  [Hosts免疫] 已加固 hosts 为只读"
        }
      } else { Write-Host "  [Hosts免疫] hosts 已是只读, 加固状态良好" -ForegroundColor Green }
    } catch {}
  } else { Write-Host "  [Hosts免疫] hosts 文件不存在(异常!)" -ForegroundColor Red }
  # ---- 3) 开机免疫 ----
  Write-Host ""
  Write-Host "  [3/3] 开机免疫: 启动项基线 (Run/启动文件夹)" -ForegroundColor Yellow
  $boot = @()
  foreach ($k in $BootRunKeys) {
    try {
      Get-ItemProperty $k -ErrorAction SilentlyContinue | ForEach-Object {
        $_.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Name -ne 'ProxyEnable' } | ForEach-Object {
          $boot += ('R|' + $k + '|' + $_.Name + '=' + [string]$_.Value)
        }
      }
    } catch {}
  }
  foreach ($sf in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
    if ($sf -and (Test-Path -LiteralPath $sf)) {
      Get-ChildItem $sf -File -ErrorAction SilentlyContinue | ForEach-Object { $boot += ('S|' + $sf + '|' + $_.Name) }
    }
  }
  $newBoot = @(); $bootOk = 0
  foreach ($item in $boot) {
    if ($Rebuild -or -not $hasState) { $state += $item }
    else {
      $prev = @($state | Where-Object { $_ -eq $item })
      if ($prev.Count -gt 0) { $bootOk++ } else { $newBoot += $item }
    }
  }
  if ($newBoot.Count -gt 0) {
    Write-Host "  [开机免疫] 检测到新增启动项 (相对上次基线)!" -ForegroundColor Red
    foreach ($n in $newBoot) { Write-Host ("    + " + $n) -ForegroundColor Red }
    Flag ("  [开机免疫] 新增启动项 " + $newBoot.Count + " 条: " + ($newBoot -join ' | '))
  } elseif ($Rebuild -or -not $hasState) {
    Write-Host ("  [开机免疫] 启动项基线已建立 (" + $boot.Count + " 条)") -ForegroundColor Green
    Add-Report ("  [开机免疫] 基线已建立: " + $boot.Count + " 条启动项")
  } else {
    Write-Host ("  [开机免疫] 启动项基线无变化 (" + $bootOk + " 条一致)") -ForegroundColor Green
    Add-Report ("  [开机免疫] 校验通过: " + $bootOk + " 条启动项一致")
  }
  Save-ImmuneState $state
  Write-Host ""
  Write-Host "  免疫检查完成。基线文件: $ImmuneState (加 /rebuild 可重建基线)" -ForegroundColor Gray
}
function Repair-HostsFile {
  param([string]$bkDir)
  if (Test-Path -LiteralPath $HostsPath) {
    try { Copy-Item $HostsPath (Join-Path $bkDir 'hosts.bak') -Force; Write-Host ("  [备份] hosts -> " + (Join-Path $bkDir 'hosts.bak')) -ForegroundColor Gray } catch {}
    try { attrib.exe -R $HostsPath 2>$null | Out-Null } catch {}
    $default = @(
      '# Copyright (c) 1993-2009 Microsoft Corp.',
      '#',
      '# 本文件由 SilverFox 检测工具 /repair 修复恢复 (原文件已备份)',
      '#',
      '# 127.0.0.1       localhost',
      '# ::1             localhost',
      '',
      '127.0.0.1       localhost',
      '::1             localhost'
    )
    Set-Content -Path $HostsPath -Value $default -Encoding ASCII
    Write-Host "  [修复] hosts 已恢复默认 (劫持条目已清除)" -ForegroundColor Green
    Add-Report ("  [修复] hosts 已恢复默认, 备份: " + (Join-Path $bkDir 'hosts.bak'))
  } else { Write-Host "  [错误] hosts 不存在" -ForegroundColor Red }
}
function Invoke-Repair {
  Write-Host ""
  Write-Host "============================================================" -ForegroundColor Cyan
  Write-Host "  系统修复 (备份 -> 修复 -> 报告)  v1.33"                   -ForegroundColor Cyan
  Write-Host "============================================================" -ForegroundColor Cyan
  Write-Host "  可修复项目:"
  Write-Host "   1. hosts 文件 (恢复默认, 清除劫持条目)"
  Write-Host "   2. DNS 设置 (检查异常 DNS + 刷新缓存)"
  Write-Host "   3. 代理设置 (清除恶意代理劫持)"
  Write-Host "   4. Winsock/LSP (netsh winsock reset, 需管理员 + 重启)"
  Write-Host "   0. 退出"
  try { Write-ScanProgress "[交互] 系统修复菜单, 请在控制台窗口选择 (1 hosts / 2 DNS / 3 代理 / 4 Winsock / 0 退出)" } catch {}
  $sel = Read-Host "  选择 (数字 = 上面的编号, 多个用逗号如 1,3; 输入 all = 全部修复; 输入 0 = 退出)"
  $sel = $sel.Trim().ToLower()
  if ($sel -eq '0' -or $sel -eq '') { Write-Host "  已退出修复模式。"; return }
  $bkDir = Join-Path $script:toolRoot ("修复备份_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
  try { New-Item -ItemType Directory -Path $bkDir -Force | Out-Null } catch {}
  $pick = @()
  if ($sel -eq 'all') { $pick = @(1,2,3,4) }
  else { foreach ($p in ($sel -split ',')) { $n = [int]($p.Trim()); if ($n -ge 1 -and $n -le 4) { $pick += $n } } }
  if ($pick -contains 1) { Write-Host ""; Write-Host "  [1] 修复 hosts 文件..." -ForegroundColor Yellow; Repair-HostsFile $bkDir }
  if ($pick -contains 2) {
    Write-Host ""; Write-Host "  [2] DNS 检查与修复..." -ForegroundColor Yellow
    try {
      $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 } | ForEach-Object { $_.ServerAddresses })
      Write-Host ("  当前 IPv4 DNS: " + $(if ($dns) { ($dns -join ', ') } else { '无(自动)' })) -ForegroundColor Gray
      $susDns = @($dns | Where-Object { $_ -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|169\.254\.)' })
      if ($susDns.Count -gt 0) {
        Write-Host ("  [警告] 检测到内网/保留 DNS: " + ($susDns -join ', ') + " (可能是 DHCP 或劫持)") -ForegroundColor Red
        Flag ("  [DNS修复] 检测到异常 DNS: " + ($susDns -join ', '))
      }
      ipconfig.exe /flushdns 2>$null | Out-Null
      Write-Host "  [修复] DNS 缓存已刷新" -ForegroundColor Green
      Write-Host "  提示: 若确认被劫持, 在 网络适配器属性-IPv4-DNS 改回自动获取, 或使用可信 DNS (223.5.5.5 / 119.29.29.29)。" -ForegroundColor Gray
    } catch { Write-Host "  [错误] DNS 检查失败: " + $_.Exception.Message -ForegroundColor Red }
  }
  if ($pick -contains 3) {
    Write-Host ""; Write-Host "  [3] 代理劫持检查..." -ForegroundColor Yellow
    try {
      $ik = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
      $ip = Get-ItemProperty $ik -ErrorAction Stop
      if ($ip.ProxyEnable -eq 1) {
        Write-Host ("  [警告] 系统代理已开启: " + $ip.ProxyServer + " (病毒常借此劫持流量)") -ForegroundColor Red
        reg.exe export $ik (Join-Path $bkDir 'proxy_backup.reg') /y 2>$null | Out-Null
        $ans = Read-Host "  是否关闭代理? (备份已存 proxy_backup.reg) [y/N]"
        if ($ans.Trim().ToLower() -eq 'y') {
          Set-ItemProperty $ik -Name ProxyEnable -Value 0
          Write-Host "  [修复] 代理已关闭" -ForegroundColor Green
          Add-Report "  [代理修复] 已关闭系统代理 (原值: $($ip.ProxyServer))"
        }
      } else { Write-Host "  系统代理未开启, 无劫持" -ForegroundColor Green }
    } catch { Write-Host "  [错误] 代理检查失败" -ForegroundColor Red }
  }
  if ($pick -contains 4) {
    Write-Host ""; Write-Host "  [4] 重置 Winsock/LSP..." -ForegroundColor Yellow
    Write-Host "  说明: 病毒常通过 LSP/Winsock 劫持网络, 重置可恢复 (需管理员, 重启后生效)" -ForegroundColor Gray
    $ans = Read-Host "  确认重置? (会中断当前网络连接) [y/N]"
    if ($ans.Trim().ToLower() -eq 'y') {
      try {
        netsh.exe winsock reset 2>$null | Out-Null
        netsh.exe int ip reset 2>$null | Out-Null
        Write-Host "  [修复] Winsock/LSP 已重置, 请重启系统后生效" -ForegroundColor Green
        Add-Report "  [Winsock修复] 已执行 netsh winsock reset + int ip reset"
      } catch { Write-Host "  [错误] 重置失败(需要管理员权限)" -ForegroundColor Red }
    }
  }
  Write-Host ""
  Write-Host "  修复完成。备份目录: $bkDir" -ForegroundColor Gray
}
function Invoke-Trace {
  Write-Host ""
  Write-Host "============================================================" -ForegroundColor Cyan
  Write-Host "  银狐修改目录追踪 (常落点扫描)  v1.33"                     -ForegroundColor Cyan
  Write-Host "============================================================" -ForegroundColor Cyan
  $dirs = @($script:EnvTmp, (Join-Path $env:WINDIR 'Temp'), $env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData, 'C:\Users\Public', [Environment]::GetFolderPath('Startup'))
  $cut = (Get-Date).AddDays(-30)
  $totalSus = 0
  foreach ($d in $dirs) {
    if (-not $d -or -not (Test-Path -LiteralPath $d)) { continue }
    Write-Host ("  追踪: " + $d) -ForegroundColor Yellow
    $sus = @()
    try {
      $files = @(Get-ChildItem $d -Recurse -Depth 1 -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $cut })
      if ($files.Count -gt 8000) { Write-Host "    文件过多(" + $files.Count + "), 仅扫描最近修改前 8000 个" -ForegroundColor Gray; $files = @($files | Sort-Object LastWriteTime -Descending | Select-Object -First 8000) }
      # 只对候选(可执行/伪装/隐藏/无扩展名)读文件头, 避免全量 IO
      $files = @($files | Where-Object { $_.Name -match '\.(exe|dll|scr|pif|bat|cmd|vbs|js|ps1|com|png|jpg|jpeg|gif|doc|xls|pdf)$' -or $_.Name -match '^\.[a-z0-9_]+$' -or $_.Name -notmatch '\.' })
      foreach ($f in $files) {
        # 跳过 FIFO/socket 等特殊文件 (OpenRead 会阻塞)
        if (-not [System.IO.File]::Exists($f.FullName)) { continue }
        $isELF = $false
        try { $fs = [IO.File]::OpenRead($f.FullName); $b0 = $fs.ReadByte(); $b1 = $fs.ReadByte(); $fs.Close(); $isPE = ($b0 -eq 0x4D -and $b1 -eq 0x5A) } catch {}
        if ($f.Name -match '\.(png|jpg|jpeg|gif|doc|xls|pdf)\.exe$') { $sus += ($f.FullName + "  [双扩展名伪装] " + $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) }
        elseif ($isPE -and $f.Extension -notmatch '^\.(exe|dll|sys)$') { $sus += ($f.FullName + "  [伪装可执行MZ] " + $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) }
        elseif ($isPE -and $f.Name -match '^[a-z0-9]{9,}\.exe$') { $sus += ($f.FullName + "  [随机名exe] " + $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) }
      }
    } catch {}
    if ($sus.Count -gt 0) {
      foreach ($s in $sus) { Write-Host ("    ! " + $s) -ForegroundColor Yellow; Flag ("  [追踪] " + $s); $totalSus++ }
    } else { Write-Host "    近 30 天无可疑文件" -ForegroundColor Gray }
  }
  Write-Host ""
  Write-Host ("  追踪完成: 发现可疑 " + $totalSus + " 项 (详见报告)") -ForegroundColor Green
}
# ===================== Defender 排除项检查 (v1.93) =====================
function Invoke-DefExclCheck {
  # 病毒常用手段: 把自身/目录加进 Defender 排除列表让杀软"失明"(样本: 假图吧工具排除 C:\ 整盘)
  $exclBases = @(
    'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths',
    'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions',
    'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes',
    'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Threats',
    'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths'
  )
  foreach ($k in $exclBases) {
    if (Test-Path -LiteralPath $k) {
      try {
        $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        $names = @($props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $_.Name })
        foreach ($nm in $names) {
          if ($nm -match '(?i)^[a-z]:\\$') {
            Add-Report ("  [高危-Defender排除] 整盘被加入排除: " + $nm + " (病毒防失明手法!)")
            Write-Host ("  [高危-Defender排除] 整盘排除: " + $nm + " (建议恢复杀毒软件清除)") -ForegroundColor Red
          } elseif ($nm -match '(?i)^[a-z]:\\(windows|users|programdata|program files|program files \(x86\))(\\|$)') {
            Add-Report ("  [高危-Defender排除] 系统目录被加入排除: " + $nm + " (病毒手法!)")
            Write-Host ("  [高危-Defender排除] 系统目录排除: " + $nm) -ForegroundColor Red
          } elseif ($nm -match '(^|\\\\)(temp|appdata|downloads|programdata|windows\\system32)' -or $nm -match '(?i)https?://') {
            Add-Report ("  [可疑-Defender排除] " + $nm + " 位置=" + $k + " (病毒常用手段, 请核实)")
            Write-Host ("  [可疑-Defender排除] " + $nm) -ForegroundColor Yellow
          } else {
            Add-Report ("  [信息-Defender排除] " + $nm + " 位置=" + $k + " (常规排除, 如非本人添加请核对)")
          }
        }
      } catch { Add-Report ("  [排除项读取失败] " + $k) }
    }
  }
}

# ===================== 证书信任链检查 (v1.84) =====================
function Invoke-CertCheck {
  # 病毒常用手段: 安装自签名根证书(伪造 HTTPS/签名信任)或篡改可信根
  # v1.89: 慎报 —— 系统根证书存储中大量老牌 CA/软件厂商自建证书属正常; 仅"自签+名称似乱码/随机字符"标警告
  #   (如 15+位随机字母数字无空格、重复字符、异常特殊符号); 其余自签仅列信息; 不自动弹处置
  $trustedPat = '(?i)(microsoft|windows|digicert|verisign|symantec|geotrust|thawte|entrust|comodo|sectigo|globalsign|letsencrypt|isrg|amazon|azure|godaddy|softline|usertrust|baltimore|cybertrust|equifax|addtrust|securetrust|secure\s?sign|wosign|utm|catcert|actalis|buypass|certum|swisssign|quovadis|huawei|zte|alibaba|tencent|baidu|cfca|gdca|cnca|unizetto|starfield|opentrust|ssl\.com|google|apple|cisco|netrust|svt|prime\.ca|telia|swedbank|keywitness|china|national|veri|identrust|szca|visa|verint|wang|sectra|netskope|digi|kinetic|mobilicert|lynx|pki|opentrust|spanish|cid|serpro|acraiz|ssl)'
  # 常见软件/厂商自建证书(用户安装的加速器/开发工具/PLC软件等属正常, 不再误报)
  $venderPat = '(?i)(beyonddimension|steamtools|etalien|game\s?booster|leigod|blizzard|battle\.net|siemens|wincc|df\b|sap|oracle|vmware|skype|teams|cisco|fortinet|palo\.?alto|eset|kaspersky|avast|360|huorong|qq|tencent|netease|epic\.?games|steam|ea\b|ubisoft|rockstar|microsoft|intel|amd|nvidia|apple|google|ubnt|ec\.acc|catalana)'
  # 可疑特征: 名称无空格且长度>=16 的随机样(大量小写混杂数字/重复段), 或者极度短(<=5)无意义
  $suspPat = '(?i)(^[a-z0-9]{16,}$|^[a-z0-9]{2,5}$|([a-z])\2{4,}|[0-9]{6,}$|\*|\+|^[a-z]+[0-9]{8,}$)'
  try {
    $roots = @(Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue)
    $warn = @(); $info = @()
    foreach ($c in $roots) {
      try {
        if (-not ($c.Subject -and $c.Issuer -and $c.Subject -eq $c.Issuer)) { continue }
        if ($c.Subject -match $trustedPat -or $c.Subject -match $venderPat) { continue }
        if ($c.Subject -match $suspPat) {
          $warn += $c
          Add-Report ("  [警告-证书] " + $c.Subject + " (指纹 " + $(if($c.Thumbprint){$c.Thumbprint.Substring(0,8)}) + "...)")
        } else {
          $info += $c.Subject
        }
      } catch {}
    }
    if ($warn.Count -gt 0) {
      Add-Report ("  [警告-证书] 发现 " + $warn.Count + " 个可疑自签名证书 (名称似乱码/随机字符, 请核实):")
      foreach ($c in $warn) { Add-Report ("    - " + $c.Subject) }
      Write-Host ("  [证书] 发现 " + $warn.Count + " 个可疑自签名证书(名称异常), 请核实; 其余自签证书为软件/企业CA正常") -ForegroundColor Yellow
    } else {
      Add-Report ("  [证书] 根证书存储 " + $roots.Count + " 个; 未发现名称异常的自签名证书 (自签 " + $info.Count + " 个为软件/企业CA, 属正常)")
      Write-Host ("  [证书] 根证书 " + $roots.Count + " 个, 无异常自签名证书") -ForegroundColor Green
    }
    # v1.89: 不再自动弹处置菜单(避免误报吓小白), 仅在可疑时才提示查看报告
    if ($warn.Count -gt 0) { try { Write-ScanProgress ("[cert] 有 " + $warn.Count + " 个可疑证书, 见报告核实") } catch {} }
  } catch { Add-Report ("  [证书] 检查异常: " + $_.Exception.Message) }
}

# ===================== 恢复杀毒软件 (v1.71) =====================
function Invoke-RestoreAV {
  Write-Host ""
  Write-Host "============================================================" -ForegroundColor Cyan
  Write-Host ("  恢复杀毒软件功能  " + $bannerVer + " (银狐限制安全软件反推全项)") -ForegroundColor Cyan
  Write-Host "============================================================" -ForegroundColor Cyan
  Add-Report ("  ===== 恢复杀毒软件 (" + $bannerVer + ") =====")
  # --- v1.75: 修复前健康快照 (修复完成后对比) ---
  $preSnapshot = @{}
  try {
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
      $mp0 = Get-MpComputerStatus -ErrorAction SilentlyContinue
      if ($mp0) { $preSnapshot['Defender实时'] = $mp0.RealtimeProtectionEnabled }
    }
  } catch {}
  try {
    $fwText = (netsh advfirewall show allprofiles state 2>$null) -join "`n"
    $preSnapshot['防火墙'] = ($fwText -match 'State\s*:\s*OFF')
  } catch {}
  try { $preSnapshot['WinDefend服务'] = ((Get-Service -Name WinDefend -ErrorAction SilentlyContinue).Status) } catch {}
  $prePol = 0
  foreach ($k in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender','HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection')) {
    if (Test-Path -LiteralPath $k) {
      foreach ($v in @('DisableRealtimeMonitoring','DisableBehaviorMonitoring','DisableAntiSpyware','DisableOnAccessProtection')) {
        if ((Get-ItemProperty -Path $k -Name $v -ErrorAction SilentlyContinue).$v -gt 0) { $prePol++ }
      }
    }
  }
  $preSnapshot['策略禁用项'] = $prePol
  # v1.92: 第三方安全软件检测提前到函数开头(阶段1/2 需在检测后)
  $script:thirdAV = $null
  try {
    $tmpAV = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue)
    foreach ($ta in $tmpAV) {
      if ($ta.displayName -notmatch '(?i)(defender|windows defender|windows security|security essentials)') {
        $script:thirdAV = $ta.displayName
      }
    }
  } catch {}
  if ($script:thirdAV) {
    $infos += ("检测到第三方杀软接管: " + $script:thirdAV + " —— Defender 相关项停用/禁用属正常状态, 不再列出警告")
  }
  $fixed = @(); $warns = @(); $infos = @()
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) {
    Write-Host "  [提示] 需管理员权限才能修复策略/服务; 当前非管理员, 仅执行检查" -ForegroundColor Yellow
    Add-Report "  [提示] 非管理员, 策略/服务修复受限 (请以管理员身份重新运行)"
  }

  # ---- 1) Defender 组策略禁用项 (含全部子键) ----
  try { Write-ScanProgress "[restoreav] 1/16 检查 Defender 策略..." } catch {}
  $polBases = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Security Center',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager',
    'HKCU:\SOFTWARE\Policies\Microsoft\Windows Defender'
  )
  $polVals = @('DisableAntiSpyware','DisableRealtimeMonitoring','DisableOnAccessProtection','DisableBehaviorMonitoring','DisableSecurityCenter','DisableIOAVProtection','DisableAntiVirus','DisableSpyNet','DisableScanOnRealtimeEnable','DisableRoutinelyTakingAction','DisableUXConfiguration')
  foreach ($k in $polBases) {
    if (Test-Path -LiteralPath $k) {
      foreach ($v in $polVals) {
        try {
          $prop = Get-ItemProperty -Path $k -Name $v -ErrorAction SilentlyContinue
          if ($prop -and $prop.$v -gt 0) {
            if ($script:thirdAV) {
              # v1.91: 第三方杀软接管时 Defender 禁用策略属正常(由第三方接管)
              $infos += ("Defender 策略" + $v + " 已禁用(第三方接管, 正常): " + $k)
            } elseif ($isAdmin) {
              Remove-ItemProperty -Path $k -Name $v -Force -ErrorAction Stop
              $fixed += ("已清除 Defender 策略禁用: " + $v + " (" + $k + ")")
            } else { $warns += ("发现(非管理员未清除): " + $v + " (" + $k + ")") }
          }
        } catch { $warns += ("处理失败: " + $v + " (" + $k + "): " + $_.Exception.Message) }
      }
    }
  }
  # 客户端实际配置 (非 Policies, 病毒直接写客户端注册表)
  $cliBases = @(
    'HKLM:\SOFTWARE\Microsoft\Windows Defender',
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection'
  )
  $cliVals = @('DisableRealtimeMonitoring','DisableAntiSpyware','DisableOnAccessProtection','DisableBehaviorMonitoring','DisableScheduledScan','DisableIOAVProtection','DisableAntiVirus')
  foreach ($k in $cliBases) {
    if (Test-Path -LiteralPath $k) {
      foreach ($v in $cliVals) {
        try {
          $prop = Get-ItemProperty -Path $k -Name $v -ErrorAction SilentlyContinue
          if ($prop -and $prop.$v -gt 0) {
            if ($script:thirdAV) {
              $infos += ("Defender 客户端" + $v + " 已禁用(第三方接管, 正常): " + $k)
            } elseif ($isAdmin) {
              Remove-ItemProperty -Path $k -Name $v -Force -ErrorAction Stop
              $fixed += ("已清除 Defender 客户端禁用: " + $v + " (" + $k + ")")
            } else { $warns += ("发现(非管理员未清除): " + $v + " (" + $k + ")") }
          }
        } catch { $warns += ("处理失败: " + $v + " (" + $k + "): " + $_.Exception.Message) }
      }
    }
  }

  # ---- 2) UAC 恢复 (病毒常禁用 UAC 让安全软件提权失效) ----
  try { Write-ScanProgress "[restoreav] 2/16 检查 UAC..." } catch {}
  $uacKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  if (Test-Path -LiteralPath $uacKey) {
    try {
      $u = Get-ItemProperty -Path $uacKey -Name EnableLUA -ErrorAction SilentlyContinue
      if ($u -and $u.EnableLUA -eq 0) {
        if ($isAdmin) {
          Set-ItemProperty -Path $uacKey -Name EnableLUA -Value 1 -Type DWord -Force -ErrorAction Stop
          $fixed += "UAC 已恢复启用 (EnableLUA=0 -> 1, 需重启生效)"
        } else { $warns += "发现 UAC 被禁用 (EnableLUA=0), 需管理员恢复" }
      }
    } catch { $warns += ("UAC 恢复失败: " + $_.Exception.Message) }
  }

  # ---- 3) 系统工具禁用解除 (任务管理器/注册表编辑器/CMD) ----
  try { Write-ScanProgress "[restoreav] 3/16 检查系统工具禁用..." } catch {}
  $toolPolicies = @{
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' = @('DisableTaskMgr','DisableRegistryTools','DisableCMD')
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' = @('DisallowRun','NoRun')
  }
  foreach ($k in $toolPolicies.Keys) {
    if (Test-Path -LiteralPath $k) {
      foreach ($v in $toolPolicies[$k]) {
        try {
          $prop = Get-ItemProperty -Path $k -Name $v -ErrorAction SilentlyContinue
          if ($prop) {
            if ($v -eq 'DisallowRun' -or $v -eq 'NoRun') {
              $warns += ("发现程序限制设置: " + $v + " (" + $k + "), 请人工核对 (可能是企业策略)")
              continue
            }
            if ($prop.$v -ne 0 -and $prop.$v -ne $null) {
              if ($isAdmin) {
                Remove-ItemProperty -Path $k -Name $v -Force -ErrorAction Stop
                $fixed += "系统工具禁用已解除: " + $v
              } else { $warns += ("发现禁用: " + $v + " (" + $k + ")") }
            }
          }
        } catch { $warns += ("处理失败: " + $v + ": " + $_.Exception.Message) }
      }
    }
  }

  # ---- 4) Windows Update 禁用解除 (病毒防补丁) ----
  try { Write-ScanProgress "[restoreav] 4/16 检查 Windows Update..." } catch {}
  $wuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
  if (Test-Path -LiteralPath $wuKey) {
    try {
      $wu = Get-ItemProperty -Path $wuKey -Name DisableWindowsUpdateAccess -ErrorAction SilentlyContinue
      if ($wu -and $wu.DisableWindowsUpdateAccess -eq 1) {
        if ($isAdmin) {
          Remove-ItemProperty -Path $wuKey -Name DisableWindowsUpdateAccess -Force -ErrorAction Stop
          $fixed += "Windows Update 访问禁用已解除"
        } else { $warns += "发现 Windows Update 被禁用" }
      }
    } catch { $warns += ("处理失败: " + $_.Exception.Message) }
  }
  $auKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
  if (Test-Path -LiteralPath $auKey) {
    try {
      $au = Get-ItemProperty -Path $auKey -Name NoAutoUpdate -ErrorAction SilentlyContinue
      if ($au -and $au.NoAutoUpdate -eq 1) {
        if ($isAdmin) {
          Set-ItemProperty -Path $auKey -Name NoAutoUpdate -Value 0 -Type DWord -Force -ErrorAction Stop
          $fixed += "Windows Update 自动更新已恢复 (NoAutoUpdate -> 0)"
        } else { $warns += "发现 NoAutoUpdate=1 (非管理员未修改)" }
      }
    } catch { $warns += ("处理失败: " + $_.Exception.Message) }
  }

  # ---- 5) 安全软件服务恢复 (Defender 全家 + 第三方常用服务名) ----
  try { Write-ScanProgress "[restoreav] 5/16 检查安全软件服务..." } catch {}
  # v1.91: 第三方安全软件检测(有接管时 Defender 相关全部降为信息, 避免误报)
    $svcAuto = @('WinDefend','WdNisSvc','SecurityHealthService','wscsvc')
  # v1.77: 驱动类服务(WdBoot/WdFilter)启动类型为 System/Boot, 不得改成 Automatic(会破坏驱动加载); 仅当被禁用时恢复 System
  $svcDriver = @('WdBoot','WdFilter')
  # 第三方安全软件服务 (按常见厂商名, best-effort; 仅恢复启动类型不安装)
  $trustedSvcPat = '(?i)(360|huorong|hips|defense|antivirus|kill|kaspersky|avp|avast|avg|rising|mfe|mcafee|symantec|norton|qqpc|tencent|safedog|kingsoft|bitdefender|eset|nods32|malwarebytes|fsecure|trendmicro|panda|sophos|netskope|qhuo|zhu dong|zhudongfangyu)'
  $allSvcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
  foreach ($sn in $svcAuto) {
    $svc = Get-Service -Name $sn -ErrorAction SilentlyContinue
    if (-not $svc) { continue }
    try {
      if ($svcDriver -contains $sn) {
        # v1.77: 驱动服务只保运行, 不改 Automatic
        if ($svc.StartType -eq 'Disabled') {
          if ($isAdmin) {
            # v1.83: PS5.1 Set-Service -StartupType 枚举不含 System, 用 sc.exe config start= system
            $null = (& sc.exe config $sn start= system 2>&1)
            $fixed += ("驱动服务已恢复: " + $sn + " (System)")
          } else { $warns += ("驱动服务被禁用: " + $sn + ", 需管理员恢复") }
        }
      } elseif ($svc.StartType -ne 'Automatic') {
        if ($script:thirdAV) {
          $infos += ("服务 " + $sn + " 非自动(" + $svc.StartType + ", 第三方接管, 正常)")
        } elseif ($isAdmin) {
          Set-Service -Name $sn -StartupType Automatic -ErrorAction Stop
          try { Start-Service -Name $sn -ErrorAction SilentlyContinue } catch {}
          $fixed += ("服务恢复自动: " + $sn)
        } else { $warns += ("服务 " + $sn + " 非自动(" + $svc.StartType + "), 需管理员恢复") }
      } elseif ($svc.Status -ne 'Running') {
        if ($script:thirdAV) {
          $infos += ("服务 " + $sn + " 状态 " + $svc.Status + " (第三方接管, 正常)")
        } elseif ($isAdmin) {
          try { Start-Service -Name $sn -ErrorAction Stop; $fixed += ("服务已启动: " + $sn) }
          catch { $warns += ("服务 " + $sn + " 启动失败: " + $_.Exception.Message) }
        }
      }
    } catch { $warns += ("服务处理失败: " + $sn + ": " + $_.Exception.Message) }
  }
  # 第三方: 只检查 StartType=Disabled 且名称匹配安全特征的服务
  if ($allSvcs) {
    foreach ($svc in $allSvcs) {
      if ($svc.StartMode -ne 'Disabled') { continue }
      if ($svc.Name -match $trustedSvcPat -or $svc.DisplayName -match $trustedSvcPat) {
        if ($isAdmin) {
          try {
            $null = (& sc.exe config $svc.Name start= auto 2>&1)
            try { $null = (& sc.exe start $svc.Name 2>&1) } catch {}
            $fixed += ("第三方安全软件服务已恢复: " + $svc.Name + " (" + $svc.DisplayName + ")")
          } catch { $warns += ("第三方服务恢复失败: " + $svc.Name) }
        } else {
          $warns += ("发现第三方安全软件服务被禁用: " + $svc.Name + " (" + $svc.DisplayName + "), 需管理员恢复")
        }
      }
    }
  }

  # ---- 6) hosts 安全厂商域名劫持移除 ----
  try { Write-ScanProgress "[restoreav] 6/16 检查 hosts 劫持..." } catch {}
  $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
  if ($isAdmin -and (Test-Path -LiteralPath $hostsPath)) {
    try {
      $avDomains = '(?i)(360safe|360\.cn|huorong|rising|kaspersky|avast|avg|mcafee|symantec|norton|defender|microsoft\.com|eset|bitdefender|malwarebytes|kingsoft|qq\.com.*(pc|safe)|tencent.*(pc|safe))'
      $lines = Get-Content -LiteralPath $hostsPath -ErrorAction SilentlyContinue
      $removed = @()
      $kept = @()
      foreach ($ln in $lines) {
        $trimmed = $ln.Trim()
        if ($trimmed -and -not $trimmed.StartsWith('#') -and ($trimmed -match '^0\.0\.0\.0\s' -or $trimmed -match '^127\.0\.0\.1\s') -and ($trimmed -match $avDomains)) {
          $removed += $trimmed
        } else {
          $kept += $ln
        }
      }
      if ($removed.Count -gt 0) {
        $bk = Join-Path $script:toolRoot ('hosts.avbackup_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
        Set-Content -LiteralPath $bk -Value $lines -Encoding ASCII -ErrorAction SilentlyContinue
        Set-Content -LiteralPath $hostsPath -Value $kept -Encoding ASCII -ErrorAction SilentlyContinue
        $fixed += ("hosts 安全厂商劫持已移除 " + $removed.Count + " 行 (备份 " + $bk + "): " + ($removed -join ' | '))
      }
    } catch { $warns += ("hosts 处理失败: " + $_.Exception.Message) }
  }

  # ---- 7) 安全软件进程检测 ----
  try { Write-ScanProgress "[restoreav] 7/16 检测安全软件进程..." } catch {}
  try {
    $avProcs = @('MsMpEng','NisSrv','SecurityHealthService','360Tray','360Safe','360sd','360se','QQPCTray','QQPCRTP','HipsTray','HipsDaemon','kissvc','avp','avastui','avgnt','RavMonD','ZhuDongFangYu','wsctrl','sguard')
    foreach ($pn in $avProcs) {
      $p = Get-Process -Name $pn -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($p) { $infos += ("杀软进程运行中: " + $pn + " (PID " + $p.Id + ")") }
    }
    $avs = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
    if ($avs) {
      foreach ($a in $avs) {
        # v1.80: productState 解码保守化 —— bit12-13 是跨厂商通用"启用"位, 其余字节各厂商自研编码
        #   (360=0x56010 等自研值, 细解读会误导"过期/实时关闭"); 故只读启用位, 其余提示以厂商界面为准
        $psn = $a.productState
        $dec = ("状态码=" + $psn)
        try {
          $iv = [Convert]::ToInt32($psn, 16)
          $en = (($iv -shr 12) -band 3)
          if ($en -eq 1) { $dec = ("启用=是(状态码=" + $psn + ")") }
          elseif ($en -eq 2) { $dec = ("启用=是(可能被篡改, 状态码=" + $psn + ")") }
          else { $dec = ("启用=否(状态码=" + $psn + ")") }
          $dec += " (实时/过期状态请以厂商界面为准)"
        } catch {}
        $line = ("杀软登记: " + $a.displayName + " [" + $dec + "]")
        $infos += $line
        Add-Report ("  [杀软] " + $line)
        Write-Host ("  [杀软] " + $line) -ForegroundColor Gray
      }
    } else {
      $warns += "安全中心未登记任何杀毒软件 (Defender 可能被禁用或未注册)"
    }
    $fws = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName FirewallProduct -ErrorAction SilentlyContinue
    if ($fws) { foreach ($f in $fws) { $infos += ("防火墙登记: " + $f.displayName + " 状态码=" + $f.productState) } }
  } catch { $warns += ("安全中心查询异常: " + $_.Exception.Message) }

  # ---- 9) Defender 排除项检测 (病毒把自身/目录加入白名单让杀软失明) ----
  try { Write-ScanProgress "[restoreav] 8/16 检查 Defender 排除项..." } catch {}
  $exclBases = @(
    'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths',
    'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions',
    'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes',
    'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Threats',
    'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths'
  )
  foreach ($k in $exclBases) {
    if (Test-Path -LiteralPath $k) {
      try {
        $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        $names = @($props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $_.Name })
        foreach ($nm in $names) {
          if ($nm -match '(?i)^[a-z]:\\$') {
            $warns += ("[高危-Defender排除] 整盘被加入排除: " + $nm + " (病毒防失明手法! 建议用恢复杀毒软件清除)")
          } elseif ($nm -match '(?i)^[a-z]:\\(windows|users|programdata|program files|program files \(x86\))(\\|$)') {
            $warns += ("[高危-Defender排除] 系统目录被加入排除: " + $nm + " (病毒手法! 建议用恢复杀毒软件清除)")
          } elseif ($nm -match '(^|\\)(temp|appdata|downloads|programdata|windows\\system32)' -or $nm -match '(?i)https?://') {
            $warns += ("发现可疑 Defender 排除项: " + $nm + " 位置=" + $k + " (病毒常用手段, 请人工核对后手动删除)")
          } else {
            $infos += ("Defender 排除项: " + $nm + " 位置=" + $k + " (属常规排除, 如非本人添加请核对)")
          }
        }
      } catch { $warns += ("排除项读取失败: " + $k) }
    }
  }
  # v1.90: 自动清除"盘根/系统目录"排除项(病毒把 Defender 开盲的手法; 记录+移除)
  foreach ($ek in $exclBases) {
    if (Test-Path -LiteralPath $ek) {
      $props = Get-ItemProperty -Path $ek -ErrorAction SilentlyContinue
      foreach ($p in @($props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
        if ($p.Name -match '(?i)^[a-z]:\\$' -or $p.Name -match '(?i)^[a-z]:\\(windows|users|programdata|program files|program files \(x86\))(\\|$)') {
          try {
            Remove-ItemProperty -Path $ek -Name $p.Name -Force -ErrorAction Stop
            $fixed += ("已清除整盘/系统目录 Defender 排除项: " + $p.Name + " (" + $ek + ") [病毒防失明手法]")
          } catch { $warns += ("清除排除项失败: " + $p.Name + ": " + $_.Exception.Message) }
        }
      }
    }
  }

  # ---- 10) 安全软件服务缺失检测 (被病毒删除) ----
  try { Write-ScanProgress "[restoreav] 9/16 检查服务缺失..." } catch {}
  foreach ($sn in $svcAuto) {
    $svcKey = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\" + $sn
    if (-not (Test-Path -LiteralPath $svcKey)) {
      if ($script:thirdAV) {
        $infos += ("服务 " + $sn + " 未注册(第三方接管环境, 正常)")
      } else {
        $warns += ("服务注册表缺失(可能被病毒删除): " + $sn + " —— 若系统组件建议 sfc /scannow + 重装 Defender 平台")
      }
    }
  }

  # ---- 11) 杀软自启动项缺失检测 ----
  try { Write-ScanProgress "[restoreav] 10/16 检查杀软自启动..." } catch {}
  try {
    $runKeys = @(
      'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'
    )
    $avRunPat = '(?i)(360|huorong|hips|antivirus|defender|kaspersky|avp|avast|rising|qqpc|tencent|mcafee|norton|symantec)'
    foreach ($rk in $runKeys) {
      if (Test-Path -LiteralPath $rk) {
        $props = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
        foreach ($p in @($props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
          if ($p.Name -match $avRunPat -and -not $p.Value) {
            $warns += ("杀软自启动项异常(值空): " + $p.Name + " (" + $rk + ")")
          } elseif ($p.Name -match $avRunPat -and $p.Value) {
            $infos += ("杀软自启动项在: " + $p.Name + " (" + $rk + ")")
          }
        }
      }
    }
    # v1.91: 仅对"已安装安全软件"检查自启动缺失(未安装的厂商不再误报)
    $avNames = @()
    try {
      $avProds = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue)
      foreach ($ap in $avProds) { $avNames += $ap.displayName }
    } catch {}
    $avMap = @{
      '360' = @('360Tray','360Soft','360Safetray','360安全卫士','360安全')
      'huorong|火绒' = @('HipsTray','HipsDaemon')
      'qqpc|腾讯|tencent' = @('QQPCTray','QQPCRTP')
      'kaspersky|卡巴' = @('kav','avp')
      'avast' = @('avastui')
      'rising|瑞星' = @('RavTray','RavMonD')
      'bitdefender|bd' = @('bdagent')
      'eset|nods' = @('egui')
    }
    if ($avNames.Count -gt 0) {
      foreach ($key in $avMap.Keys) {
        $installed = $false
        foreach ($an in $avNames) { if ($an -match $key) { $installed = $true; break } }
        if ($installed) {
          # v1.92: 该杀软进程运行中 -> 自启/守护正常, 不再报缺失
          $procRunning = $false
          foreach ($pn in @('360Tray','360Safe','360sd','HipsTray','HipsDaemon','QQPCTray','QQPCRTP','kav','avp','avastui','RavTray')) {
            if (Get-Process -Name $pn -ErrorAction SilentlyContinue) { $procRunning = $true; break }
          }
          if ($procRunning) {
            $infos += ("杀软自启检查: " + $key + " 相关进程运行中(自启正常)")
          } else {
            foreach ($rkey in @('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run')) {
              if (Test-Path -LiteralPath $rkey) {
                $props = Get-ItemProperty -Path $rkey -ErrorAction SilentlyContinue
                foreach ($c in $avMap[$key]) {
                  if (-not ($props.PSObject.Properties | Where-Object { $_.Name -match $c })) {
                    $warns += ("未见杀软自启动项: " + $c + " (已安装该杀软但自启缺失, 请在其主界面修复)")
                  }
                }
              }
            }
          }
        }
      }
    }
  } catch { $warns += ("自启动项检查异常: " + $_.Exception.Message) }

  # ---- 12) Defender 防篡改 (TamperProtection) 检查 ----
  try { Write-ScanProgress "[restoreav] 11/16 检查防篡改..." } catch {}
  try {
    $tpKey = 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Features'
    if (Test-Path -LiteralPath $tpKey) {
      $tp = Get-ItemProperty -Path $tpKey -Name TamperProtection -ErrorAction SilentlyContinue
      if ($tp -and $tp.TamperProtection -eq 0) {
        $warns += "Defender 防篡改已被关闭 (TamperProtection=0), 病毒可随意修改 Defender; 请在 Windows 安全中心手动开启"
      } else {
        $infos += ("Defender 防篡改状态: " + $(if ($tp.TamperProtection -eq 5) {'开启'} else {'未知(' + $tp.TamperProtection + ')'}))
      }
    }
  } catch { $warns += ("防篡改检查异常: " + $_.Exception.Message) }

  # ---- 13) 代理 / DNS 异常提示 ----
  try { Write-ScanProgress "[restoreav] 12/16 检查代理/DNS..." } catch {}
  try {
    $proxy = Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -ErrorAction SilentlyContinue
    if ($proxy -and $proxy.ProxyEnable -eq 1 -and $proxy.ProxyServer) {
      if ($proxy.ProxyServer -match '(?i)(0\.0\.0\.0|127\.0\.0\.1|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:|[a-z0-9]+\.[a-z0-9]+\.[a-z]+$)') {
        $warns += ("发现异常代理设置: " + $proxy.ProxyServer + " (病毒可经代理拦截杀软更新; 点系统修复(/repair)可清除)")
      } else {
        $infos += ("代理设置: " + $proxy.ProxyServer + " (非异常模式)")
      }
    }
    $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 } | ForEach-Object { $_.ServerAddresses -join ',' })
    # v1.91: 常见公共 DNS 白名单(合法正常); 仅"非白名单且非内网"才疑劫持
    $dnsWhite = '(?i)^(114\.114\.114\.114|114\.114\.115\.115|223\.5\.5\.5|223\.6\.6\.6|8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1|119\.29\.29\.29|180\.76\.76\.76|101\.226\.4\.6|9\.9\.9\.9|208\.67\.222\.222|208\.67\.220\.220|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)$'
    $dnsOk = @(); $dnsSusp = @()
    foreach ($d in $dns) {
      foreach ($ip in ($d -split ',')) {
        $ip = $ip.Trim()
        if ($ip -match $dnsWhite) { $dnsOk += $ip } else { $dnsSusp += $ip }
      }
    }
    if ($dnsSusp.Count -gt 0) {
      $warns += ("DNS 存在非常见服务器(可能被劫持): " + ($dnsSusp -join ' | ') + " (常见公共DNS如114/223.5.5.5/119.29.29.29属正常; 点系统修复可检查)")
    } else {
      $infos += ("DNS: " + ($dnsOk -join ' | ') + " (常见公共/内网DNS, 正常)")
    }
  } catch { $warns += ("代理/DNS 检查异常: " + $_.Exception.Message) }

  # ---- 14) 系统防火墙状态 (病毒常用手段: 关闭防火墙放行外联) ----
  try { Write-ScanProgress "[restoreav] 13/16 检查防火墙..." } catch {}
  try {
    $fwOut = @(netsh advfirewall show allprofiles state 2>$null)
    $off = @()
    $cur = $null
    foreach ($fl in $fwOut) {
      if ($fl -match 'Profile Settings|settings') { $cur = $fl.Trim() }
      if ($fl -match 'State\s*:\s*(ON|OFF)') {
        $st = $Matches[1]
        if ($cur -match 'Domain') { $dn = '域'; } elseif ($cur -match 'Private') { $dn = '专用'; } elseif ($cur -match 'Public') { $dn = '公用'; } else { $dn = '' }
        if ($st -eq 'OFF') { $off += ($dn + ' 配置') }
      }
    }
    if ($off.Count -gt 0) {
      if ($isAdmin) {
        # v1.77: 黑窗口黑屏时 Read-Host 为交互盲区(用户看不见提示会卡住) -> 自动开启+警告记录
        Write-Host ("  [发现] 防火墙被关闭: " + ($off -join '、') + " -- 已自动开启(恢复杀毒软件语境下视为病毒破坏)") -ForegroundColor Yellow
        $null = netsh advfirewall set allprofiles state on 2>$null
        $fixed += ("防火墙已恢复开启 (曾关闭: " + ($off -join '、') + "); 如非本意可另行关闭")
      } else {
        $warns += ("防火墙被关闭 (" + ($off -join '、') + "), 需管理员恢复")
      }
    } else {
      $infos += "防火墙状态正常 (全部开启)"
    }
  } catch { $warns += ("防火墙检查异常: " + $_.Exception.Message) }

  # ---- 15) Defender 引擎状态 (模块可用时) ----
  try { Write-ScanProgress "[restoreav] 14/16 检查 Defender 引擎..." } catch {}
  try {
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
      $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
      if ($mp) {
        $rtOn = $mp.RealtimeProtectionEnabled
        $avOn = $mp.AntivirusEnabled
        if (-not $rtOn -or -not $avOn) {
          if ($script:thirdAV) {
            $infos += ("Defender 防护未启 (第三方接管, 正常; 实时=" + $rtOn + ")")
          } elseif ($isAdmin) {
            try { Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableOnAccessProtection $false -ErrorAction Stop } catch {}
            try { Start-Service -Name WinDefend -ErrorAction SilentlyContinue } catch {}
            $fixed += ("Defender 实时保护已恢复 (引擎状态: 实时=" + $rtOn + " 防病毒=" + $avOn + ")")
          } else {
            $warns += ("Defender 防护未启 (实时=" + $rtOn + " 防病毒=" + $avOn + "), 需管理员恢复")
          }
        } else {
          $infos += ("Defender 引擎状态正常 (实时=开 防病毒=开, 杀毒引擎版本=" + $mp.AMServiceEnabled + ")")
        }
      }
    } else {
      $infos += "Defender 模块不可用(可能被移除或系统精简)"
    }
  } catch { $warns += ("Defender 状态检查异常: " + $_.Exception.Message) }

  # ---- 16) IFEO 进程劫持检测 (病毒给杀软 exe 加 Debugger 值让其启动即失败) ----
  try { Write-ScanProgress "[restoreav] 15/16 检查 IFEO 劫持..." } catch {}
  try {
    $ifeoKey = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options'
    $ifeoAvPat = '(?i)(360|huorong|hips|antivirus|defender|msmpeng|kaspersky|avp|avast|avg|rising|raqwatcher|qqpc|tencent|mcafee|norton|symantec|safedog)'
    if (Test-Path -LiteralPath $ifeoKey) {
      $subs = Get-ChildItem -LiteralPath $ifeoKey -ErrorAction SilentlyContinue
      foreach ($sub in $subs) {
        if ($sub.PSChildName -match $ifeoAvPat) {
          $dbg = Get-ItemProperty -Path $sub.PSPath -Name Debugger -ErrorAction SilentlyContinue
          if ($dbg -and $dbg.Debugger) {
            if ($isAdmin) {
              Remove-ItemProperty -Path $sub.PSPath -Name Debugger -Force -ErrorAction SilentlyContinue
              $fixed += ("IFEO 劫持已清除: " + $sub.PSChildName + " (Debugger=" + $dbg.Debugger + ")")
            } else {
              $warns += ("发现 IFEO 劫持: " + $sub.PSChildName + " (Debugger=" + $dbg.Debugger + "), 需管理员清除")
            }
          }
        }
      }
    }
  } catch { $warns += ("IFEO 检查异常: " + $_.Exception.Message) }

  # ---- 8) Defender 默认恢复 (MpCmdRun) ----
  try { Write-ScanProgress "[restoreav] 16/16 恢复 Defender 默认设置..." } catch {}
  $mpCands = @(
    "$env:ProgramFiles\Windows Defender\MpCmdRun.exe",
    "$env:ProgramData\Microsoft\Windows Defender\Platform\" + (Get-ChildItem "$env:ProgramData\Microsoft\Windows Defender\Platform" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty Name) + "\MpCmdRun.exe"
  )
  if ($isAdmin) {
    foreach ($mp in $mpCands) {
      if ($mp -and (Test-Path -LiteralPath $mp)) {
        try { $null = & $mp -RestoreDefaults 2>&1; $fixed += "Defender 已恢复默认设置"; break }
        catch { $warns += ("MpCmdRun 恢复失败: " + $_.Exception.Message) }
      }
    }
  }

  # ---- v1.75: 修复后复查对比 ----
  try {
    $postChecks = @()
    $diff = @()
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
      $mp1 = Get-MpComputerStatus -ErrorAction SilentlyContinue
      if ($mp1) {
        $postChecks += ("Defender实时防护: " + $(if ($mp1.RealtimeProtectionEnabled) {'已开启'} else {'仍关闭'}))
        if ($preSnapshot['Defender实时'] -eq $false -and $mp1.RealtimeProtectionEnabled) { $diff += "Defender 实时防护" }
      }
    }
    $fwText2 = (netsh advfirewall show allprofiles state 2>$null) -join "`n"
    $fwOff2 = ($fwText2 -match 'State\s*:\s*OFF')
    $postChecks += ("防火墙: " + $(if ($fwOff2) {'仍有配置关闭'} else {'全部开启'}))
    if ($preSnapshot['防火墙'] -and -not $fwOff2) { $diff += "防火墙" }
    $svc1 = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    $postChecks += ("WinDefend服务: " + $(if ($svc1) { $svc1.Status } else {'缺失'}))
    if ($svc1 -and $svc1.Status -eq 'Running' -and $preSnapshot['WinDefend服务'] -ne 'Running') { $diff += "WinDefend 服务" }
    $postPol = 0
    foreach ($k in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender','HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection')) {
      if (Test-Path -LiteralPath $k) {
        foreach ($v in @('DisableRealtimeMonitoring','DisableBehaviorMonitoring','DisableAntiSpyware','DisableOnAccessProtection')) {
          if ((Get-ItemProperty -Path $k -Name $v -ErrorAction SilentlyContinue).$v -gt 0) { $postPol++ }
        }
      }
    }
    $postChecks += ("策略禁用项: " + $postPol + " 个 (修复前 " + $preSnapshot['策略禁用项'] + " 个)")
    if ($preSnapshot['策略禁用项'] -gt 0 -and $postPol -eq 0) { $diff += "Defender 策略禁用项" }
    Write-Host ""
    Write-Host "  ===== 修复前后对比 =====" -ForegroundColor Cyan
    foreach ($c in $postChecks) { Write-Host ("  " + $c) -ForegroundColor Gray }
    if ($diff.Count -gt 0) {
      Write-Host ("  [已验证修复] " + ($diff -join ' / ')) -ForegroundColor Green
      Add-Report ("  [已验证修复] " + ($diff -join ' / '))
    } else {
      Write-Host "  本次未观察到可自动修复项的改善 (可能已健康或需重启/手动操作)" -ForegroundColor Yellow
      Add-Report "  [验证] 未观察到自动修复项改善 (部分修复需重启或管理员手动操作)"
    }
  } catch { $warns += ("复查对比异常: " + $_.Exception.Message) }

  # ---- 17) 证书信任链检查 (v1.84) ----
  try { Write-ScanProgress "[restoreav] 17/17 证书信任链检查..." } catch {}
  Invoke-CertCheck

  # ---- 汇总 ----
  Write-Host ""
  Write-Host ("  [结果] 修复 " + $fixed.Count + " 项, 警告 " + $warns.Count + " 项, 信息 " + $infos.Count + " 项") -ForegroundColor Green
  Add-Report ("  [结果] 修复 " + $fixed.Count + " 项:")
  foreach ($x in $fixed) { Add-Report ("    + " + $x) }
  if ($warns.Count -gt 0) { Add-Report "  [警告]"; foreach ($x in $warns) { Add-Report ("    ! " + $x) } }
  if ($infos.Count -gt 0) { Add-Report "  [信息]"; foreach ($x in $infos) { Add-Report ("    - " + $x) } }
  if ($fixed.Count -eq 0 -and $warns.Count -eq 0 -and $infos.Count -eq 0) { Add-Report "  [结果] 未发现安全软件被破坏的迹象" }
  Write-ScanProgress ("[restoreav] 修复 " + $fixed.Count + " 项, 警告 " + $warns.Count + " 项")
  Write-Host "  提示: 如使用第三方杀软(360/火绒/卡巴等)被禁用, 恢复服务后请在其主界面手动开启防护" -ForegroundColor Gray
  # v1.78: 黑窗口黑屏时用户看不到结果, 自动打开报告
  try { Write-ScanProgress ("[完成] 报告已生成: " + $log + " (自动弹出记事本)") } catch {}
try { Start-Process notepad $log } catch {}
}

# ===================== 免疫 / 修复 / 追踪 模式分支 =====================
if ($Immune -or $Repair -or $Trace -or $RestoreAV) {
  Write-AuditLog -Type 'MODE' -Msg ('进入 免疫=' + $Immune + ' 修复=' + $Repair + ' 追踪=' + $Trace + ' 重建基线=' + $Rebuild)
  if ($Immune) { Invoke-Immune -Rebuild $Rebuild }
  if ($Repair) { Invoke-Repair }
  if ($Trace)  { Invoke-Trace }
  if ($RestoreAV) { Invoke-RestoreAV }
  Exit-Tool -Code 0 -Reason ('免疫/修复/恢复杀软完成, 可疑 ' + $script:susp.Count + ' 项')
}
function Observe($s){ $script:observe += $s }
# v1.31 零信任模式: 判断文件是否属于工具自身(引擎/启动器/配置/运行产物)
# 零信任模式下工具目录也扫描, 但工具自身文件必须保护 - 只跳过不隔离, 绝不误杀
function Test-ToolSelfFile {
  param([string]$fp)
  if (-not $fp) { return $false }
  $r = $script:toolRoot.TrimEnd('\','/')
  if (-not $fp.StartsWith($r + '\', [StringComparison]::OrdinalIgnoreCase)) { return $false }
  $rel = $fp.Substring($r.Length).TrimStart('\','/')
  $leaf = Split-Path $fp -Leaf
  # 1) bin 目录下的引擎/辅助脚本/配置/ioc/更新包
  if ($rel -match '(?i)^bin\\.*\.(ps1|txt|json)$') { return $true }
  # 2) 根目录启动器/辅助 bat
  if ($rel -match '(?i)^(银狐木马检测|回滚恢复|恢复隔离文件|清理缓存|清理隔离区|诊断)\.bat$') { return $true }
  # 3) 引擎运行产物: 报告/观察清单/隔离区/审计/缓存/运行标记/日志
  if ($leaf -match '^银狐特攻扫描报告_.*\.txt$') { return $true }
  if ($leaf -match '^进程观察清单_.*\.txt$')     { return $true }
  # 隔离区目录(相对路径前缀): 隔离区内的样本已隔离, 不再重复检出
  if ($rel -match '(?i)^银狐特攻隔离区_')       { return $true }
  if ($leaf -match '^sf_(debug\.log|hash_cache\.txt|purge_audit\.log|restore_debug\.log|running\.flag|run\.log|run\.pid)') { return $true }
  if ($leaf -match '^操作留痕\.log$') { return $true }   # v1.35 审计日志
  if ($leaf -match '^锁定清单\.txt$') { return $true }   # v1.38 锁定清单
  if ($leaf -match '^网络封锁清单\.txt$') { return $true }   # v1.39 网络封锁清单
  if ($leaf -match '^sf_exit_.*\.flag$')         { return $true }
  return $false
}
# v1.7: 隔离仅对"高危明确特征"调用; 默认 QuarantineMode=false 时不移动文件
function Quarantine($path, $reason, [switch]$Force){
  # v1.31: 工具自身文件绝不隔离 (零信任模式下也不会误杀工具)
  if (Test-ToolSelfFile $path) { return "工具自身文件,跳过" }
  if (-not $QuarantineMode -and -not $Force) { return "建议隔离" }
  # v1.38: 真正移动前解锁 (锁定状态下无法移动; 默认只报告模式保持锁定)
  Remove-ThreatLock $path
  try {
    if (-not (Test-Path -LiteralPath $qdir)) { New-Item -ItemType Directory -Path $qdir -Force | Out-Null }
    $leaf = Split-Path $path -Leaf
    $dest = Join-Path $qdir $leaf
    if (Test-Path -LiteralPath $dest) { $dest = Join-Path $qdir ($leaf + "_" + [guid]::NewGuid().ToString("N").Substring(0,6)) }
    # v1.40: Move-Item 必须 -ErrorAction Stop 并复核, 否则移动失败仍报"已隔离"(假成功)
    Move-Item -Path $path -Destination $dest -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $path) { throw "移动后原文件仍存在" }
    Add-Content -Path (Join-Path $qdir "隔离清单.txt") -Value ("$dest <= 原始路径: $path  [$reason]") -Encoding UTF8
    $script:qcount++
    # v1.35: 操作留痕 - 隔离成功
    Write-AuditLog -Type 'QUARANTINE' -Msg ('已隔离: ' + $path + ' -> ' + $dest + ' [' + $reason + ']')
    return "已隔离"
  } catch {
    # v1.41: 隔离失败后补回锁定 (文件仍在原位, 防止恶意程序自我修复)
    try { Add-ThreatLock $path $reason } catch {}
    # v1.35: 操作留痕 - 隔离失败
    Write-AuditLog -Type 'QUARANTINE' -Msg ('隔离失败: ' + $path + ' [' + $reason + '] ' + $_.Exception.Message)
    return "隔离失败: " + $_.Exception.Message
  }
}

function Invoke-InteractiveConfirm {
  # 想法 2: 扫描后交互确认 - 从 $susp 提取文件类可疑项, 逐项询问是否隔离
  $fileItems = @($script:susp | Where-Object { $_ -match '\[高危文件\]' })
  # v1.35: 操作留痕 - 交互确认开始
  Write-AuditLog -Type 'INTERACTIVE' -Msg ('交互确认开始, 文件类可疑项 ' + $fileItems.Count + ' 个')
  if ($fileItems.Count -eq 0) {
    Write-Host "" -ForegroundColor Gray
    Write-Host "  [交互] 无可隔离的文件类可疑项, 跳过。" -ForegroundColor Gray
    return 0
  }
  Write-Host ""
  Write-Host "============================================================" -ForegroundColor Yellow
  Write-Host ("  交互确认: " + $fileItems.Count + " 个文件类可疑项") -ForegroundColor Yellow
  try { Write-ScanProgress ("[交互] 检测到 " + $fileItems.Count + " 项文件类可疑! 请在控制台窗口按提示选择处理 (1隔离/2删除/3跳过)") } catch {}
  Write-Host "  处理方式: 先隔离到隔离区 (可恢复, 不直接删除)" -ForegroundColor Yellow
  Write-Host "============================================================" -ForegroundColor Yellow
  for ($i=0; $i -lt $fileItems.Count; $i++) {
    $item = $fileItems[$i]
    Write-Host ("  [" + ($i+1) + "] " + $item.Trim()) -ForegroundColor Gray
  }
  Write-Host ""
  Write-Host "  输入要隔离的序号 (支持: 单个 1 / 多个 1,3,5 / 范围 1-3 / all 全部 / 0 跳过)"
  try { Write-ScanProgress ("[交互] 请输入要处理的序号 (1/多个如1,3/范围/0跳过), 输入在控制台窗口") } catch {}
  $choice = Read-Host "  选择"
  $selected = @(Get-Selection -Choice $choice -Count $fileItems.Count)
  if ($selected.Count -eq 1 -and $selected[0] -eq -1) { Write-Host "  已跳过交互处理。"; return 0 }
  if ($selected.Count -eq 0) { Write-Host "  无有效选择, 跳过。"; return 0 }
  Write-Host "  输入要处理的序号 (支持: 单个 1 / 多个 1,3,5 / 范围 1-3 / all 全部 / 0 跳过)"
  $choice = Read-Host "  选择"
  $selected = @(Get-Selection -Choice $choice -Count $fileItems.Count)
  if ($selected.Count -eq 1 -and $selected[0] -eq -1) { Write-Host "  已跳过交互处理。"; return 0 }
  if ($selected.Count -eq 0) { Write-Host "  无有效选择, 跳过。"; return 0 }
  # v1.82: 其他可疑项展示 (自启动/计划任务/服务/命令行/WMI 等, 报告已记录; 展示+建议, 不自动修改)
  $otherSusp = @($script:susp | Where-Object { $_ -match '\[(待核实|高危)-(自启动|计划任务|服务|命令行|WMI)\]' })
  if ($otherSusp.Count -gt 0) {
    Write-Host ""
    Write-Host ("  [其他可疑项] " + $otherSusp.Count + " 项 (自启动/计划任务/服务/命令行/WMI 等):") -ForegroundColor Yellow
    $showN = [Math]::Min($otherSusp.Count, 20)
    for ($xi = 0; $xi -lt $showN; $xi++) {
      Write-Host ("    " + $otherSusp[$xi].Trim()) -ForegroundColor Gray
    }
    if ($otherSusp.Count -gt $showN) { Write-Host ("    ... 其余 " + ($otherSusp.Count - $showN) + " 项见报告") -ForegroundColor Gray }
    Write-Host "  处置说明: 以上项已记录到报告; 自启动/计划任务请核实后手动处理, 系统负责项可用[系统修复]" -ForegroundColor Cyan
    try { Write-ScanProgress ("[交互] 其他可疑项 " + $otherSusp.Count + " 项, 详见报告 (已展示 " + $showN + " 项)") } catch {}
  }

  # v1.81: 进程处置 —— 高危进程列表, 用户选择是否结束
  if ($script:threatProcs -and $script:threatProcs.Count -gt 0) {
    Write-Host ""
    Write-Host ("  [进程处置] 高危进程 " + $script:threatProcs.Count + " 个 (伪装系统进程等):") -ForegroundColor Yellow
    foreach ($tp in $script:threatProcs) {
      $tpi = Get-Process -Id $tp -ErrorAction SilentlyContinue
      if ($tpi) {
        Write-Host ("    -> " + $tpi.ProcessName + " (PID=" + $tp + ")  路径=" + $tpi.Path) -ForegroundColor Gray
      } else {
        Write-Host ("    -> PID=" + $tp + " (已退出)") -ForegroundColor Gray
      }
    }
    try { Write-ScanProgress ("[交互] 高危进程 " + $script:threatProcs.Count + " 个待确认, 请在控制台选择是否结束 (建议 y)") } catch {}
    $kp = Read-Host "  结束这些高危进程? (y=结束后重新隔离 / n=跳过)"
    if ($kp.Trim().ToLower() -eq 'y') {
      foreach ($tp in $script:threatProcs) {
        $tpi = Get-Process -Id $tp -ErrorAction SilentlyContinue
        if ($tpi) {
          try { Stop-Process -Id $tp -Force -ErrorAction Stop; Add-Report ("  [已结束进程] " + $tpi.ProcessName + " PID=" + $tp) } catch { Add-Report ("  [结束失败] " + $tpi.ProcessName + " PID=" + $tp + " (需管理员)") }
        }
      }
    } else {
      Write-Host "  已跳过进程处置。" -ForegroundColor Gray
    }
  }

  # v2.15.34: 专杀交互升级 —— 用户选择"隔离(可恢复) / 删除(先备份后物理删除) / 跳过"
  Write-Host ""
  Write-Host "  [专杀] 对选中的 " + $selected.Count + " 个可疑项执行: " -ForegroundColor Yellow
  Write-Host "    1 = 隔离 (移动到隔离区, 可恢复, 推荐)" -ForegroundColor Cyan
  Write-Host "    2 = 删除 (先备份到隔离区再物理删除, 不可恢复但留底)" -ForegroundColor Cyan
  Write-Host "    3 = 跳过 (本次不处理)" -ForegroundColor Cyan
  try { Write-ScanProgress "[交互] 选择处理方式: 1=隔离(推荐) 2=删除(先备份) 3=跳过 (输入在控制台窗口)" } catch {}
  $mode = Read-Host "  选择处理方式"
  if ($mode.Trim() -eq '3' -or $mode.Trim() -eq '' -or $mode.Trim() -notin @('1','2')) { Write-Host "  已跳过。"; return 0 }
  if ($mode.Trim() -eq '2') {
    Write-Host ""
    Write-Host "  [警告] 删除为物理删除, 将先备份到隔离区。确认? (y=是 / n=取消)" -ForegroundColor Red
    try { Write-ScanProgress "[交互] 物理删除需确认, 请在控制台窗口输入 y 确认或 n 取消" } catch {}
    $confirmD = Read-Host "  确认"
    if ($confirmD.Trim().ToLower() -ne 'y') { Write-Host "  已取消。"; return 0 }
  }
  $done = 0
  foreach ($idx in $selected) {
    $item = $fileItems[$idx]
    $path = ''
    if ($item -match '\[高危文件\]\[[^\]]*\]\s+(.+)$') { $path = ($Matches[1] -replace '\s*\[[^\]]*\]\s*$','').Trim() }   # v1.13/1.42: 剥离行尾 [状态]
    if (-not $path) { continue }
    if ($mode.Trim() -eq '1') {
      $qm = Quarantine $path "交互隔离" -Force
      if ($qm -ne '建议隔离' -and $qm -ne '已隔离') {
        Write-Host ("  [失败] " + $path + " : " + $qm) -ForegroundColor Red
        Write-AuditLog -Type 'INTERACTIVE' -Msg ('隔离失败: ' + $path + ' [' + $qm + ']')
        continue
      }
      $done++
      Write-Host ("  [已隔离] " + $path) -ForegroundColor Green
      Write-AuditLog -Type 'INTERACTIVE' -Msg ('已隔离: ' + $path)
    } elseif ($mode.Trim() -eq '2') {
      # 删除: 先备份到隔离区再 Remove-Item (防误删)
      $qm = Quarantine $path "删除前备份" -Force
      if ($qm -eq '建议隔离' -or $qm -eq '已隔离') {
        try {
          Remove-Item -LiteralPath $path -Force -ErrorAction Stop
          $done++
          Write-Host ("  [已删除] " + $path + " (备份于隔离区)") -ForegroundColor Green
          Write-AuditLog -Type 'INTERACTIVE' -Msg ('已删除: ' + $path + ' (先隔离备份)')
        } catch {
          Write-Host ("  [删除失败] " + $path + " : " + $_.Exception.Message) -ForegroundColor Red
          Write-AuditLog -Type 'INTERACTIVE' -Msg ('删除失败: ' + $path)
        }
      } else {
        Write-Host ("  [删除失败] 备份失败: " + $qm + ", 不执行删除(防误删)") -ForegroundColor Red
      }
    }
  }
  Write-Host ("  专杀处理完成: " + $done + " 个文件。")
  Write-AuditLog -Type 'INTERACTIVE' -Msg ('专杀交互结束, 共处理' + $done + ' 个文件')
  return $done
}


# ===================== 待办3: 自身保护 + 待办7: Ring0 删除/无伤清除 (v1.30) =====================
$script:RunMark = Join-Path $script:toolRoot 'sf_running.flag'

# ===================== v1.32 自身防篡改 =====================
# 完整性清单 integrity.manifest: 相对路径|SHA256, 末行 signed=<YYYY-MM-DD> 与 sig=<sha256(全部条目+signed行+salt)前16hex>
# 校验: manifest 签名有效(防清单本身被改, 含日期) + 签名日期语义校验(防未来/篡改) + 逐文件哈希比对(防工具文件被替换)
# v1.55: signed 日期纳入签名载荷, 改日期即导致签名失效; 校验时另做日期合法性检查
$script:IntegritySalt = 'SilverFoxDetector-INTEGRITY-SALT-v1-!@#$%^&*2026'
function Test-Integrity {
  $mf = Join-Path $script:toolRoot 'integrity.manifest'
  if (-not (Test-Path -LiteralPath $mf)) {
    Write-Host ("  [INTEGRITY] " + (T 'INTEG_MISSING')) -ForegroundColor Yellow
    Add-Report ("  [INTEGRITY] " + (T 'INTEG_REPORT_MISS'))
    return
  }
  try {
    $lines = @(Get-Content $mf -Encoding UTF8)
    $sigLine = $lines | Where-Object { $_ -match '^sig=' } | Select-Object -First 1
    $signedLine = $lines | Where-Object { $_ -match '^signed=' } | Select-Object -First 1
    $entries = @($lines | Where-Object { $_ -match '^[^\s|]+\|[0-9a-fA-F]{64}$' })
    if (-not $sigLine -or $entries.Count -eq 0) {
      Write-Host ("  [INTEGRITY] " + (T 'INTEG_FMT_BAD')) -ForegroundColor Yellow
      return
    }
    # v1.55: 验签载荷 = 条目行 + 签名日期行 + salt (日期纳入签名, 改日期即失效)
    # v1.55: signed payload = entry lines + signed-date line + salt (date is signed)
    $payload = ($entries -join "`n") + "`n" + $signedLine + $script:IntegritySalt
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $h = ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payload))) -replace '-', '').ToLower()
    $expect = (($sigLine -replace '^sig=', '').Trim()).ToLower()
    if (-not $h.StartsWith($expect)) {
      Write-Host ("  [INTEGRITY] " + (T 'INTEG_SIG_INVALID')) -ForegroundColor Red
      Add-Report ("  [INTEGRITY] " + (T 'INTEG_REPORT_SIG'))
      return
    }
    # v1.55: 签名日期语义校验 (防未来日期/时钟篡改; 改日期会使上面签名失败)
    # v1.55: signed-date semantic check (rejects future dates / clock tampering)
    $signDateStr = '?'
    if ($signedLine -match '^signed=(\d{4}-\d{2}-\d{2})$') {
      $signDateStr = $Matches[1]; $d = $Matches[1]
      try {
        $sd = [datetime]::ParseExact($d, 'yyyy-MM-dd', $null)
        if ($sd -gt (Get-Date).AddDays(2)) {
          Write-Host (("  [INTEGRITY] " + ((T 'INTEG_DATE_FUTURE') -f $d))) -ForegroundColor Yellow
        }
      } catch {
        Write-Host (("  [INTEGRITY] " + ((T 'INTEG_DATE_BAD') -f $d))) -ForegroundColor Yellow
      }
    }
    # 逐文件校验
    $bad = @()
    foreach ($e in $entries) {
      $rel, $want = $e -split '\|', 2
      $fp = Join-Path $script:toolRoot ($rel -replace '/', [IO.Path]::DirectorySeparatorChar)
      if (-not (Test-Path -LiteralPath $fp)) { $bad += ($rel + " (file missing)"); continue }
      $h2 = ([System.BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($fp))) -replace '-', '').ToLower()
      if ($h2 -ne $want.ToLower()) { $bad += $rel }
    }
    if ($bad.Count -gt 0) {
      Write-Host ("  [INTEGRITY] " + (T 'INTEG_TAMPERED')) -ForegroundColor Red
      foreach ($b in $bad) { Write-Host ("    - " + $b) -ForegroundColor Red }
      Add-Report ("  [INTEGRITY] " + (T 'INTEG_REPORT_TAMPER') + ($bad -join ', '))
    } else {
      Write-Host (("  [INTEGRITY] " + ((T 'INTEG_PASS') -f $entries.Count, $signDateStr))) -ForegroundColor Green
      Add-Report (("  [INTEGRITY] " + ((T 'INTEG_PASS') -f $entries.Count, $signDateStr)))
    }
  } catch {
    Write-Host (("  [INTEGRITY] " + (T 'INTEG_EXC')) + $_.Exception.Message) -ForegroundColor Yellow
  }
}

function Initialize-SelfProtect {
  # v1.32 单实例互斥锁: 独占打开运行标记文件 (FileShare.None)
  #   - 打开成功 = 无其他实例; 失败 = 已有实例在运行 -> 拒绝启动(防报告互相污染)
  #   - 正常退出: Exit-Tool 关闭句柄+删标记; 异常退出: 句柄随进程释放, 标记残留 -> 下次提示
  try {
    $script:RunLockFS = [IO.File]::Open($script:RunMark, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    # 读残留内容 (异常退出留下的)
    $prev = ""
    try {
      $script:RunLockFS.Position = 0
      $plen = $script:RunLockFS.Length
      if ($plen -gt 0) {
        $pbuf = New-Object byte[] $plen
        [void]$script:RunLockFS.Read($pbuf, 0, $plen)
        $prev = [Text.Encoding]::UTF8.GetString($pbuf)
      }
    } catch {}
    # 写入本实例标记
    try {
      $info = "PID=" + $PID + " 开始=" + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
      $ib = [Text.Encoding]::UTF8.GetBytes($info)
      $script:RunLockFS.SetLength(0)
      $script:RunLockFS.Position = 0
      $script:RunLockFS.Write($ib, 0, $ib.Length)
      $script:RunLockFS.Flush()
    } catch {}
    # 1) 上次运行检查: 有残留内容说明上次未正常退出(Exit-Tool 会删除标记)
    if ($prev -and $prev.Trim()) {
      Write-Host ""
      Write-Host "  [自保护] 上次运行未正常退出, 可能被恶意终止!" -ForegroundColor Yellow
      Write-Host ("  上次运行标记: " + $prev.Trim()) -ForegroundColor Yellow
    # 尝试从安全事件日志找凶手 (4689 = 进程终止)
    try {
      $killer = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4689 } -MaxEvents 60 -ErrorAction Stop |
        Where-Object { $_.Message -match 'SilverFoxDetect' } | Select-Object -First 1
      if ($killer) {
        Write-Host ("  找到相关终止事件: " + $killer.TimeCreated) -ForegroundColor Yellow
        Add-Report ("  [自保护] 上次运行异常终止! 相关事件: " + $killer.TimeCreated)
      } else {
        Write-Host "  未找到明确终止事件(安全日志可能不可读)" -ForegroundColor Gray
        Add-Report "  [自保护] 上次运行异常终止!(安全日志不可读或无匹配事件)"
      }
    } catch { Write-Host "  无法读取安全事件日志(需管理员)" -ForegroundColor Gray }
    } else {
      Write-Host "  [自保护] 上次运行正常退出, 无残留标记" -ForegroundColor Gray
    }
  } catch [System.IO.IOException] {
    # 已有实例持有互斥锁
    $prev2 = ""
    try { if (Test-Path -LiteralPath $script:RunMark) { $prev2 = Get-Content $script:RunMark -Raw -ErrorAction SilentlyContinue } } catch {}
    Write-Host ""
    Write-Host "  [互斥锁] 已有检测实例正在运行, 为避免报告互相污染, 已拒绝启动!" -ForegroundColor Red
    if ($prev2) { Write-Host ("  运行中实例: " + $prev2.Trim()) -ForegroundColor Yellow }
    Write-Host "  请等待其结束后重试。" -ForegroundColor Yellow
    Exit-Tool -Code 2 -Reason '已有实例在运行(互斥锁)'
  } catch {
    # 权限等其他原因: 降级为无锁运行, 只提示
    Write-Host "  [互斥锁] 无法建立运行锁(权限受限?), 本次无锁运行, 请勿开多个实例" -ForegroundColor Yellow
    Add-Report "  [互斥锁] 警告: 无法建立运行锁, 请勿同时运行多个实例"
  }
  # 2) 防篡改完整性校验 (v1.32)
  Test-Integrity
  # 3) 防 Ctrl+C 误退: 捕获后留痕 + 提示 (无法可靠阻塞, 退出标记兜底判定)
  try {
    [Console]::CancelKeyPress.Add({
      try { Add-Content -Path $DebugLog -Value ("[自保护] 检测到 Ctrl+C") -Encoding UTF8 } catch {}
    }) | Out-Null
  } catch {}
  # 4) 进程级保护 (DACL + watchdog) 已在参数解析后由 Start-ProcessGuard 启用 (v1.44)
  $spNote = if ($script:SelfProtect) { " + 进程保护" } else { " (进程保护已关闭)" }
  Write-Host ("  [自保护] 已启用 (单实例锁 + 退出标记 + 上次运行检查" + $spNote + ")") -ForegroundColor Gray
}

# ---- 待办7: 无伤清除 + Ring0 删除 ----
function Get-RelatedProcesses {
  param([string]$Path)
  $procs = @()
  Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID } | ForEach-Object {
    $ep = ''
    try { $ep = (Get-CimInstance Win32_Process -Filter ("ProcessId=" + $_.Id) -ErrorAction SilentlyContinue).ExecutablePath } catch {}
    if ($ep -and $ep -ieq $Path) { $procs += $_ }
  }
  return $procs
}
function Remove-Persistence {
  param([string]$Path)
  $esc = [regex]::Escape($Path)
  # a) 注册表 Run 键
  foreach ($rk in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
                    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run')) {
    if (Test-Path -LiteralPath $rk) {
      Get-Item $rk -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property | ForEach-Object {
        $val = (Get-ItemProperty -Path $rk -Name $_ -ErrorAction SilentlyContinue).$_
        if ($val -and $val -match $esc) {
          Remove-ItemProperty -Path $rk -Name $_ -Force -ErrorAction SilentlyContinue
          Write-Host ("  [清持久化] 注册表 Run: " + $rk + "\" + $_) -ForegroundColor Yellow
          try { Add-Content -Path (Join-Path $script:toolRoot 'sf_purge_audit.log') -Value ("[清持久化 {0}] 注册表 {1}\{2} (关联: {3})" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $rk, $_, $Path) -Encoding UTF8 } catch {}
        }
      }
    }
  }
  # b) 计划任务
  try {
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
      Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.Actions -and ($_.Actions | Where-Object { $_.Execute -and $_.Execute -match $esc })
      } | ForEach-Object {
        Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host ("  [清持久化] 计划任务: " + $_.TaskName) -ForegroundColor Yellow
        try { Add-Content -Path (Join-Path $script:toolRoot 'sf_purge_audit.log') -Value ("[清持久化 {0}] 计划任务 {1} (关联: {2})" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $_.TaskName, $Path) -Encoding UTF8 } catch {}
      }
    } else {
      # v1.42: Win7 无 ScheduledTasks 模块, 回退 schtasks 按目标路径匹配删除
      $rows = @(schtasks /query /fo csv /nh 2>$null)
      foreach ($row in $rows) {
        if ($row -match $esc) {
          $tn = ($row -split ',')[0].Trim('"')
          if ($tn) {
            & schtasks /delete /tn "$tn" /f 2>$null
            Write-Host ("  [清持久化] 计划任务: " + $tn) -ForegroundColor Yellow
            try { Add-Content -Path (Join-Path $script:toolRoot 'sf_purge_audit.log') -Value ("[清持久化 {0}] 计划任务 {1} (关联: {2})" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $tn, $Path) -Encoding UTF8 } catch {}
          }
        }
      }
    }
  } catch {}
  # c) 服务
  try {
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -and $_.PathName -match $esc } | ForEach-Object {
      Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
      & sc.exe delete $_.Name | Out-Null
      Write-Host ("  [清持久化] 服务: " + $_.Name) -ForegroundColor Yellow
      try { Add-Content -Path (Join-Path $script:toolRoot 'sf_purge_audit.log') -Value ("[清持久化 {0}] 服务 {1} (关联: {2})" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $_.Name, $Path) -Encoding UTF8 } catch {}
    }
  } catch {}
}
function Remove-WithEscalation {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return "不存在" }
  # 路径1: 常规删除
  try { Remove-Item -LiteralPath $Path -Force -ErrorAction Stop; if (-not (Test-Path -LiteralPath $Path)) { return "已删除" } } catch {}
  # 路径2: takeown + icacls 提权 (需管理员)
  try {
    & takeown /f $Path /a 2>$null | Out-Null
    & icacls $Path /grant "*S-1-5-32-544:F" 2>$null | Out-Null
    Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $Path)) { return "提权删除(takeown+icacls)" }
  } catch {}
  # 路径3: SYSTEM 计划任务 (最高用户态权限)
  try {
    $taskName = "SFDel_" + [guid]::NewGuid().ToString("N").Substring(0, 8)
    # v1.40: 先展开环境变量再拼接, 防止 cmd 二次展开 %VAR% 误删其他文件
    $delPath = [Environment]::ExpandEnvironmentVariables($Path)
    if (-not (Test-Path -LiteralPath $delPath)) { $delPath = $Path }
    if ($delPath -match '[%]') { return "删除失败(路径含%不冒险)" }  # v1.41: 含未展开 % 直接跳过, 不回退原路径
    $act = New-ScheduledTaskAction -Execute "cmd.exe" -Argument ('/c del /f /q "' + $delPath + '"') -ErrorAction Stop
    Register-ScheduledTask -TaskName $taskName -Action $act -User "SYSTEM" -Force -ErrorAction Stop | Out-Null
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
    Start-Sleep -Seconds 2
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $Path)) { return "SYSTEM删除" }
  } catch {}
  return "删除失败(需 Ring0 内核级/PE环境/安全模式)"
}
function Invoke-Ring0Delete {
  # /ring0 模式下 $qdir 未定义 (主扫描流程才初始化), 兜底创建
  if (-not $script:qdir) {
    $script:qdir = Join-Path $script:toolRoot ("银狐特攻隔离区_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
  }
  $qdir = $script:qdir
  # 待办7: 无伤清除相关程序 + 提权删除
  Write-Host "============================================================" -ForegroundColor Yellow
  Write-Host "  Ring0 删除模式: 无伤清除 + 提权删除" -ForegroundColor Yellow
  Write-Host "  (先停进程/清持久化, 再按 常规->takeown->SYSTEM 逐级提权删除)" -ForegroundColor Yellow
  Write-Host "============================================================" -ForegroundColor Yellow
  # 收集目标: 命令行参数中的路径 (在 $args 里除了 /ring0 之外的非开关参数)
  $targets = @()
  foreach ($a in $script:PathArgs) {
    if ($a -match '^/[-a-zA-Z]+$') { continue }
    if (Test-Path -LiteralPath $a) { $targets += $a }
  }
  if ($targets.Count -eq 0) {
    # 从最新报告提取高危文件
    $latest = Get-ChildItem (Join-Path $script:toolRoot "银狐特攻扫描报告_*.txt") -ErrorAction SilentlyContinue |
      Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latest) {
      $targets = @(Get-Content $latest.FullName -ErrorAction SilentlyContinue |
        Where-Object { $_ -match '\[高危文件\]' } |
        ForEach-Object { if ($_ -match '\[高危文件\]\[[^\]]*\]\s+(.+)$') { ($Matches[1] -replace '\s*\[[^\]]*\]\s*$','').Trim() } } |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    }
  }
  if ($targets.Count -eq 0) {
    Write-Host ""
    Write-Host "  未找到待删除目标。" -ForegroundColor Gray
    Write-Host "  用法: 银狐木马检测.bat /ring0 <文件路径> [更多路径...]" -ForegroundColor Gray
    Write-Host "  或先运行检测生成报告, 再 /ring0 自动提取高危文件。" -ForegroundColor Gray
    return
  }
  Write-Host ("`n  待处理 " + $targets.Count + " 个文件:")
  for ($i=0; $i -lt $targets.Count; $i++) { Write-Host ("    [" + ($i+1) + "] " + $targets[$i]) -ForegroundColor Gray }
  Write-Host ""
  $confirm = Read-Host "  确认处理这些文件? (工具会先备份到隔离区, 再删除原文件; 备份可恢复。y=是 / n=取消)"
  if ($confirm.Trim().ToLower() -ne 'y') { Write-Host "  已取消。"; return }
  $okCount = 0; $failList = @()
  foreach ($t in $targets) {
    if (-not (Test-Path -LiteralPath $t)) { Write-Host ("  跳过(不存在): " + $t) -ForegroundColor Gray; continue }
    Write-Host ("`n[处理] " + $t) -ForegroundColor Cyan
    # 1) 无伤清除: 停相关进程 (仅目标程序, 不碰系统)
    try {
      $procs = @(Get-RelatedProcesses $t)
      foreach ($p in $procs) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        Write-Host ("  [停进程] PID " + $p.Id + " (" + $p.ProcessName + ")") -ForegroundColor Yellow
        try { Add-Content -Path (Join-Path $script:toolRoot 'sf_purge_audit.log') -Value ("[停进程 {0}] PID {1} ({2}) 关联: {3}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $p.Id, $p.ProcessName, $t) -Encoding UTF8 } catch {}
      }
    } catch {}
    # 2) 无伤清除: 清持久化 (注册表 Run / 计划任务 / 服务)
    Remove-Persistence $t
    # 3) 隔离备份 (可回滚)
    try {
      if (-not (Test-Path -LiteralPath $qdir)) { New-Item -ItemType Directory -Path $qdir -Force | Out-Null }
      Copy-Item -LiteralPath $t -Destination (Join-Path $qdir (Split-Path $t -Leaf)) -Force -ErrorAction Stop
      Write-Host "  [备份] 已复制到隔离区" -ForegroundColor Yellow
    } catch {}
    # 4) 逐级提权删除
    $r = Remove-WithEscalation $t
    if ($r -notmatch '失败') { $okCount++ }   # v1.42: 只要不含'失败'即成功 (修 失败计成功)
    Write-Host ("  [删除] " + $r) -ForegroundColor $(if ($r -match '失败') { 'Red' } else { 'Green' })
    try { Add-Content -Path (Join-Path $script:toolRoot 'sf_purge_audit.log') -Value ("[Ring0删除 {0}] {1} -> {2} 操作者: {3}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $t, $r, $env:USERNAME) -Encoding UTF8 } catch {}
  }
  Write-Host ("`n  处理完成: 成功 " + $okCount + " / 共 " + $targets.Count) -ForegroundColor Cyan
  Write-Host ("  审计日志: " + (Join-Path $script:toolRoot 'sf_purge_audit.log'))
}

# ===================== v1.36: 驱动审计 (想法6 - 过期签名/BYOVD 脆弱驱动检测) =====================
# 已知脆弱驱动种子库 (文件名小写匹配; 参考 loldrivers.io 知名 BYOVD 驱动)
# 仅作参考标记, 命中不代表已被利用, 提示人工核实 (只记录不删除)
$script:VulnDrivers = @(
  @{ Name='rtcore64.sys';      Desc='MSI Afterburner 旧版驱动 (CVE-2019-16098)' },
  @{ Name='rtcore32.sys';      Desc='MSI Afterburner 旧版驱动 (CVE-2019-16098)' },
  @{ Name='gdrv.sys';          Desc='Gigabyte 旧版驱动 (CVE-2018-19320)' },
  @{ Name='dbutil_2_3.sys';    Desc='Dell DBUTIL (CVE-2021-21551)' },
  @{ Name='dbutil.sys';        Desc='Dell DBUTIL 系列' },
  @{ Name='ene.sys';           Desc='ENE Technology (CVE-2021-31783)' },
  @{ Name='ene_amd64.sys';     Desc='ENE Technology AMD64 (CVE-2021-31783)' },
  @{ Name='eneio64.sys';       Desc='ENE Technology I/O (CVE-2021-31783)' },
  @{ Name='capcom.sys';        Desc='Capcom 驱动 (提权滥用, 著名 rootkit 载体)' },
  @{ Name='procexp152.sys';    Desc='Sysinternals Process Explorer 旧版 (PPL 绕过)' },
  @{ Name='procexp154.sys';    Desc='Sysinternals Process Explorer 旧版' },
  @{ Name='iqvw64e.sys';       Desc='Intel 旧版驱动 (CVE-2015-2291)' },
  @{ Name='asio.sys';          Desc='ASUS 旧版驱动 (CVE-2018-18537)' },
  @{ Name='asio2.sys';         Desc='ASUS 旧版驱动' },
  @{ Name='winio.sys';         Desc='WinIO 驱动 (提权滥用)' },
  @{ Name='winio64.sys';       Desc='WinIO 驱动 64位' },
  @{ Name='io64.sys';          Desc='IO 端口操作驱动' },
  @{ Name='naldrv.sys';        Desc='NalDrv (提权滥用)' },
  @{ Name='gmer64.sys';        Desc='GMER rootkit 工具驱动' },
  @{ Name='dgderdrv.sys';      Desc='华擎/技嘉工具驱动' },
  @{ Name='windbg.sys';        Desc='WinDbg 内核调试驱动' },
  @{ Name='dbk64.sys';         Desc='Cheat Engine 内核驱动 (反作弊绕过)' },
  @{ Name='sandbox.sys';       Desc='Sandboxie 驱动' }
)

function Invoke-DriverAudit {
  # 驱动签名审计: 枚举已加载驱动 + 数字签名状态 + 脆弱库比对 + (可选 DriverStore 深度)
  # v1.42: 独立模式分支在报告初始化前, 先兜底报告路径
  if (-not $log) {
    $stamp0 = Get-Date -Format 'yyyyMMdd_HHmmss'
    $log = Join-Path $script:toolRoot ("银狐特攻扫描报告_" + $stamp0 + ".txt")
    try { Set-Content -Path $log -Value ("银狐木马检测报告 (" + (Get-Date) + ")") -Encoding UTF8 } catch { $log = $null }
  }
  Write-Host "`n[驱动审计] 开始检测过期/脆弱驱动 (BYOVD 风险)..." -ForegroundColor Cyan
  Write-AuditLog -Type 'DRIVER' -Msg '驱动审计开始'
  $findings = @()   # 问题驱动
  $total = 0
  $script:DriverFindings = @()   # 供交互删除使用

  # ---- 1) 已加载驱动 (服务方式) ----
  try {
    $drvServices = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' }
    foreach ($d in $drvServices) {
      $total++
      $svcName = $d.Name
      if (-not $d.PathName) { continue }   # v1.42: 空 PathName 判空
      $path = $d.PathName -replace '\\\\.\\', '' -replace '^system32\\', ($env:SystemRoot + '\system32\') -replace '^\\SystemRoot\\', ($env:SystemRoot + '\')
      $path = $path.Trim('"')
      $name = Split-Path $path -Leaf
      $sig = $null; $status = '未签名'; $signer = ''; $expired = $false; $notAfter = ''
      if (Test-Path -LiteralPath $path) {
        try {
          $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
          $status = switch ($sig.Status) {
            'Valid'        { '有效' }
            'Expired'      { '已过期' }
            'NotTrusted'   { '不受信任(可能吊销)' }
            'NotSigned'    { '未签名' }
            'HashMismatch' { '哈希不匹配(被篡改!)' }
            'UnknownError' { '验证错误' }
            default        { $sig.Status.ToString() }
          }
          if ($sig.SignerCertificate) {
            $signer = $sig.SignerCertificate.Subject -replace '^CN=', ''
            if ($signer -match '^([^,]+)') { $signer = $Matches[1] }
            if ($sig.SignerCertificate.NotAfter) {
              $notAfter = $sig.SignerCertificate.NotAfter.ToString('yyyy-MM-dd')
              if ($sig.SignerCertificate.NotAfter -lt (Get-Date)) { $expired = $true }
            }
          }
        } catch { $status = '无法验证' }
      } else { $status = '路径不存在' }
      # 脆弱库命中 (文件名匹配)
      $vulnHit = $null
      foreach ($v in $script:VulnDrivers) { if ($name.ToLower() -eq $v.Name) { $vulnHit = $v.Desc; break } }
      # 标记条件: 脆弱命中 / 过期 / 不受信任 / 哈希不匹配 / 未签名(仅加载状态)
      $isProblem = $false
      if ($vulnHit) { $isProblem = $true }
      elseif ($status -in @('已过期','不受信任(可能吊销)','哈希不匹配(被篡改!)')) { $isProblem = $true }
      elseif ($status -eq '未签名' -and $Full) { $isProblem = $true }  # 深度模式才报未签名
      if ($isProblem) {
        $finding = [PSCustomObject]@{
          Name=$name; Path=$path; Status=$status; Signer=$signer; NotAfter=$notAfter
          Vuln=$vulnHit; SHA=''; Loaded=$true; Service=$svcName
        }
        $findings += $finding
        $script:DriverFindings += $finding
        # v1.38: 检测出先锁定驱动文件 (防恶意程序篡改/恢复)
        if ($path -and (Test-Path -LiteralPath $path)) { Add-ThreatLock $path ('问题驱动: ' + $name) }
        $line = "[驱动] $name  状态=$status  签发者=$signer  过期时间=$notAfter  路径=$path"
        if ($vulnHit) { $line += "  [脆弱库命中: $vulnHit]" }
        Add-Report $line
        $script:observe += ($line + '  [已加载]')
        Write-AuditLog -Type 'DRIVER' -Msg ('已加载驱动问题: ' + $name + ' 状态=' + $status + ' 签发者=' + $signer + ' 过期=' + $notAfter + ($(if($vulnHit){' [脆弱库:' + $vulnHit + ']'}else{''})) + ' 路径=' + $path)
      }
    }
  } catch {
    try { Add-Content -Path $DebugLog -Value ("[驱动审计] 已加载驱动枚举失败(需管理员): " + $_.Exception.Message) -Encoding UTF8 } catch {}
    Write-Host "  [提示] 已加载驱动枚举失败, 可能非管理员权限 (Win32_SystemDriver 需要权限)" -ForegroundColor Yellow
  }

  # ---- 2) DriverStore 深度扫描 (/full) ----
  if ($Full) {
    Write-Host "  [深度] 扫描 DriverStore 驱动仓库 (较慢)..." -ForegroundColor Gray
    $storeDir = Join-Path $env:SystemRoot 'System32\DriverStore\FileRepository'
    if (Test-Path -LiteralPath $storeDir) {
      $sysFiles = Get-ChildItem $storeDir -Filter *.sys -Recurse -ErrorAction SilentlyContinue
      foreach ($f in $sysFiles) {
        $total++
        $name = $f.Name
        # 脆弱库命中
        $vulnHit = $null
        foreach ($v in $script:VulnDrivers) { if ($name.ToLower() -eq $v.Name) { $vulnHit = $v.Desc; break } }
        if (-not $vulnHit) { continue }  # 深度模式只报脆弱库命中 + 签名问题驱动
        $sha = ''
        try { $sha = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch {}
        $finding = [PSCustomObject]@{ Name=$name; Path=$f.FullName; Status=''; Signer=''; NotAfter=''; Vuln=$vulnHit; SHA=$sha; Loaded=$false; Service='' }
        $findings += $finding
        $script:DriverFindings += $finding
        $line = "[驱动] $name  状态=脆弱库命中  路径=$f.FullName  SHA256=$sha"
        Add-Report $line
        $script:observe += ($line + '  [DriverStore, 未加载]')
        Write-AuditLog -Type 'DRIVER' -Msg ('DriverStore 脆弱驱动: ' + $name + ' [脆弱库: ' + $vulnHit + '] 路径=' + $f.FullName)
      }
    }
  }

  # ---- 汇总 ----
  Write-Host ("`n[驱动审计] 检查驱动 " + $total + " 个, 发现问题 " + $findings.Count + " 个") -ForegroundColor Cyan
  if ($findings.Count -eq 0) {
    Add-Report ("[驱动审计] 检查 " + $total + " 个驱动, 未发现过期/脆弱驱动 (BYOVD 风险)")
  } else {
    Add-Report ("[驱动审计] 检查 " + $total + " 个驱动, 发现问题 " + $findings.Count + " 个:")
    Add-Report "  - 脆弱库命中: 该驱动常被恶意程序加载提权/关杀软, 请核实是否必要, 必要时禁用或升级"
    Add-Report "  - 签名过期/不受信任: 驱动签名证书已过期或被吊销, 建议更新到厂商新版本"
    Add-Report "  - 哈希不匹配: 驱动文件被篡改, 高度可疑!"
    Add-Report "  - 处置: 以上仅记录不删除 (驱动删除有系统风险), 请用驱动管理器核实"
  }
  # v1.81: 驱动签名信任检查 —— 银狐自签恶意驱动不满足微软/主流厂商签名
  try {
    $drvSvc = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' }
    $drvChecked = 0; $drvUnsigned = 0
    foreach ($d in $drvSvc) {
      try {
        $dp = Get-ExecPath $d.PathName
        if (-not $dp -or -not (Test-Path -LiteralPath $dp)) { continue }
        if ((Get-Item -LiteralPath $dp).Length -gt 52428800) { continue }
        $drvChecked++
        $sig = Get-AuthenticodeSignature -FilePath $dp -ErrorAction SilentlyContinue
        if (-not $sig -or $sig.Status -ne 'Valid') {
          $drvUnsigned++
          Add-Report ("  [观察-未签名驱动] " + $d.Name + " -> " + $dp)
        }
      } catch {}
    }
    if ($drvUnsigned -gt 0) { Add-Report ("  [驱动签名] 运行中驱动 " + $drvChecked + " 个, 未签名 " + $drvUnsigned + " 个(观察, 请核对)") }
  } catch { Add-Report ("  [驱动签名] 检查异常: " + $_.Exception.Message) }

  Write-AuditLog -Type 'DRIVER' -Msg ('驱动审计完成: 检查 ' + $total + ' 个, 发现问题 ' + $findings.Count + ' 个')
  return $findings.Count
}

function Invoke-DriverInteractiveDelete {
  # v1.37: 驱动审计后手动选择删除 (Ring0 提权: 停服务 -> 备份 -> 逐级提权删文件)
  # /drivers 模式下 $qdir 未定义 (主扫描流程才初始化), 这里兜底
  if (-not $script:qdir) {
    $script:qdir = Join-Path $script:toolRoot ("银狐特攻隔离区_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
  }
  $qdir = $script:qdir
  if ($script:DriverFindings.Count -eq 0) { return }
  Write-Host ""
  Write-Host "============================================================" -ForegroundColor Yellow
  Write-Host ("  驱动交互删除: " + $script:DriverFindings.Count + " 个问题驱动可供处理") -ForegroundColor Yellow
  Write-Host "  处理方式: 停服务 -> 备份到隔离区 -> Ring0 提权删除文件" -ForegroundColor Yellow
  Write-Host "  (DriverStore 条目建议用 pnputil 卸载, 不自动删除)" -ForegroundColor Yellow
  Write-Host "============================================================" -ForegroundColor Yellow
  for ($i=0; $i -lt $script:DriverFindings.Count; $i++) {
    $f = $script:DriverFindings[$i]
    $tag = if ($f.Loaded) { '已加载' } else { 'DriverStore' }
    $info = ("  [" + ($i+1) + "] " + $f.Name + "  [" + $tag + "] 状态=" + $f.Status)
    if ($f.Vuln) { $info += "  [脆弱库: " + $f.Vuln + "]" }
    Write-Host $info -ForegroundColor Gray
    Write-Host ("        " + $f.Path) -ForegroundColor DarkGray
  }
  Write-Host ""
  Write-Host "  输入要删除的序号 (单个 1 / 多个 1,3,5 / 范围 1-3 / all 全部 / 0 跳过)"
  $choice = Read-Host "  选择"
  $selected = @(Get-Selection -Choice $choice -Count $script:DriverFindings.Count)
  if ($selected.Count -eq 1 -and $selected[0] -eq -1) { Write-Host "  已跳过驱动删除。"; return }
  if ($selected.Count -eq 0) { Write-Host "  无有效选择, 跳过。"; return }
  Write-Host ("`n  将处理 " + $selected.Count + " 个驱动:")
  foreach ($idx in $selected) {
    $f = $script:DriverFindings[$idx]
    Write-Host ("    - " + $f.Name + "  " + $f.Path) -ForegroundColor Gray
  }
  try { Write-ScanProgress "[交互] 驱动删除需确认, 请在控制台窗口输入 DELETE 继续" } catch {}
  $confirm = Read-Host "`n  确认删除这些驱动文件? (危险操作!) 输入 y 确认删除 (其他任意键取消)"
  if ($confirm.Trim().ToLower() -ne 'y') { Write-Host "  已取消。"; return }

  $ok = 0; $fail = 0
  foreach ($idx in $selected) {
    $f = $script:DriverFindings[$idx]
    Write-Host ("`n  [处理] " + $f.Name) -ForegroundColor Cyan
    # 1) DriverStore 条目: 不自动删, 提示 pnputil
    if (-not $f.Loaded) {
      Write-Host "  [跳过] DriverStore 条目建议用 pnputil /delete-driver 卸载 (管理员), 不自动删除" -ForegroundColor Yellow
      Write-AuditLog -Type 'DRIVER' -Msg ('跳过 DriverStore 驱动删除(提示 pnputil): ' + $f.Name + ' 路径=' + $f.Path)
      continue
    }
    # 2) 停服务 + 删服务注册
    if ($f.Service) {
      try {
        & sc.exe stop $f.Service | Out-Null
        Start-Sleep -Milliseconds 500
        & sc.exe delete $f.Service | Out-Null
        Write-Host "  [服务] 已停止并删除服务: $($f.Service)" -ForegroundColor Green
      } catch {
        Write-Host "  [服务] 停止/删除服务失败: $($f.Service) (可能需管理员)" -ForegroundColor Red
      }
    }
    # 3) 备份到隔离区 (可回滚)
    $backupOk = $false
    try {
      if (-not (Test-Path -LiteralPath $qdir)) { New-Item -ItemType Directory -Path $qdir -Force | Out-Null }
      if (Test-Path -LiteralPath $f.Path) {
        Copy-Item -LiteralPath $f.Path -Destination (Join-Path $qdir (Split-Path $f.Path -Leaf)) -Force -ErrorAction Stop
        Add-Content -Path (Join-Path $qdir '隔离清单.txt') -Value ((Join-Path $qdir (Split-Path $f.Path -Leaf)) + " <= 原始路径: " + $f.Path + "  [驱动删除备份]") -Encoding UTF8
        $backupOk = $true
        Write-Host "  [备份] 已复制到隔离区" -ForegroundColor Green
      }
    } catch {
      Write-Host "  [备份] 失败: " + $_.Exception.Message -ForegroundColor Red
    }
    # 4) Ring0 提权删除文件 (删除前先解锁)
    Remove-ThreatLock $f.Path
    $r = Remove-WithEscalation $f.Path
    Write-Host ("  [删除] " + $r) -ForegroundColor $(if ($r -match '失败') { 'Red' } else { 'Green' })
    if ($r -notmatch '失败' -and $r -ne '不存在') {
      $ok++
      try { Add-Content -Path (Join-Path $script:toolRoot 'sf_purge_audit.log') -Value ("[驱动删除 {0}] {1} (服务={2}) -> {3} 操作者: {4}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $f.Name, $f.Service, $r, $env:USERNAME) -Encoding UTF8 } catch {}
      Write-AuditLog -Type 'DRIVER' -Msg ('驱动删除成功: ' + $f.Name + ' (' + $r + ') 路径=' + $f.Path + ' 服务=' + $f.Service)
    } else {
      $fail++
      Write-AuditLog -Type 'DRIVER' -Msg ('驱动删除失败: ' + $f.Name + ' 路径=' + $f.Path + ' 结果=' + $r)
    }
  }
  Write-Host ("`n  驱动处理完成: 成功 " + $ok + " / 失败 " + $fail)
  Write-AuditLog -Type 'DRIVER' -Msg ('驱动交互删除完成: 成功 ' + $ok + ' / 失败 ' + $fail)
}


# ===================== v1.42: 内存内容检测 (想法12) =====================
# 扫描可疑进程内存中的恶意特征 (C2 域名/IP / 反射加载 / 编码载荷),
# 以及注册表 Run 值内容 / 计划任务脚本本体的内容特征。
# P/Invoke: [已混淆] + VirtualQueryEx + ReadProcessMemory (PS5.1 可用 Add-Type)
$script:MemScanResults = @()

function Initialize-MemPInvoke {
  # 定义 P/Invoke; 失败(无编译器)返回 false, 调用方降级为仅内容检测
  try {
    if (-not ('MemScanNative' -as [type])) {
      Add-Type -TypeDefinition ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('dXNpbmcgU3lzdGVtOwp1c2luZyBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXM7CnB1YmxpYyBzdGF0aWMgY2xhc3MgTWVtU2Nhbk5hdGl2ZSB7CiAgW0RsbEltcG9ydCgia2VybmVsMzIuZGxsIiwgU2V0TGFzdEVycm9yPXRydWUpXQogIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIEludFB0ciBPcGVuUHJvY2Vzcyh1aW50IGR3RGVzaXJlZEFjY2VzcywgYm9vbCBiSW5oZXJpdEhhbmRsZSwgaW50IGR3UHJvY2Vzc0lkKTsKICBbRGxsSW1wb3J0KCJrZXJuZWwzMi5kbGwiKV0KICBwdWJsaWMgc3RhdGljIGV4dGVybiBib29sIENsb3NlSGFuZGxlKEludFB0ciBoT2JqZWN0KTsKICBbU3RydWN0TGF5b3V0KExheW91dEtpbmQuU2VxdWVudGlhbCldCiAgcHVibGljIHN0cnVjdCBNRU1PUllfQkFTSUNfSU5GT1JNQVRJT04gewogICAgcHVibGljIEludFB0ciBCYXNlQWRkcmVzczsgcHVibGljIEludFB0ciBBbGxvY2F0aW9uQmFzZTsKICAgIHB1YmxpYyB1aW50IEFsbG9jYXRpb25Qcm90ZWN0OyBwdWJsaWMgdXNob3J0IFBhcnRpdGlvbklkOyBwdWJsaWMgSW50UHRyIFJlZ2lvblNpemU7CiAgICBwdWJsaWMgdWludCBTdGF0ZTsgcHVibGljIHVpbnQgUHJvdGVjdDsgcHVibGljIHVpbnQgVHlwZTsKICB9CiAgW0RsbEltcG9ydCgia2VybmVsMzIuZGxsIiwgU2V0TGFzdEVycm9yPXRydWUpXQogIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIGludCBWaXJ0dWFsUXVlcnlFeChJbnRQdHIgaFByb2Nlc3MsIEludFB0ciBscEFkZHJlc3MsIG91dCBNRU1PUllfQkFTSUNfSU5GT1JNQVRJT04gbHBCdWZmZXIsIHVpbnQgZHdMZW5ndGgpOwogIFtEbGxJbXBvcnQoImtlcm5lbDMyLmRsbCIsIFNldExhc3RFcnJvcj10cnVlKV0KICBwdWJsaWMgc3RhdGljIGV4dGVybiBib29sIFJlYWRQcm9jZXNzTWVtb3J5KEludFB0ciBoUHJvY2VzcywgSW50UHRyIGxwQmFzZUFkZHJlc3MsIGJ5dGVbXSBscEJ1ZmZlciwgaW50IG5TaXplLCBvdXQgSW50UHRyIGxwTnVtYmVyT2ZCeXRlc1JlYWQpOwp9'))) -ErrorAction Stop
    }
    return $true
  } catch { return $false }
}

function Read-ProcMemory([int]$ProcId, [int]$MaxBytes) {
  # 读取进程可读提交内存, 拼成 Latin1 字符串 (1字节=1字符, 匹配不丢字节)
  # 单区域最多 1MB, 单进程最多 $MaxBytes, 15s 超时; 失败/无权限返回空串
  $out = New-Object System.Text.StringBuilder
  try {
    $h = [MemScanNative]::OpenProcess(0x0010 -bor 0x0400, $false, $ProcId)  # PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
    if ($h -eq [IntPtr]::Zero) { return $null }   # v1.42: $null=失败(无权限), ''=成功但无可读, 区分统计
    try {
      $mbi = New-Object MemScanNative+MEMORY_BASIC_INFORMATION
      $addr = [IntPtr]::Zero
      $total = 0
      $sw = [System.Diagnostics.Stopwatch]::StartNew()
      while ($total -lt $MaxBytes -and $sw.Elapsed.TotalSeconds -lt 15) {
        $ret = [MemScanNative]::VirtualQueryEx($h, $addr, [ref]$mbi, [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($mbi))
        if ($ret -eq 0) { break }
        $prot = $mbi.Protect -band 0xFF
        $readable = ($prot -band (0x02 -bor 0x04 -bor 0x08 -bor 0x10 -bor 0x20 -bor 0x40 -bor 0x80)) -ne 0   # 含 WRITECOPY/EXECUTE_WRITECOPY
        $committed = ($mbi.State -band 0x1000) -ne 0
        $guard = ($mbi.Protect -band 0x100) -ne 0
        if ($committed -and $readable -and -not $guard) {
          $chunk = [int][Math]::Min([int64]$mbi.RegionSize, 1048576)
          $chunk = [Math]::Min($chunk, ($MaxBytes - $total))
          if ($chunk -gt 0) {
            $buf = New-Object byte[] $chunk
            $read = [IntPtr]::Zero
            if ([MemScanNative]::ReadProcessMemory($h, $mbi.BaseAddress, $buf, $chunk, [ref]$read)) {
              $n = [int]$read
              if ($n -gt 0) {
                [void]$out.Append([System.Text.Encoding]::GetEncoding(28591).GetString($buf, 0, $n))
                $total += $n
              }
            }
          }
        }
        try { $next = $mbi.BaseAddress.ToInt64() + [int64]$mbi.RegionSize; if ($next -le 0 -or $next -le $addr.ToInt64()) { break }; $addr = [IntPtr]$next } catch { break }
      }
    } finally { [MemScanNative]::CloseHandle($h) | Out-Null }
  } catch {}
  return $out.ToString()
}

function Invoke-MemScan {
  # 内存内容检测: 可疑进程内存 + 注册表 Run 内容 + 计划任务脚本本体
  # v1.42: 独立模式分支在报告初始化前, 先兜底报告路径
  if (-not $log) {
    $stamp0 = Get-Date -Format 'yyyyMMdd_HHmmss'
    $log = Join-Path $script:toolRoot ("银狐特攻扫描报告_" + $stamp0 + ".txt")
    try { Set-Content -Path $log -Value ("银狐木马检测报告 (" + (Get-Date) + ")") -Encoding UTF8 } catch { $log = $null }
  }
  Write-Host "`n[内存检测] 扫描进程内存中的恶意特征 (C2/反射加载/编码载荷)..." -ForegroundColor Cyan
  Write-AuditLog -Type 'MEM' -Msg '内存内容检测开始'
  $hasPInvoke = Initialize-MemPInvoke
  if (-not $hasPInvoke) {
    Write-Host "  [内存检测] P/Invoke 初始化失败(缺编译器?), 降级为命令行/注册表/任务脚本内容检测" -ForegroundColor Yellow
  }
  $memTotal = 0; $memHit = 0; $memNA = 0

  # ---- 特征表: C2 域名/IP + 固定恶意特征 ----
  $feat = @()
  foreach ($d in $c2Domains.Keys) { if ($d.Length -ge 4) { $feat += $d } }
  foreach ($ip in $c2IPs.Keys) { if ($ip.Length -ge 7) { $feat += $ip } }
  $feat += @('MODBEACON','ReflectiveLoader','msfvenom','DownloadString','FromBase64String','-enc ','SilverFox','beacon')   # v1.42: 去掉 'w hidden'(过宽)

  # ---- 1) 进程内存扫描 (候选: 非系统目录进程) ----
  if ($hasPInvoke) {
    $cands = @()
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
      if ($_.Id -eq $PID) { return }
      $pp = $_.Path
      if (-not $pp) { return }
      if (-not $pp.StartsWith($env:SystemRoot, [StringComparison]::OrdinalIgnoreCase)) { $cands += $_ }
    }
    # v1.42: 全局时间预算 60s + 候选上限 40 (防拖垮)
    $memSW = [System.Diagnostics.Stopwatch]::StartNew()
    if ($cands.Count -gt 40) { $cands = @($cands | Select-Object -First 40); Add-Report "  [内存-进程] 候选超过 40 个, 仅扫描前 40 个" }
    foreach ($p in $cands) {
      if ($memSW.Elapsed.TotalSeconds -gt 60) { Add-Report "  [内存-进程] 达到 60s 时间预算, 提前结束"; break }
      $memStr = Read-ProcMemory $p.Id 33554432   # v1.42: 单进程上限 32MB (x86 内存压力)
      if ($null -eq $memStr) { $memNA++; continue }
      if ($memStr -eq '') { $memTotal++; continue }
      $memTotal++
      $hits = @()
      foreach ($f in $feat) {
        if ($memStr.IndexOf($f, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $hits += $f }
      }
      if ($hits.Count -gt 0) {
        $memHit++
        $uniq = @($hits | Select-Object -Unique)
        $line = "  [内存特征] " + $p.ProcessName + " (PID " + $p.Id + ") 命中: " + ($uniq -join ',') + " [" + $p.Path + "]"
        Flag $line
        $script:MemScanResults += $line
        Write-AuditLog -Type 'MEM' -Msg ('进程内存特征: ' + $p.ProcessName + ' PID=' + $p.Id + ' 命中=' + ($uniq -join ',') + ' 路径=' + $p.Path)
      }
    }
    Add-Report ("  [内存-进程] 扫描 " + $memTotal + " 个进程, 命中 " + $memHit + " 个, 无权限/无法读取 " + $memNA + " 个 (需管理员)")
  } else {
    Add-Report "  [内存-进程] P/Invoke 不可用, 跳过进程内存读取"
  }

  # ---- 2) 注册表 Run 内容特征 (编码载荷/下载器) ----
  try {
    $runKeys = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce')
    foreach ($rk in $runKeys) {
      if (-not (Test-Path -LiteralPath $rk)) { continue }
      (Get-ItemProperty $rk -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
        $v = [string]$_.Value
        if ($v -and $v -match '(?i)(-enc |encodedcommand|frombase64|downloadstring|mshta http|regsvr32 /u /s|wscript|bitsadmin /transfer|"https?://)') {
          $memHit++
          $line = "  [内存-Run内容] " + ($rk -split '\\')[-1] + '\' + $_.Name + " = " + $v.Substring(0, [Math]::Min(150, $v.Length))
          Flag $line
          $script:MemScanResults += $line
          Write-AuditLog -Type 'MEM' -Msg ('Run 值内容特征: ' + $rk + '\' + $_.Name)
        }
      }
    }
  } catch {}

  # ---- 3) 计划任务脚本本体 (指向 .ps1/.bat/.vbs 的任务脚本内容) ----
  try {
    $scripts = @()
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
      Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
        $_.Actions | ForEach-Object {
          # v1.42: 脚本可能在 Execute 或 Arguments (powershell -File x.ps1), 两处都取
          $ex = $_.Execute
          if ($ex -and $ex -match '\.(ps1|bat|cmd|vbs|js)$' -and (Test-Path -LiteralPath $ex)) { $scripts += $ex }
          $ar = [string]$_.Arguments
          if ($ar -match '(?i)(?:-file|-command|/c)\s+"?([^\s"]+\.(?:ps1|bat|cmd|vbs|js))') {
            $sPath = $Matches[1].Trim('"')
            if (Test-Path -LiteralPath $sPath) { $scripts += $sPath }
          }
        }
      }
    } else {
      # Win7 回退: schtasks list 解析 (仅取脚本型执行路径)
      $taskLines = @(schtasks /query /v /fo list 2>$null)
      $bRun = ''
      foreach ($line in $taskLines) {
        $line = $line.Trim()
        if (-not $line) {
          if ($bRun -match '\.(ps1|bat|cmd|vbs|js)') {
            $ex0 = $bRun
            if ($ex0 -match '^"([^"]+)"') { $ex0 = $Matches[1] }
            elseif ($ex0 -match '^(\S+)') { $ex0 = $Matches[1] }
            if (Test-Path -LiteralPath $ex0) { $scripts += $ex0 }
          }
          $bRun = ''; continue
        }
        if ($line -match '^Task To Run:\s*(.+)$') { $bRun = $Matches[1].Trim() }
        elseif ($line -match '^任务要运行:\s*(.+)$') { $bRun = $Matches[1].Trim() }
      }
    }
    foreach ($s in @($scripts | Select-Object -Unique)) {
      try {
        $content = [IO.File]::ReadAllText($s)
        if ($content -match '(?i)(frombase64|downloadstring|invoke-|mshta|wscript|cscript|-enc |encodedcommand)') {
          $memHit++
          $line = "  [内存-任务脚本] " + $s + " 含可疑代码 (base64/下载器/编码命令)"
          Flag $line
          $script:MemScanResults += $line
          Write-AuditLog -Type 'MEM' -Msg ('任务脚本特征: ' + $s)
        }
      } catch {}
    }
  } catch {}

  Add-Report ("  [内存检测] 完成: 命中 " + $memHit + " 项 (进程内存 " + $memTotal + " 个)")
  Write-AuditLog -Type 'MEM' -Msg ('内存内容检测完成: 命中 ' + $memHit + ' 项')
  return $memHit
}

# ===================== 待办3: 自保护初始化 (函数定义后) =====================
if ($script:SelfProtect) { try { Initialize-SelfProtect } catch { Add-Content -Path $DebugLog -Value ("  [自保护初始化异常] " + $_.Exception.Message) } }

# ===================== 待办7: Ring0 删除模式 (函数定义后, 检测前) =====================
if ($Ring0) {
  Write-AuditLog -Type 'MODE' -Msg ('进入 Ring0 删除模式, 目标: ' + ($script:PathArgs -join ','))
  Write-Host "检测到 /ring0 参数, 进入 Ring0 删除模式 (无伤清除 + 提权删除)..."
  Invoke-Ring0Delete
  Exit-Tool -Code 0 -Reason "Ring0 删除模式完成"
}

# ===================== v1.38: 解锁模式 (/unlock) =====================
if ($Unlock) {
  Write-AuditLog -Type 'MODE' -Msg '进入解锁模式 (/unlock)'
  Write-Host "检测到 /unlock 参数, 列出已锁定文件..."
  Show-LockList
  Exit-Tool -Code 0 -Reason '解锁模式完成'
}

# ===================== v1.39: 网络封锁管理 (/netblock) =====================
if ($NetBlockMode) {
  Write-AuditLog -Type 'MODE' -Msg '进入网络封锁管理 (/netblock)'
  Write-Host "检测到 /netblock 参数, 查看网络封锁清单..."
  Show-NetBlock
  Exit-Tool -Code 0 -Reason '网络封锁管理完成'
}

# ===================== v1.42: 内存检测模式 (/mem) =====================
if ($MemScan) {
  Write-AuditLog -Type 'MODE' -Msg '进入内存内容检测模式 (/mem)'
  Write-Host "检测到 /mem 参数, 进入内存内容检测模式..."
  Invoke-MemScan | Out-Null
  Exit-Tool -Code 0 -Reason '内存检测完成'
}

# ===================== v1.36: 驱动审计模式 (/drivers) =====================
if ($Drivers) {
  Write-AuditLog -Type 'MODE' -Msg ('进入驱动审计模式 (/drivers, full=' + $Full + ')')
  Write-Host "检测到 /drivers 参数, 进入驱动签名审计模式..."
  Invoke-DriverAudit | Out-Null
  # v1.37: 发现问题驱动后询问是否手动选择删除 (Ring0 提权)
  try { Invoke-DriverInteractiveDelete } catch { Write-Host ("  [驱动删除异常] " + $_.Exception.Message) -ForegroundColor Red }
  Exit-Tool -Code 0 -Reason '驱动审计完成'
}

# ===================== v1.34: 启动关机拦截 (检测前) =====================
Start-ShutdownGuard




Add-Report ("白名单 : 签名者 " + $script:WL.Signers.Count + " / 目录 " + $script:WL.Dirs.Count + " / 路径 " + $script:WL.Paths.Count + " / 名称 " + $script:WL.Names.Count)
try { Ensure-Watchdog } catch {}   # v1.50: 扫描前检查 watchdog 存活

# 写文件头
Add-Report "=============================================="
Add-Report "   顽固木马扫描专杀-银狐特攻 扫描 / 隔离报告"
Add-Report "=============================================="
Add-Report ("检测时间 : " + $ts)
$modeStr = if($Full){"全盘"}else{"关键目录"}
if ($ZeroTrust) { $modeStr += "+零信任(含工具目录)" }
if ($Safe) { $modeStr += "+安全模式" }
if ($Offline) { $modeStr += "+离线(无网络)" }
if ($script:ShutdownGuard) { $modeStr += "+关机拦截" }
$hashStr = if($NoHash){"关"}else{"启用 MD5=" + $hashMD5.Count + " SHA256=" + $hashSHA.Count}
$quarStr = if($QuarantineMode -and -not $NoQuarantine){"开(仅高危特征)"}else{"关(默认只报告不移动文件)"}
Add-Report ("模式     : " + $modeStr + "  哈希比对=" + $hashStr + "  自动隔离=" + $quarStr + "  C2库=" + ($c2Domains.Count + $c2IPs.Count))
Add-Report ("计算机名 : " + $env:COMPUTERNAME + "   用户: " + $env:USERNAME)
Add-Report ""
# v1.35: 操作留痕 - 扫描开始 (放在模式变量定义之后)
try { Write-AuditLog -Type 'SCAN' -Msg ('扫描开始 模式=' + $modeStr + ' 哈希比对=' + $hashStr + ' 自动隔离=' + $quarStr) } catch {}
# v1.68: 扫描进度初始化 (GUI 展示)
Clear-ScanProgress
Write-ScanProgress ('扫描引擎 v1.94 已启动  模式=' + $modeStr + '  OS=' + [System.Environment]::OSVersion.Version.ToString() + '  PS=' + $PSVersionTable.PSVersion.ToString() + '  时间=' + (Get-Date -Format 'HH:mm:ss'))

# ===================== 多重启动模式: 安全模式检测 (v1.32) =====================
function Test-SafeMode {
  # 注册表 SafeBoot\Option\OptionValue: 1=minimal 2=network
  try {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Option' -Name OptionValue -ErrorAction Stop).OptionValue
    return ($v -eq 1 -or $v -eq 2)
  } catch { return $false }
}
if ($Safe) {
  if (Test-SafeMode) {
    Write-Host "  [安全模式] 当前处于安全模式环境, 顽固木马无法加载驱动/自启对抗" -ForegroundColor Green
    Add-Report "  [启动模式] 安全模式环境 (顽固木马对抗能力受限, 更易清除)"
  } else {
    Write-Host ""
    Write-Host "  [安全模式] 当前不是安全模式。顽固木马在正常模式下会对抗检测/恢复自启。" -ForegroundColor Yellow
    Write-Host "  急救箱流程: 设置安全模式 -> 重启 -> 进入安全模式后再次运行本工具查杀。" -ForegroundColor Yellow
    Write-Host "  注意: bcdedit 将修改系统启动配置(可随时用 bcdedit /deletevalue safeboot 恢复)。" -ForegroundColor Gray
    $ans = Read-Host "  是否立即设置安全模式并重启? (y=设置并重启 / n=仅当前环境继续)"
    if ($ans.Trim().ToLower() -eq 'y') {
      Write-Host "  正在设置安全模式启动项..." -ForegroundColor Cyan
      try {
        $rc = Start-Process bcdedit.exe -ArgumentList '/set','{current}','safeboot','minimal' -NoNewWindow -Wait -PassThru -ErrorAction Stop
        if ($rc.ExitCode -eq 0) {
          Write-Host "  [OK] 已设置安全模式。10 秒后重启, 请重新运行本工具!" -ForegroundColor Green
          Start-Sleep -Seconds 10
          shutdown.exe /r /t 5 /c "SilverFox 检测工具: 进入安全模式急救" 
        } else {
          Write-Host "  [错误] bcdedit 设置失败(退出码 " + $rc.ExitCode + "), 需管理员权限" -ForegroundColor Red
        }
      } catch { Write-Host "  [错误] bcdedit 不可用: " + $_.Exception.Message -ForegroundColor Red }
    } else {
      Write-Host "  继续在当前环境运行 (安全模式可稍后手动设置: bcdedit /set {current} safeboot minimal)" -ForegroundColor Gray
    }
  }
}

# ===================== 1 进程 / 命令行扫描 =====================
Add-Report "[1/7] 进程 / 命令行扫描"
Write-ScanProgress "[1/7] 进程 / 命令行扫描..."
try {
  $sysRoots = @("$env:SystemRoot\System32","$env:SystemRoot\SysWOW64","$env:SystemRoot")
  $sysNames = @('svchost.exe','explorer.exe','lsass.exe','services.exe','csrss.exe','winlogon.exe','smss.exe','taskhost.exe')
  $myPid = $PID
  # v1.53: 旧 cmdBad/c2pat 一刀切正则已废弃, 改由 Get-CmdRisk + Test-C2DomainInText 评分引擎接管
  $procCount = 0; $obsCount = 0; $flagCount = 0
  if (-not $script:threatProcs) { $script:threatProcs = @() }   # v1.81: 高危进程记录(交互处置用)
  # v1.42: 预取 Win32_Process 路径映射, 供 Get-Process 的 Path 为空时回退 (提权/他人账户进程)
  $cimProcPaths = @{}
  try { Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { if ($_.ExecutablePath) { $cimProcPaths[$_.ProcessId] = $_.ExecutablePath } } } catch {}
  Get-Process | ForEach-Object {
    $p = $_.Path
    if (-not $p) {
      $p = $cimProcPaths[$_.Id]
      if (-not $p) {
        # v1.42: 仍读不到路径的进程不静默丢弃, 计入观察清单
        $obsCount++
        $script:observe += ("[进程无路径] PID=" + $_.Id + " 名=" + $_.Name + " (无法读取映像路径, 可能需管理员权限)")
        return
      }
    }
    # 排除自身进程
    if ($_.Id -eq $myPid) { return }
    if ($p -match 'SilverFoxDetect|银狐') { return }
    $name = $_.Name + '.exe'
    $inSys = $false
    foreach ($d in $sysRoots){ if ($p.StartsWith($d, [StringComparison]::OrdinalIgnoreCase)){ $inSys = $true } }
    $procCount++
    # a) 伪装系统进程: 名字是系统进程但路径不在系统目录
    if (($sysNames -contains $name) -and -not $inSys) {
      # v1.24: 白名单/可信签名降噪
      if (Test-Whitelist -Path $p -Name $name) { return }
      if (Test-TrustedSigner $p) { return }
      $flagCount++
      Add-ThreatLock $p "伪装系统进程名"   # v1.38 检测出先锁定
      # v1.81: 恶意伪装系统进程先安全结束(best-effort), 再隔离文件(运行中文件无法移动)
      try {
        Stop-Process -Id $_.Id -Force -ErrorAction Stop
        Write-Host ("  [已结束进程] " + $name + " PID=" + $_.Id) -ForegroundColor Yellow
        Add-Report ("  [已结束进程] " + $name + " PID=" + $_.Id)
      } catch {
        Write-Host ("  [提示] 结束进程失败(需管理员?): " + $name + " PID=" + $_.Id) -ForegroundColor Gray
        Add-Report ("  [提示] 结束进程失败: " + $name + " PID=" + $_.Id)
      }
      if (-not ($script:threatProcs -contains $_.Id)) { $script:threatProcs += $_.Id }
      $qm = Quarantine $p "伪装系统进程名"
      Flag ("  [高危-伪装系统进程] " + $name + " -> " + $p + "  [" + $qm + "]  PID " + $_.Id)
      return
    }
    # b) 非系统目录的其他进程 -> 观察清单 (不 Flag 不隔离)
    if (-not $inSys -and ($p -match '\.(exe|dll)$')) {
      $obsCount++
      Observe ("  " + $name + " -> " + $p + "  PID " + $_.Id)
      return
    }
  }
  # 命令行扫描 (含 C2 与恶意特征)
  Get-CimInstance Win32_Process | ForEach-Object {
    $cmd = $_.CommandLine
    if (-not $cmd) { return }
    if ($_.ProcessId -eq $myPid) { return }
    if ($cmd -match 'SilverFoxDetect') { return }
    # v1.53: 命令行风险评分 (替代旧 cmdBad 一刀切). 弱信号单独不再判高危, 累积评分裁决.
    #        已知 C2 域名被引用: 仍自动封锁外联(低成本可逆), 但仅作为中权重信号参与评分, 不再必报高危.
    $procPath2 = $null
    try { $procPath2 = (Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue).Path } catch {}
    # 可信签名进程引用域名/命令特征几乎必为合法(厂商遥测/研究), 直接跳过降噪
    if ($procPath2 -and (Test-TrustedSigner $procPath2)) { return }
    $sig = Get-CmdRisk $cmd
    # v1.90: 强制重启命令特征(病毒让 Defender 排除项生效的经典手法, 样本 shutdown /r /f /t 0)
    if ($cmd -match '(?i)shutdown\s+(/r|-r)(\s+/f|-f)') {
      WatchLine ("  [注意-强制重启] 检测到强制重启命令调用: " + $cmd.Substring(0, [Math]::Min(120, $cmd.Length)))
      Add-Report ("  [注意-强制重启] " + $cmd.Substring(0, [Math]::Min(180, $cmd.Length)) + " (病毒让排除项生效的手法, 请警觉)")
    }
    $c2hits = Test-C2DomainInText $cmd
    if ($c2hits -and $c2hits.Count -gt 0) {
      $sig['C2_DOMAIN_CMD'] = $RISK['C2_DOMAIN_CMD']
      if ($NetBlock) {
        try { Add-NetBlock -IP '' -ProcessPath $procPath2 -Reason ('C2域名:' + ($c2hits -join '/')) } catch {}
      }
    }
    if ($sig.Count -gt 0) {
      $verdict = Get-RiskVerdict $sig
      $label = ($_.Name + " : " + $cmd.Substring(0, [Math]::Min(200, $cmd.Length)))
      [void](Invoke-Verdict -Verdict $verdict -Label $label -Path $procPath2 -QuarantineReason '命令行' -NoQuarantine)
      if ($verdict.Verdict -eq 'THREAT') { $flagCount++ } else { $obsCount++ }
    }
  }
  Add-Report ("  [统计] 运行进程 " + $procCount + " 个, 高危 " + $flagCount + " 项, 观察清单 " + $obsCount + " 项")
  if ($obsCount -gt 0) {
    Add-Report ("  [观察] 非系统目录进程 " + $obsCount + " 项已写入: " + $obsFile)
    try { (("进程观察清单 " + $ts + "`n") + ($observe -join "`n")) | Set-Content -Path $obsFile -Encoding UTF8 } catch {}
  }
} catch { Flag ("  [模块错误] 进程扫描异常: " + $_.Exception.Message) }
Add-Report ""

# ===================== 2 落地文件 + 双哈希 =====================
Add-Report "[2/7] 落地文件与哈希扫描 (MD5+SHA256)"
Write-ScanProgress "[2/7] 落地文件与哈希扫描 (遍历目录, 耗时视内容而定)..."
try {
  $dl = Join-Path $script:EnvUser 'Downloads'
  $docs = Join-Path $script:EnvUser 'Documents'
  if ($Full) {
    # v1.94: 真全盘 —— 所有固定分区(盘根) + 深度999全递归; 耗时很长, 提示用户
    $allRoots = @()
    try {
      $lds = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)
      foreach ($ld in $lds) {
        $root = ($ld.DeviceID + '\\')
        if (Test-Path -LiteralPath $root) { $allRoots += @{Path=$root; Depth=999} }
      }
    } catch {}
    if ($allRoots.Count -eq 0) {
      $allRoots = @(
        @{Path=$script:EnvUser; Depth=5}, @{Path=$script:EnvTmp; Depth=3}, @{Path=$env:APPDATA; Depth=3},
        @{Path=$env:LOCALAPPDATA; Depth=3}, @{Path=$env:ProgramData; Depth=3},
        @{Path=(Join-Path $env:SystemRoot 'System32'); Depth=1}, @{Path=(Join-Path $env:SystemRoot 'SysWOW64'); Depth=1}
      )
    }
    $scanDirs = $allRoots
    $depth = 999
    $rootNames = ($allRoots | ForEach-Object { $_.Path }) -join ' '
    Add-Report ("  [全盘模式] 扫描全部分区: " + $rootNames + " (深度全递归; 预计耗时很长, 可随时关闭窗口取消)")
  } else {
    # v1.81: scanDirs 支持带深度元组, System32 顶层+drivers 浅扫(银狐常驻点)
    $scanDirs = @(
      @{Path=$script:EnvTmp; Depth=3}, @{Path=$env:APPDATA; Depth=3}, @{Path=$env:LOCALAPPDATA; Depth=3},
      @{Path=$env:ProgramData; Depth=3},
      @{Path=[Environment]::GetFolderPath('Startup'); Depth=1}, @{Path=[Environment]::GetFolderPath('CommonStartup'); Depth=1},
      @{Path=$dl; Depth=2}, @{Path=$docs; Depth=2},
      @{Path=(Join-Path $env:SystemRoot 'System32'); Depth=1},
      @{Path=(Join-Path $env:SystemRoot 'System32\drivers'); Depth=1},
      @{Path=(Join-Path $env:SystemRoot 'SysWOW64'); Depth=1}
    )
    $depth = 3
    Add-Report "  [关键目录模式] 扫描 Temp/AppData/ProgramData/启动/下载/文档/System32(浅扫)"
  }
  # v1.31 零信任: 工具目录自身也纳入扫描 (检测掉入工具目录的木马/样本), 追加前先去重
  if ($ZeroTrust -and $script:toolRoot) {
    $tr = $script:toolRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $dup = $false
    foreach ($sd in $scanDirs) {
      if ($sd -and $sd.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) -eq $tr) { $dup = $true; break }
    }
    if (-not $dup) { $scanDirs += $script:toolRoot }
    Add-Report ("  [零信任] 追加工具目录: " + $script:toolRoot)
  }  $exts = @('exe','dll','ps1','vbs','js','bat','cmd','scr','jar','sys')
  $fileCount = 0; $highFlag = 0; $obsFileCount = 0
  $hashChecked = 0; $hashCacheHit = 0
  # v1.21: 持久化哈希缓存 - 主存 C盘 %LOCALAPPDATA%\SilverFoxDetector\hash_cache.txt
  #        (换版本/换目录不丢), 工具目录留副本 sf_hash_cache.txt
  #        每行: "大小|修改时间ticks|md5|sha256"
  $cacheDir = $env:LOCALAPPDATA
  if (-not $cacheDir -or -not (Test-Path -LiteralPath $cacheDir)) { $cacheDir = $script:EnvUser }
  $cacheDir = Join-Path $cacheDir 'SilverFoxDetector'
  try { New-Item -ItemType Directory -Path $cacheDir -Force -ErrorAction Stop | Out-Null } catch { $cacheDir = $script:toolRoot }
  $CacheFile = Join-Path $cacheDir 'hash_cache.txt'
  $CacheMirror = Join-Path $script:toolRoot 'sf_hash_cache.txt'
  $hashCache = @{}
  if (Test-Path -LiteralPath $CacheFile) {
    foreach ($cl in (Get-Content $CacheFile -Encoding ASCII -ErrorAction SilentlyContinue)) {
      if ($cl -match '^(\d+)\|(\d+)\|([0-9a-f]{32})\|([0-9a-f]{64})$') {
        $hashCache[$Matches[1] + '|' + $Matches[2]] = @{ m5=$Matches[3]; s5=$Matches[4] }
      }
    }
  }
  # 主缓存缺失时, 用工具目录副本兜底
  if ($hashCache.Count -eq 0 -and (Test-Path -LiteralPath $CacheMirror)) {
    foreach ($cl in (Get-Content $CacheMirror -Encoding ASCII -ErrorAction SilentlyContinue)) {
      if ($cl -match '^(\d+)\|(\d+)\|([0-9a-f]{32})\|([0-9a-f]{64})$') {
        $hashCache[$Matches[1] + '|' + $Matches[2]] = @{ m5=$Matches[3]; s5=$Matches[4] }
      }
    }
  }
  $cacheDirty = $false
  # v1.22: 多线程哈希计算 (RunspacePool, 默认4线程, /threads=N 可调)
  $workerScript = {
    param($path)
    try {
      $fs = [System.IO.File]::OpenRead($path)
      $shaObj = [System.Security.Cryptography.SHA256]::Create()
      $sb = $shaObj.ComputeHash($fs)
      $fs.Position = 0
      $md5Obj = [System.Security.Cryptography.MD5]::Create()
      $mb = $md5Obj.ComputeHash($fs)
      $fs.Close()
      $h = ([System.BitConverter]::ToString($sb) -replace '-', '').ToLower()
      $m = ([System.BitConverter]::ToString($mb) -replace '-', '').ToLower()
      return $h + '|' + $m
    } catch { return '' }
  }
  function Invoke-HashBatch {
    param([array]$Items, [int]$Threads, [scriptblock]$Script)
    $results = @{}
    $pool = [runspacefactory]::CreateRunspacePool(1, $Threads)
    $pool.Open()
    $jobs = @()
    foreach ($item in $Items) {
      $ps = [powershell]::Create()
      $ps.RunspacePool = $pool
      [void]$ps.AddScript($Script).AddArgument($item.Path)
      $handle = $ps.BeginInvoke()
      $jobs += @{ PS=$ps; Handle=$handle; Item=$item }
    }
    foreach ($j in $jobs) {
      try {
        $out = $j.PS.EndInvoke($j.Handle)
        if ($out -and $out.Count -gt 0 -and $out[0] -match '^([0-9a-f]{64})\|([0-9a-f]{32})$') {
          $results[$j.Item.Key] = @{ m5=$Matches[2]; s5=$Matches[1] }
        }
      } catch {}
      $j.PS.Dispose()
    }
    $pool.Close(); $pool.Dispose()
    return $results
  }
  $pending = @()  # 未命中缓存, 需并行算哈希
  $candidates = @()  # 所有候选(命中+未命中), 第4遍比对用
  foreach ($dir in $scanDirs) {
    $dirPath = if ($dir -is [hashtable]) { $dir.Path } else { $dir }
    $dirDepth = if ($dir -is [hashtable]) { $dir.Depth } else { $depth }
    if ($dirPath -and (Test-Path -LiteralPath $dirPath)) {
      $files = @(Get-ChildItemSafe -Path $dirPath -Depth $dirDepth)
      $dirTotal = $files.Count
      if ($dirTotal -eq 0) { continue }
      Write-Host ("  扫描: " + (Split-Path $dirPath -Leaf) + " (深度 " + $dirDepth + "), 候选 " + $dirTotal + " 个文件 ...")
      $dirIdx = 0
      foreach ($f in $files) {
        $dirIdx++; $fileCount++
        if ($dirIdx % 500 -eq 0 -or $dirIdx -eq $dirTotal) {
          $pct = [math]::Round($dirIdx * 100.0 / $dirTotal)
          Write-Host ("    进度: " + $dirIdx + "/" + $dirTotal + " (" + $pct + "%)")
          # v2.15.32: 进度同时写入报告(窗口黑屏时仍可实时查看)
          try { Add-Report ("    进度: " + $dirIdx + "/" + $dirTotal + " (" + $pct + "%)") } catch {}
          # v1.69: 进度同步到 GUI 面板 (Write-ScanProgress)
          try { Write-ScanProgress ("[2/7] 文件扫描: " + $dirIdx + "/" + $dirTotal + " (" + $pct + "%)") } catch {}
        }
        $fn = $f.Name; $fp = $f.FullName
        # v1.27: 排除工具根目录自身 (引擎自己生成的报告/隔离区/观察清单等)
        # v1.31: 零信任模式 /zerotrust 下不排除工具目录, 工具自身文件由 Test-ToolSelfFile 保护
        if ($fp.StartsWith(($script:toolRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) {   # v1.42: 前缀补分隔符
          if (-not $ZeroTrust) { continue }
          if (Test-ToolSelfFile $fp) { continue }
        }
        # v1.28: 读文件头判断是否 PE (MZ) - 不依赖扩展名 (银狐可伪装成图片/驱动/无扩展名)
        $isPE = $false   # v1.42: 重置移到 if 外, 防 <2 字节文件继承上轮值
        if ($f.Length -ge 2) {
          try {
            $fs = [System.IO.File]::OpenRead($fp)
            $b0 = $fs.ReadByte(); $b1 = $fs.ReadByte()
            $fs.Close()
            $isPE = ($b0 -eq 0x4D -and $b1 -eq 0x5A)
          } catch {}
        $isImg = $fn -match '\.(png|jpg|jpeg|gif|bmp|ico|webp)$'
        }
        $isExecExt = $fn -match '\.(exe|dll|sys|ps1|vbs|js|bat|cmd|scr|jar|tmp|dat|bin)$'
        $noExt = ($fn -notmatch '\.')
        # 隐藏/系统属性
        $attrs = [int]$f.Attributes
        $isHidden = (($attrs -band 2) -ne 0)   # FILE_ATTRIBUTE_HIDDEN
        $isSystem = (($attrs -band 4) -ne 0)   # FILE_ATTRIBUTE_SYSTEM
        # v1.43: 启发式高危判定前查白名单/签名 (Bcut/Inno Setup/CPU-Z 等合法软件免误报)
        #        命中则本文件跳过启发式, 仍走 hash 比对 (本轮之后还会算 md5/sha256)
        $wlSkip = $false
        if (Test-Whitelist -Path $fp -Name $fn) { $wlSkip = $true }
        # v1.69: 签名验证必须先判 PE(MZ头)+大小<=50MB —— Get-AuthenticodeSignature 对
        #   大文件/云盘占位文件/畸形PE 会挂起数分钟, 旧版每个文件都验签导致 [2/7] 卡死(实测 3500/14820 停 15 分钟)
        elseif ($isPE -and $f.Length -le 52428800 -and (Test-TrustedSigner $fp)) { $wlSkip = $true }
        elseif ($isPE -and $f.Length -le 52428800 -and (Test-SafeHarbor $fp)) { $wlSkip = $true }

        # 1) 文件名启发式 (原有)
        $hit = $false; $reason = ""
        if (-not $wlSkip) {
          if ($fn -match '\.png\.exe$|\.jpg\.exe$|\.gif\.exe$|\.txt\.exe$|\.doc\.exe$') { $hit=$true; $reason="双扩展名伪装" }
          elseif ($fn -match '^(svchost|explorer|lsass|services|smss|winlogon)\.exe$') { $hit=$true; $reason="与系统进程同名" }
          # 2) v1.28: 内容启发式 - 图片/无扩展名但文件头是 MZ -> 伪装可执行
          elseif ($isPE -and ($isImg -or $noExt)) { $hit=$true; $reason="图片/无扩展名伪装可执行(MZ头)" }
        }
        if ($hit) {
          $highFlag++
          Add-ThreatLock $fp $reason   # v1.38 检测出先锁定
      $qm = Quarantine $fp $reason
          Flag ("  [高危文件][$reason] " + $fp + "  [" + $qm + "]")
          continue
        }
        # ===== v1.95: PE 结构启发 (双段 overlay / 加壳节) — 白签名捆绑/大文件专用静态信号 =====
        # 不依赖签名判有效; 但对含白名单/信任签名的小文件(<=50MB)跳过以降噪(与既有启发一致;
        # 大文件>50MB不走 wlSkip, 这里照样会跑)。命中默认仅观察(档位1), 不误杀官方大安装器
        # (官方微信/Adobe/Office 多为 NSIS, 尾部 overlay 也大)。档位2需叠加信号, 档位3才直接隔离。
        if (-not $wlSkip -and $isPE) {
          $struct = Get-PEStruct $fp $f.Length
          $structHit = $false; $structWhy = ""; $im = @()
          if ($struct) {
            if ($struct.Packed) { $structHit=$true; $structWhy += "加壳节(" + (@($struct.Sections) -join ',') + ")" }
            if ($struct.Overlay -ge 8388608 -and $struct.OverlayRatio -ge 0.5) {
              $mb = [math]::Round($struct.Overlay/1048576.0,1)
              if ($structWhy) { $structWhy += " + " }
              $structWhy += ("双段overlay {0}MB({1:P0})" -f $mb, $struct.OverlayRatio)
            }
          }
          if ($structHit) {
            $obsFileCount++
            $im = @()
            if ($DeepPE) { $im = @(Get-ImportSensitive $fp) }
            Observe ("  [PE结构][观察] " + $fp + "  -> " + $structWhy + $(if ($im.Count -gt 0) { "  [导入敏感API:" + ($im -join '/') + "]" } else { "" }))
            # 档位3: 结构异常即高危隔离 (最激进, 用户自选)
            if ($StructPolicy -eq 3) {
              $highFlag++
              Add-ThreatLock $fp $structWhy
              $qm = Quarantine $fp $structWhy
              Flag ("  [高危文件][PE结构异常:" + $structWhy + "] " + $fp + "  [" + $qm + "]")
              continue
            }
            # 档位2: 多信号叠加才高危 —— 导入敏感API>=3类 / 文件名伪装 / 隐藏系统属性
            if ($StructPolicy -eq 2) {
              $boost=$false; $boostWhy=""
              if ($im.Count -ge 3) { $boost=$true; $boostWhy="导入敏感API(" + ($im -join '/') + ")" }
              elseif ($fn -match '\.png\.exe$|\.jpg\.exe$|\.gif\.exe$|\.txt\.exe$|\.doc\.exe$') { $boost=$true; $boostWhy="双扩展名伪装" }
              elseif ($isHidden -or $isSystem) { $boost=$true; $boostWhy="隐藏/系统属性" }
              if ($boost) {
                $highFlag++
                Add-ThreatLock $fp ($structWhy + " + " + $boostWhy)
                $qm = Quarantine $fp ($structWhy + " + " + $boostWhy)
                Flag ("  [高危文件][PE结构异常+叠加] " + $fp + "  [" + $qm + "]")
                continue
              }
            }
            # 档位1(默认): 仅观察, 不隔离, 继续走后续检查
          }
        }
        # 3) v1.28: 隐藏/系统属性 - 可执行则高危, 否则观察
        # v1.43: Bcut/Inno Setup/老版本 dll 大量设了 Hidden 属性, 单独该属性不再是高危证据.
        #        仅"启发式未命中+哈希也未命中"时, 记为观察 (不再 ThreatLock / Quarantine).
        if ($isHidden -or $isSystem) {
          if ($isPE -and -not $wlSkip) {
            $obsFileCount++
            Observe ("  [隐藏属性可执行] " + $fp)
          } elseif (-not $isPE) {
            $obsFileCount++
            Observe ("  [隐藏文件] " + $fp)
          }
          continue
        }
        # 4) 随机名 exe (误报多, 仅观察)
        if (-not $wlSkip -and $fn -match '^[a-z0-9]{9,}\.exe$') {
          $obsFileCount++
          Observe ("  [随机名exe] " + $fp + " 大小=" + $f.Length)
          continue
        }
        # 5) v1.28: 未签名驱动观察 (.sys 不在 system32\drivers)
        if ($fn -match '\.sys$' -and $fp -notmatch '(?i)\\system32\\drivers\\') {
          try {
            if ($f.Length -gt 52428800) { continue }  # v1.69: 超大 .sys 验签挂起, 跳过仅观察
            $sig = Get-AuthenticodeSignature -FilePath $fp -ErrorAction SilentlyContinue
            if (-not $sig -or $sig.Status -ne 'Valid') {
              $obsFileCount++
              Observe ("  [未签名驱动] " + $fp + " 签名=" + $(if ($sig) { $sig.Status.ToString() } else { '无' }))
            }
          } catch {}
        }
        # 6) 候选判定: MZ 或 可执行扩展 -> 进入哈希比对 (任意格式的恶意文件都能覆盖)
        if ($isPE -or $isExecExt) {
          $hkey = $f.Length.ToString() + '|' + $f.LastWriteTimeUtc.Ticks.ToString()
          $candidates += @{ Path=$fp; Key=$hkey }
          if (-not $NoHash) {
            if ($hashCache.ContainsKey($hkey)) {
              $hashCacheHit++
            } else {
              $pending += @{ Path=$fp; Key=$hkey }
            }
          }
        }
      }
    }
  }
  # 第三遍: 多线程并行计算待算文件哈希
  if (-not $NoHash -and $pending.Count -gt 0) {
    Write-Host ("  并行计算 " + $pending.Count + " 个文件哈希 (" + $Threads + " 线程) ...")
    $batchSize = $Threads * 16
    $done = 0
    for ($i=0; $i -lt $pending.Count; $i += $batchSize) {
      $hi = [Math]::Min($i + $batchSize - 1, $pending.Count - 1)
      $batch = @($pending[$i..$hi])
      $res = Invoke-HashBatch -Items $batch -Threads $Threads -Script $workerScript
      foreach ($k in $res.Keys) {
        $hashCache[$k] = $res[$k]
        $cacheDirty = $true
        $hashChecked++
      }
      $done += $batch.Count
      $pct = [math]::Round($done * 100.0 / $pending.Count)
      Write-Host ("    哈希进度: " + $done + "/" + $pending.Count + " (" + $pct + "%)")
      # v2.15.32: 进度同步写报告
      try { Add-Report ("    哈希进度: " + $done + "/" + $pending.Count + " (" + $pct + "%)") } catch {}
      # v1.69: 进度同步到 GUI 面板
      try { Write-ScanProgress ("[2/7] 哈希比对: " + $done + "/" + $pending.Count + " (" + $pct + "%)") } catch {}
    }
  }
  # 第四遍: 用缓存(含新算的)比对已知恶意库 - 只处理候选文件(不重新枚举)
  foreach ($c in $candidates) {
    $fp = $c.Path
    if ($NoHash) { continue }
    if ($hashCache.ContainsKey($c.Key)) {
      $h = $hashCache[$c.Key].s5
      $m = $hashCache[$c.Key].m5
      if ($h -and $hashSHA.ContainsKey($h)) {
        $highFlag++
        Add-ThreatLock $fp "已知恶意SHA256"   # v1.38 检测出先锁定
        $qm = Quarantine $fp "已知恶意SHA256"
        Flag ("  [高危文件][已知恶意SHA256] " + $fp + "  [" + $qm + "]")
      } elseif ($m -and $hashMD5.ContainsKey($m)) {
        $highFlag++
        Add-ThreatLock $fp "已知恶意MD5"   # v1.38 检测出先锁定
        $qm = Quarantine $fp "已知恶意MD5"
        Flag ("  [高危文件][已知恶意MD5] " + $fp + "  [" + $qm + "]")
      }
    }
  }
  # v1.21: 有新增缓存时双写 - C盘主缓存 + 工具目录副本
  if ($cacheDirty) {
    try {
      $cap = 200000  # 缓存条数上限, 超出截断
      $cacheLines = @()
      foreach ($k in @($hashCache.Keys)) {
        $v = $hashCache[$k]
        $cacheLines += ($k + '|' + $v.m5 + '|' + $v.s5)
        if ($cacheLines.Count -ge $cap) { break }
      }
      $cacheLines | Set-Content -Path $CacheFile -Encoding ASCII
      try { $cacheLines | Set-Content -Path $CacheMirror -Encoding ASCII } catch {}
    } catch {}
  }
  Add-Report ("  [统计] 扫描 " + $fileCount + " 个文件, 可执行候选 " + $candidates.Count + " 个, 算哈希 " + $hashChecked + " 个 (缓存命中 " + $hashCacheHit + ", 缓存共 " + $hashCache.Count + " 条), 高危 " + $highFlag + " 项, 观察 " + $obsFileCount + " 项")
  if ($obsFileCount -gt 0) {
    Add-Report ("  [观察] 随机名 exe 已并入观察清单: " + $obsFile)
    try { Add-Content -Path $obsFile -Value ("`n--- 随机名exe观察 ---`n" + (($observe | Where-Object {$_ -match '随机名'}) -join "`n")) -Encoding UTF8 } catch {}
  }
} catch { Flag ("  [模块错误] 文件扫描异常: " + $_.Exception.Message) }
Add-Report ""

# ===================== 3 注册表 =====================
Add-Report "[3/7] 注册表自启动项扫描"
Write-ScanProgress "[3/7] 注册表自启动项扫描..."
try {
  $runKeys = @(
   'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
   'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
   'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
   'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
   'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
  $skipProps = @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')
  $runCount = 0; $runFlag = 0; $runWarn = 0
  foreach ($k in $runKeys) {
    if (Test-Path -LiteralPath $k) {
      Get-ItemProperty $k | ForEach-Object {
        $_.PSObject.Properties | Where-Object { $_.Name -notin $skipProps -and $_.Value } | ForEach-Object {
          $runCount++
          $val = [string]$_.Value
          # v1.53: 改用持久化风险评分 (Get-PersistRisk), 单一弱信号不再必报高危
          $runVal = [string]$val
          $runExe = Get-ExecPath $runVal
          # 白名单/可信签名降噪: 直接跳过
          if (Test-Whitelist -Path $runExe -Name (Split-Path $runExe -Leaf)) { return }
          if (Test-TrustedSigner $runExe) { return }
          $pr = Get-PersistRisk $runExe $runVal
          if ($pr.Signals.Count -gt 0) {
            $verdict = Get-RiskVerdict $pr.Signals
            $sigInfo = Get-SignatureStatus $pr.ExecClean
            $sigStr = if ($sigInfo.Signer) { ("签名=" + $sigInfo.Raw + "(" + $sigInfo.Signer + ")") } else { ("签名=" + $sigInfo.Raw) }
            $label = ($k + " -> " + $_.Name + " = " + $runVal.Substring(0, [Math]::Min(160, $runVal.Length)) + "  " + $sigStr)
            [void](Invoke-Verdict -Verdict $verdict -Label $label -Path $pr.ExecClean -QuarantineReason '自启动' -NoQuarantine)
            if ($verdict.Verdict -eq 'THREAT') { $runFlag++ } else { $runWarn++ }
          }
        }
      }
    }
  }
  Add-Report ("  [统计] 自启动项 " + $runCount + " 个, 高危 " + $runFlag + " 项, 待核实 " + $runWarn + " 项")
} catch { Flag ("  [模块错误] 注册表扫描异常: " + $_.Exception.Message) }
Add-Report ""

# ===================== 4 计划任务 =====================
Add-Report "[4/7] 计划任务扫描"
Write-ScanProgress "[4/7] 计划任务扫描..."
try {
  $script:taskCount = 0; $script:taskFlag = 0; $script:taskWarn = 0
  # v1.42: Win7/PS5.1 无 ScheduledTasks 模块 (Get-ScheduledTask 未定义时命令静默失败, 假报 0 个),
  #        先探测, 缺失则回退 schtasks /query /v /fo list 解析
  function Test-TaskEntry([string]$TaskName, [string]$TaskPath, [string]$Exec, [string]$Args) {
    $script:taskCount++
    $ex = $Exec; $ar = $Args
    $exClean = Get-ExecPath $ex
    # v1.53: 白名单/可信签名降噪: 直接跳过 (覆盖绝大多数正常软件更新任务, 根除 \appdata\ 过度命中)
    if (Test-Whitelist -Path $exClean -Name (Split-Path $exClean -Leaf)) { return }
    if (Test-TrustedSigner $exClean) { return }
    # 持久化风险评分. 把 exec+args 作为 Value 评估 (下载执行特征可能在参数里)
    $pr = Get-PersistRisk $ex ($ex + ' ' + $ar)
    if ($pr.Signals.Count -gt 0) {
      $verdict = Get-RiskVerdict $pr.Signals
      $sigInfo = Get-SignatureStatus $pr.ExecClean
      $sigStr = if ($sigInfo.Signer) { ("签名=" + $sigInfo.Raw + "(" + $sigInfo.Signer + ")") } else { ("签名=" + $sigInfo.Raw) }
      $label = ("任务=" + $TaskName + " 路径=" + $TaskPath + " 执行=" + $ex + "  " + $sigStr + " " + $ar.Substring(0, [Math]::Min(120, $ar.Length)))
      [void](Invoke-Verdict -Verdict $verdict -Label $label -Path $pr.ExecClean -QuarantineReason '计划任务' -NoQuarantine)
      if ($verdict.Verdict -eq 'THREAT') { $script:taskFlag++ } else { $script:taskWarn++ }
    }
  }
  if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
    Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
      $t = $_
      # v1.7: 排除 Windows 系统任务 (TaskPath 以 \Microsoft\ 开头)
      if ($t.TaskPath -match '^\\Microsoft\\') { return }   # v1.42: \M 是非法正则转义, 会抛异常导致整个模块失效
      try {
        $t.Actions | ForEach-Object {
          Test-TaskEntry -TaskName $t.TaskName -TaskPath $t.TaskPath -Exec $_.Execute -Args ([string]$_.Arguments)
        }
      } catch {
        # v1.70: 单任务异常(如 Actions 属性/执行路径无效)不拖垮整段, 跳过继续
        sf-deb ("[4/7] 任务异常跳过: " + $t.TaskName + " -> " + $_.Exception.GetType().Name + ": " + $_.Exception.Message)
      }
    }
  } else {
    # fallback: schtasks /query /v /fo list (Win7 无 ScheduledTasks 模块)
    $taskLines = @(schtasks /query /v /fo list 2>$null)
    $bName = ''; $bPath = ''; $bRun = ''
    foreach ($line in $taskLines) {
      $line = $line.Trim()
      if (-not $line) {
        if ($bName -and $bRun) {
          $bName = $bName.Trim('"')
          if ($bName -match '^\\Microsoft\\') { $bName=''; $bRun=''; continue }   # v1.42: 系统任务按任务名前缀排除
          $ex = $bRun; $ar = ''
          if ($bRun -match '^"([^"]+)"\s*(.*)$') { $ex = $Matches[1]; $ar = $Matches[2] }
          elseif ($bRun -match '^(\S+)\s*(.*)$') { $ex = $Matches[1]; $ar = $Matches[2] }
          Test-TaskEntry -TaskName $bName -TaskPath $bPath -Exec $ex -Args $ar
        }
        $bName=''; $bPath=''; $bRun=''
        continue
      }
      if ($line -match '^任务名:\s*(.+)$') { $bName = $Matches[1].Trim() }
      elseif ($line -match '^Task Name:\s*(.+)$') { $bName = $Matches[1].Trim() }
      elseif ($line -match '^Task To Run:\s*(.+)$') { $bRun = $Matches[1].Trim() }
      elseif ($line -match '^任务要运行:\s*(.+)$') { $bRun = $Matches[1].Trim() }
      elseif ($line -match '^要运行的任务:\s*(.+)$') { $bRun = $Matches[1].Trim() }   # v1.42: 中文 Win7 实际表头
    }
    if ($bName -and $bRun) {
      $ex = $bRun; $ar = ''
      if ($bRun -match '^"([^"]+)"\s*(.*)$') { $ex = $Matches[1]; $ar = $Matches[2] }
      elseif ($bRun -match '^(\S+)\s*(.*)$') { $ex = $Matches[1]; $ar = $Matches[2] }
      Test-TaskEntry -TaskName $bName -TaskPath $bPath -Exec $ex -Args $ar
    }
  }
  Add-Report ("  [统计] 非系统计划任务 " + $taskCount + " 个, 高危 " + $taskFlag + " 项, 待核实 " + $taskWarn + " 项")
} catch {
  Add-Report ("  (计划任务扫描异常: " + $_.Exception.GetType().Name + ": " + $_.Exception.Message + ")")
  sf-deb ("[4/7] 计划任务扫描异常: " + $_.Exception.GetType().Name + ": " + $_.Exception.Message)
}
Add-Report ""
# ===================== 5 服务 =====================
Add-Report "[5/7] 服务扫描"
Write-ScanProgress "[5/7] 服务扫描..."
try {
  $svcCount = 0; $svcFlag = 0; $svcWarn = 0
  Get-CimInstance Win32_Service | ForEach-Object {
    $svcCount++
    try {
      $pn = $_.PathName
      $svcPath = Get-ExecPath $pn
      # v1.53: 白名单/可信签名降噪 + 持久化评分 (替代旧裸正则, 减少误报)
      if (Test-Whitelist -Path $svcPath -Name (Split-Path $svcPath -Leaf)) { return }
      if (Test-TrustedSigner $svcPath) { return }
      $pr = Get-PersistRisk $svcPath $pn
      if ($pr.Signals.Count -gt 0) {
        $verdict = Get-RiskVerdict $pr.Signals
        $sigInfo = Get-SignatureStatus $pr.ExecClean
        $sigStr = if ($sigInfo.Signer) { ("签名=" + $sigInfo.Raw + "(" + $sigInfo.Signer + ")") } else { ("签名=" + $sigInfo.Raw) }
        $label = ("服务=" + $_.Name + " (状态=" + $_.State + ") -> " + $pn.Substring(0, [Math]::Min(180, $pn.Length)) + "  " + $sigStr)
        [void](Invoke-Verdict -Verdict $verdict -Label $label -Path $pr.ExecClean -QuarantineReason '服务' -NoQuarantine)
        if ($verdict.Verdict -eq 'THREAT') { $svcFlag++ } else { $svcWarn++ }
      }
    } catch {
      # v1.70: 单服务异常(PathName 无效/签名验证异常等)跳过, 不拖垮整段
      sf-deb ("[5/7] 服务异常跳过: " + $_.Name + " -> " + $_.Exception.GetType().Name + ": " + $_.Exception.Message)
    }
  }
  Add-Report ("  [统计] 服务 " + $svcCount + " 个, 高危 " + $svcFlag + " 项, 待核实 " + $svcWarn + " 项")
} catch {
  Add-Report ("  (服务扫描异常: " + $_.Exception.GetType().Name + ": " + $_.Exception.Message + ")")
  sf-deb ("[5/7] 服务扫描异常: " + $_.Exception.GetType().Name + ": " + $_.Exception.Message)
}
Add-Report ""

# ===================== 6 网络 + C2 =====================
Add-Report "[6/7] 可疑外部网络连接 / C2 命中"
Write-ScanProgress "[6/7] 可疑外部网络连接 / C2 命中检测..."
if ($Offline) {
  Add-Report "  [离线模式] 跳过网络连接扫描 (断网急救场景)"
} else {
try {
  $connCount = 0; $c2Hit = 0; $connOther = 0
  # v1.83: Win7 无 NetTCPIP 模块 -> netstat -ano 回退
  if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
      $_.RemoteAddress -notmatch '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|fe80)'
    }
  } else {
    $conns = @()
    $ns = @(netstat -ano 2>$null)
    foreach ($nl in $ns) {
      if ($nl -match 'TCP\s+\S+:\d+\s+([^:]+):\d+\s+ESTABLISHED\s+(\d+)') {
        $raddr = $Matches[1].Trim('[', ']')
        if ($raddr -notmatch '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|fe80)') {
          $conns += [pscustomobject]@{ RemoteAddress=$raddr; OwningProcess=[int]$Matches[2] }
        }
      }
    }
  }
  foreach ($c in $conns) {
    $connCount++
    if ($connCount -gt 50) { break }  # 限制长度
    $pid_ = $c.OwningProcess
    $proc = Get-Process -Id $pid_ -ErrorAction SilentlyContinue
    $ra = $c.RemoteAddress
    $procName = if ($proc) { $proc.Name } else { "?" }
    if ($c2IPs.ContainsKey($ra)) {
      $c2Hit++
      Flag ("  [C2 IP外联] " + $ra + ":" + $c.RemotePort + " <- " + $procName + " (PID " + $pid_ + ")")
      # v1.39: 自动封锁恶意程序网络 (C2 IP + 进程出站)
      if ($NetBlock) {
        try { Add-NetBlock -IP $ra -ProcessPath $(if($proc){$proc.Path}else{''}) -Reason 'C2 IP 外联' } catch {}
      }
    } else {
      # v2.15.33: 非 C2 外联降噪 —— 只统计, 不逐条列
      $connOther++
    }
  }
  if ($connCount -eq 0) { Add-Report "  (未发现外部连接或系统不支持)" }
  else {
    Add-Report ("  [统计] 外部连接 " + $connCount + " 条 (前50条), C2命中 " + $c2Hit + " 项")
    if ($connOther -gt 0) { Add-Report ("  [提示] 其余 " + $connOther + " 条为常规外连(浏览器/云服务等), 未列入可疑") }
  }
} catch { Add-Report "  (系统不支持 Get-NetTCPConnection，已跳过)" }
}
Add-Report ""

# ===================== 7 WMI =====================
Add-Report "[7/7] WMI 持久化事件扫描"
Write-ScanProgress "[7/7] WMI 持久化事件扫描..."
try {
  $wmiCount = 0; $wmiFlag = 0; $wmiWarn = 0
  $wmi = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
  if ($wmi) {
    foreach ($f in $wmi) {
      $wmiCount++
      $fname = [string]$f.Name
      $fquery = [string]$f.Query
      # v1.7: 排除微软官方筛选器 (如 SCM Event Log Filter 用于事件日志)
      if ($fname -match 'SCM Event Log|Microsoft|^BVT|NTDS|Netlogon|EventLog') { continue }
      # v1.53: 评分引擎. WMI 筛选器是监控类软件常建的中等风险信号, 默认降为待核实;
      #        仅当查询含下载执行特征(确证恶意)才升为威胁, 根除一刀切误报.
      $s = @{ WMI_FILTER = $RISK['WMI_FILTER'] }
      if ($fquery -match '(?i)downloadstring|invoke-webrequest|frombase64|mshta|bitsadmin|regsvr32|powershell.*-enc|-enc ') { $s['DL_EXEC_WEB'] = $RISK['DL_EXEC_WEB'] }
      $verdict = Get-RiskVerdict $s
      $label = ($fname + " : " + $fquery.Substring(0, [Math]::Min(150, $fquery.Length)))
      [void](Invoke-Verdict -Verdict $verdict -Label $label -Path '' -QuarantineReason 'WMI' -NoQuarantine)
      if ($verdict.Verdict -eq 'THREAT') { $wmiFlag++ } else { $wmiWarn++ }
    }
    Add-Report ("  [统计] WMI 筛选器 " + $wmiCount + " 个, 高危 " + $wmiFlag + " 项, 待核实 " + $wmiWarn + " 项")
  } else { Add-Report "  (未发现 WMI 事件筛选器)" }
} catch { Add-Report "  (WMI 扫描异常，已跳过)" }
Add-Report ""

# ===================== 汇总 =====================
Add-Report "=============================================="
Add-Report "检测结果汇总"
Add-Report "=============================================="
if ($susp.Count -eq 0) {
  Add-Report "未发现明显银狐木马特征项。仍建议配合专业杀软全盘扫描。"
} else {
  Add-Report ("共发现 " + $susp.Count + " 项可疑指标" + $(if($qcount -gt 0){"，已隔离 " + $qcount + " 个文件"}else{"，本次未自动隔离任何文件"}) + "。请人工核实：")
  $susp | ForEach-Object { Add-Report ("  - " + $_) }
  Add-Report ""
  Add-Report "处置建议："
  Add-Report "  1. 报告中的高危项请优先人工确认；确认恶意后自行删除/隔离。"
  Add-Report "  2. 如需自动隔离(仅高危特征): 运行  银狐木马检测.bat /quarantine"
  Add-Report "  3. 观察清单(非系统目录进程/随机名exe)仅作参考, 多数为正常软件。"
  Add-Report "  4. 清除对应自启动项 / 计划任务 / 服务 / WMI 事件 / C2 外联。"
  Add-Report "  5. 使用专业杀软全盘查杀并修改重要账户密码。"
}
if ($qcount -gt 0) { Add-Report ("隔离区: " + $qdir) }
Add-Report ""
Add-Report "免责声明：本工具基于公开已知特征与启发式规则，仅供辅助排查，不保证100%检出。默认不自动隔离文件；/quarantine 模式也仅处理明确高危特征。"
Add-Report ("报告路径: " + $log)
if (Test-Path -LiteralPath $obsFile) { Add-Report ("观察清单: " + $obsFile) }

# ===================== 8 证书信任链检查 (v1.84) =====================
Add-Report "[8] 证书信任链检查 (根证书/自签名)"
Write-ScanProgress "[8] 证书信任链检查..."
try { Invoke-CertCheck } catch { Add-Report ("  [证书] 检查异常: " + $_.Exception.Message) }
Add-Report ""

# ===================== 9 Defender 排除项检查 (v1.93) =====================
Add-Report "[9] Defender 排除项检查 (病毒加自身白名单让杀软失明)"
Write-ScanProgress "[9] Defender 排除项检查..."
try { Invoke-DefExclCheck } catch { Add-Report ("  [排除项] 检查异常: " + $_.Exception.Message) }
Add-Report ""

# ===================== 想法2: 交互确认 =====================
Write-ScanProgress ('扫描完成, 可疑指标 ' + $script:susp.Count + ' 项, 进入处理阶段...')
try { Ensure-Watchdog } catch {}   # v1.50: 交互前检查 watchdog 存活
# v1.43: 默认有文件类高危就弹交互菜单 (无需 /interactive).
#   /interactive -> 总是弹 (旧行为, 兼容)
#   /ask         -> 显式启用 (默认即开启, 此开关为冗余显式声明)
#   /noask       -> 关闭默认菜单, 全程静默 (用于无人值守 / 任务计划)
# v1.82: 交互条件放宽 —— 文件高危 或 其他可疑项(待核实/高危-自启动/任务/服务/命令行/WMI) 或 高危进程 都弹菜单引导
$hasFileHigh = @($script:susp | Where-Object { $_ -match '\[高危文件\]' }).Count -gt 0
$hasOther = @($script:susp | Where-Object { $_ -match '\[(待核实|高危)-(自启动|计划任务|服务|命令行|WMI|伪装系统进程)\]' }).Count -gt 0
$runInteractive = $Interactive -or ($AutoAsk -and ($hasFileHigh -or $hasOther -or ($script:threatProcs -and $script:threatProcs.Count -gt 0)))
if ($runInteractive) {
  try { Invoke-InteractiveConfirm | Out-Null } catch { Write-Host ("  [交互确认异常] " + $_.Exception.Message) -ForegroundColor Red }
}

# ===================== v1.36: 主扫描附加驱动审计 =====================
# 默认已加载驱动快速检查 (DriverStore 深度留给 /drivers 独立模式)
if (-not $Drivers) {
  try { Invoke-DriverAudit | Out-Null } catch { Write-Host ("  [驱动审计异常] " + $_.Exception.Message) -ForegroundColor Red }
}
try { Ensure-Watchdog } catch {}   # v1.50: 完成前检查 watchdog 存活
Write-Host ("`n检测完成：可疑指标 " + $susp.Count + " 项，已隔离 " + $qcount + " 个文件。")
Write-Host ("报告: " + $log)
if (Test-Path -LiteralPath $obsFile) { Write-Host ("观察清单: " + $obsFile) }
Write-ScanProgress ('检测完成: 可疑 ' + $script:susp.Count + ' 项, 已隔离 ' + $qcount + ' 个, 报告: ' + $log)
try { Start-Process notepad $log } catch {}

# v1.10: 统一受控退出 (写正常退出标记)
Exit-Tool -Code 0 -Reason ('检测完成, 可疑指标 ' + $susp.Count + ' 项')
