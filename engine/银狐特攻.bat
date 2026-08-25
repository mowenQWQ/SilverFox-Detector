@echo off
:: ============================================================
::  顽固木马扫描专杀-银狐特攻 v1.60 启动器 (GBK编码版) - 整合单入口
:: v2.15.16 交付修复: 引擎/UI ps1 单 BOM 重发布 (见修复报告)
:: v1.60 命名规范化 (v2.15.20): 对外名称统一「顽固木马扫描专杀-银狐特攻 (SilverFox Detector)」, 不再出现
::   "银狐木马 (SilverFox)" 式疑似病毒本体的自报名称; 同时修正全部 banner 版本漂移(v1.56->v1.60).
:: v1.59 修复结尾乱码 (v2.15.18): chcp 65001 后 bat 自身 GBK echo 中文被按 UTF-8 解码显示乱码;
::   本版移除 chcp 65001, 控制台保持系统默认 936, 引擎同步 936 输出 (v1.61), 前后编码一致.
:: v1.58 修复 UAC 提权失败 (v2.15.17): -Command "字符串" 模式下 $args 恒为 null (仅 scriptblock
::   形式才传参), Start-Process -ArgumentList $args 抛 ParameterBindingValidationException
::   (参数 Null/含 Null) -> 提权申请失败降级普通权限. 本版改为: 环境变量 SF_ELEV_ARGS 传递 %*,
::   PowerShell 内 -split 数组化, $a 恒为数组, 参数验证永不失败 (当前调用面参数均无空格).
:: v1.57 修复 9020 (v2.15.15): WindowsApps\pwsh.exe 是 PowerShell 7 的"应用执行别名",
::   在 Start-Process -Verb RunAs (UAC 提权)或 -File 调长路径/中文路径脚本时极易返回
::   9020 (系统无法执行指定的程序)。本版启动器改为:
::   1) 真实安装路径优先: C:\Program Files\PowerShell\7\pwsh.exe ->
::      C:\Program Files (x86)\PowerShell\7\pwsh.exe -> 系统 PS 5.1, 每个候选做
::      -Command "exit 0" 可执行验证;
::   2) PATH 搜索其次: 对 where pwsh / where powershell 命中逐个验证, 跳过 WindowsApps;
::   3) WindowsApps 别名仅最后兜底: 命中时记录警告 (may cause 9020 under UAC/RunAs);
::   4) 步骤 4 把 PowerShell 标准错误重定向到 sf_run.log, 便于诊断 9020/启动失败.
:: v2.14 修复: GUI_MODE 标题行 (原 line 382) 与 TOOL_DIAG 标题行 (原 line 586)
::   原写法: if "..." (echo   银狐木马 (SilverFox) 检测工具 ...) else (...)
::   CMD 解析器对 if-body 的 (echo ...) else (...) 做括号配对追踪时,
::   会把 echo 字符串内的 (SilverFox) 也当成新嵌套块起点, 配对错位,
::   立刻报 "此时不应有 检测工具。" 并退出 (整个 bat 一行 banner 后就关).
::   现象: GUI 点 "启动银狐特攻扫描" 或 "系统诊断" 后 bat 弹窗报错闪退.
::   修复: (SilverFox)/(集成模式) 改为 [SilverFox]/[集成模式] (方括号对
::   CMD 解析器无特殊含义, 纯字面量). 同时清理历史 CR-CR-LF 行尾残渣.
::  想法11: 根目录只留本入口, 子工具通过参数调用:
::    /restore 恢复隔离文件  /purge 清理隔离区  /rollback 回滚恢复
::    /clearcache 清哈希缓存  /diag 诊断  /update 更新IOC库
::  (旧独立 bat 已归档到 bin\_legacy_bat\)
:: ============================================================
:: v1.50 自查修复:
::   1) PowerShell 查找: 加 PATH 搜索 (where powershell / where pwsh) + WindowsApps + Scoop
::   2) 每个候选路径验证可执行性 (实际执行 -Version 探针, 失败不算数)
::   3) 下载流程加文件大小校验 + errorlevel 双校验
::   4) PS_EXE 为空时强制 pause 退出 (避免后续步骤触发 "Windows 找不到文件 -NoProfile")
::   5) banner 同步到 v1.50 (之前显示 v1.42 但引擎是 v1.50, 用户混淆)
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

:: ---- v1.56: 系统语言检测 (默认系统语言为主, 未知回退英文) ----
:: ---- v1.56: detect system UI language (system first, fall back to English) ----
for /f "delims=" %%L in ('powershell -NoProfile -Command "(Get-Culture).Name" 2^>nul') do set "SF_LANG=%%L"
if not defined SF_LANG set "SF_LANG=en"
echo %SF_LANG% | findstr /i "zh" >nul && (set "SF_LANG=zh") || (set "SF_LANG=en")

>  "%~dp0sf_run.log" echo === 银狐特攻扫描 v1.60 ===
>> "%~dp0sf_run.log" echo 时间: %DATE% %TIME%
>> "%~dp0sf_run.log" echo 路径: %~dp0
>> "%~dp0sf_run.log" echo 用户: %USERNAME%
>> "%~dp0sf_run.log" echo 参数: %*
>> "%~dp0sf_run.log" echo 命令行: %CMDCMDLINE%

:: ---------- 想法11: 子工具参数分派 (整合单入口) ----------
:: 子工具模式: 跳过检测 banner 和"按任意键开始检测", 直接进入对应工具
set "SF_TOOL="
if /i "%~1"=="/restore"     set "SF_TOOL=restore"
if /i "%~1"=="-restore"     set "SF_TOOL=restore"
if /i "%~1"=="/purge"       set "SF_TOOL=purge"
if /i "%~1"=="-purge"       set "SF_TOOL=purge"
if /i "%~1"=="/rollback"    set "SF_TOOL=rollback"
if /i "%~1"=="-rollback"    set "SF_TOOL=rollback"
if /i "%~1"=="/clearcache"  set "SF_TOOL=clearcache"
if /i "%~1"=="-clearcache"  set "SF_TOOL=clearcache"
if /i "%~1"=="/diag"        set "SF_TOOL=diag"
if /i "%~1"=="/restoreav"  set "SF_TOOL=restoreav"
if /i "%~1"=="/netblock"   set "SF_TOOL=netblock"
if /i "%~1"=="-diag"        set "SF_TOOL=diag"
if /i "%~1"=="/update"      set "SF_TOOL=update"
if /i "%~1"=="-update"      set "SF_TOOL=update"
if defined SF_TOOL goto TOOL_MODE
:: v1.50: 无参数双击 -> 直接弹 GUI (老 CLI 流程在带参数时保留)
if "%~1"=="" goto GUI_MODE

echo.
if "%SF_LANG%"=="zh" goto BANNER_ZH
echo ============================================================
echo   顽固木马扫描专杀-银狐特攻 (SilverFox Detector)  v1.60
echo ============================================================
echo   Work dir : %~dp0
echo   Started  : %DATE% %TIME%
echo   User     : %USERNAME%
echo ============================================================
echo   Params : /full full scan  /quarantine auto-quarantine  /zerotrust zero-trust (scan tool dir too)
echo            /safe safe-mode first-aid  /offline offline first-aid  /interactive confirm  /ring0 delete  /update update IOC
echo            /immune system immunity (files/Hosts/boot)  /repair repair (hosts/DNS/proxy/Winsock)
echo            /trace SilverFox change tracking  /rebuild rebuild baseline  /drivers driver signature audit  /unlock unlock list  /netblock network block  /noshutdownguard disable shutdown guard
echo            /restore restore quarantined  /purge purge  /rollback rollback  /clearcache clear cache  /diag diagnose  /mem memory scan
echo            /extremeprotect kernel protect paused (source in bin/)  /resetextreme clear legacy extreme flag
echo            /lang=en^|zh force UI language (default follows system)
echo ============================================================
goto BANNER_DONE
:BANNER_ZH
echo ============================================================
echo   顽固木马扫描专杀-银狐特攻 (SilverFox Detector)  v1.60
echo ============================================================
echo   工作目录 : %~dp0
echo   开始时间 : %DATE% %TIME%
echo   当前用户 : %USERNAME%
echo ============================================================
echo   参数   : /full 全盘  /quarantine 自动隔离  /zerotrust 零信任(工具目录自身也检测)
echo             /safe 安全模式急救  /offline 离线断网急救  /interactive 交互确认  /ring0 删除  /update 更新IOC库
echo             /immune 系统免疫(文件/Hosts/开机)  /repair 修复(hosts/DNS/代理/Winsock)
echo             /trace 银狐修改追踪  /rebuild 重建免疫基线  /drivers 驱动签名审计(含手动删除)  /unlock 解锁清单  /netblock 网络封锁管理  /noshutdownguard 关闭关机拦截
echo             /restore 恢复隔离文件  /purge 清理隔离区  /rollback 回滚恢复  /clearcache 清哈希缓存  /diag 诊断  /mem 内存检测
echo             /extremeprotect 内核保护已暂停(源码保留bin/)  /resetextreme 清除历史极端态标志
echo ============================================================
echo.
:BANNER_DONE

if "%SF_LANG%"=="zh" (echo 按任意键开始检测... 关闭窗口可取消) else (echo Press any key to start... close window to cancel)
pause >nul
>> "%~dp0sf_run.log" echo [步骤] 用户已确认, 开始检测

:: ---------- 步骤 1: 检查引擎文件 ----------
echo.
echo [步骤 1/5] 检查引擎文件 SilverFoxDetect.ps1 ...
if not exist "%~dp0bin\SilverFoxDetect.ps1" goto PS1_MISSING
echo   [OK] 引擎文件存在
>> "%~dp0sf_run.log" echo [步骤1] OK ps1 存在
goto STEP1_DONE

:PS1_MISSING
echo   [错误] 未找到 SilverFoxDetect.ps1
echo   请把 .bat 和 .ps1 放在同一目录!
>> "%~dp0sf_run.log" echo [步骤1] 失败: ps1 缺失
echo.
echo 按任意键关闭窗口...
pause >nul
endlocal & exit /b 2

:STEP1_DONE

:: ---------- 步骤 2: 查找 PowerShell (v1.57 真实安装路径优先 + 逐个可执行验证) ----------
:: v1.57 修复 9020: PATH 里的 WindowsApps\pwsh.exe 是"应用执行别名"(非 pwsh 本体), UAC 提权
::   (-Verb RunAs)或 -File 调长路径/中文路径脚本时极易返回 9020 (系统无法执行指定的程序)。
::   优先顺序: 1) 真实安装路径(官方 7 + 系统 5.1, 逐个 -Command "exit 0" 验证)
::             2) PATH 搜索(跳过 WindowsApps 命中, 同样逐个验证)
::             3) WindowsApps 别名仅最后兜底(命中记 9020 风险警告)
echo.
echo [步骤 2/5] 检查 PowerShell (真实安装路径优先, PATH 其次, WindowsApps 兜底) ...
set "PS_EXE="
:: 1) 真实安装路径优先 (v1.57): 官方 PowerShell 7 MSI 位置 + 系统自带 5.1, 逐个可执行验证
for %%P in ("C:\Program Files\PowerShell\7\pwsh.exe" "C:\Program Files (x86)\PowerShell\7\pwsh.exe" "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" "%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe") do (
    if not defined PS_EXE if exist "%%~P" (
        set "PS_EXE=%%~P"
        call :PS_VALIDATE
    )
)
:: 2) PATH 搜索其次 (v1.57): scoop/choco/dotnet tool 安装的 pwsh 会在 PATH; 跳过 WindowsApps 别名(9020 元凶)
if not defined PS_EXE for /f "delims=" %%P in ('where pwsh 2^>nul') do (
    if not defined PS_EXE if exist "%%P" (
        set "P_CAND=%%~P"
        set "P_CHK=!P_CAND:WindowsApps=!"
        if /i "!P_CHK!"=="!P_CAND!" (
            set "PS_EXE=!P_CAND!"
            call :PS_VALIDATE
        )
    )
)
if not defined PS_EXE for /f "delims=" %%P in ('where powershell 2^>nul') do (
    if not defined PS_EXE if exist "%%P" (
        set "P_CAND=%%~P"
        set "P_CHK=!P_CAND:WindowsApps=!"
        if /i "!P_CHK!"=="!P_CAND!" (
            set "PS_EXE=!P_CAND!"
            call :PS_VALIDATE
        )
    )
)
:: 3) WindowsApps 别名仅最后兜底 (v1.57): 能用但 UAC/RunAs 下可能 9020, 记录警告供远程诊断
if not defined PS_EXE if exist "%LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe" (
    set "PS_EXE=%LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe"
    call :PS_VALIDATE
)
:: v1.57: 命中 WindowsApps 别名时显式告警 (console + 日志)
if defined PS_EXE (
    set "P_CHK2=!PS_EXE:WindowsApps=!"
    if /i not "!P_CHK2!"=="!PS_EXE!" (
        echo   [警告] 命中 WindowsApps 应用执行别名 [非 pwsh 本体], UAC 提权下可能返回 9020
        echo   [警告] 建议安装官方 PowerShell 7: https://aka.ms/powershell
        >> "%~dp0sf_run.log" echo [步骤2] 警告: PS 为 WindowsApps 别名 [may cause 9020 under UAC/RunAs]: !PS_EXE!
    )
)
if defined PS_EXE goto PS_FOUND
goto PS_MISSING

:: ---- v1.57 子程序: PS 候选可执行验证 (-Command "exit 0" 探针, 失败清空 PS_EXE) ----
:PS_VALIDATE
if not defined PS_EXE goto :eof
"%PS_EXE%" -NoProfile -Command "exit 0" >nul 2>&1
if errorlevel 1 set "PS_EXE="
goto :eof

:PS_FOUND
echo   [OK] 找到 PowerShell: %PS_EXE%
>> "%~dp0sf_run.log" echo [步骤2] PS: %PS_EXE%
:: v1.11: 用临时文件方式取版本号, 避免 for /f + 反引号 + 双引号嵌套解析错误
"%PS_EXE%" -NoProfile -Command "Set-Content -Path $env:TEMP\sf_psver.txt -Value $PSVersionTable.PSVersion.ToString()" 2>nul
if exist "%TEMP%\sf_psver.txt" (
    set /p PSVER=<"%TEMP%\sf_psver.txt"
    del /q "%TEMP%\sf_psver.txt" >nul 2>&1
    echo   PowerShell 版本: !PSVER!
) else (
    echo   [警告] 无法查询 PowerShell 版本, 但已找到引擎, 继续
)
goto STEP2_DONE

:PS_MISSING
echo   [错误] 未找到任何 PowerShell (PATH + 常见安装位置 + WindowsApps 全部失败)
echo.
echo   ============================================================
echo   [自查反馈 v1.50] bat 早期版本只有 4 个固定路径, 现已扩展到:
echo     - PATH 搜索 (where powershell / where pwsh)
echo     - 系统自带 5.1 + 官方 PowerShell 7 (常见安装位置)
echo     - WindowsApps (Win11 微软商店版)
echo     - 实际可执行验证 (避免假阳性)
echo   若仍报此错, 说明本机确实无任何 PowerShell, 请:
echo     1. 打开 https://aka.ms/powershell 下载 PowerShell-7.x-win-x64.msi
echo     2. 或安装 Windows 自带功能: 控制面板 - 程序 - 启用或关闭 Windows 功能 - Windows PowerShell
echo   ============================================================
echo   尝试自动安装 PowerShell 7 ...
set "PS_AUTO=0"
:: 方式1: winget
where winget >nul 2>&1
if errorlevel 1 goto SG_NO_WINGET
echo   [安装] 使用 winget 安装 PowerShell 7 ...
winget install --id Microsoft.PowerShell -e --accept-source-agreements --accept-package-agreements >nul 2>&1
if exist "%ProgramFiles%\PowerShell\7\pwsh.exe" set "PS_EXE=%ProgramFiles%\PowerShell\7\pwsh.exe"
if exist "%LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe" set "PS_EXE=%LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe"
if defined PS_EXE set "PS_AUTO=1"
if defined PS_EXE goto SG_INSTALL_OK
:SG_NO_WINGET
:: 方式2: 下载 MSI (winget 失败时; v1.34 清华镜像优先, GitHub 兜底)
:: 有系统自带 5.1 时用 PowerShell 下载(带超时); 无 5.1 时用 certutil 下载(不依赖 PowerShell)
if defined PS_EXE goto SG_INSTALL_OK
echo   [安装] winget 不可用或失败, 尝试下载 PowerShell 7 MSI ...
if exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" goto SG_DL_PS5
:: 无 PowerShell: certutil 兜底 (清华镜像 -> GitHub) - v1.50: 加文件大小校验 + errorlevel 双校验
echo   [下载] certutil 清华镜像 ...
set "RC="
certutil -urlcache -split -f "https://mirrors.tuna.tsinghua.edu.cn/github-release/PowerShell/PowerShell/LatestRelease/PowerShell-7.6.5-win-x64.msi" "%TEMP%\pwsh_setup.msi" >nul 2>&1
if not errorlevel 1 (
    if exist "%TEMP%\pwsh_setup.msi" for %%S in ("%TEMP%\pwsh_setup.msi") do if %%~zS LSS 1000000 set "RC=BAD"
    if defined RC goto SG_DL_PS5_GITHUB
    goto SG_MSI_INSTALL
)
:SG_DL_PS5_GITHUB
echo   [下载] certutil 清华镜像失败或文件异常, 切换 GitHub ...
del /q "%TEMP%\pwsh_setup.msi" >nul 2>&1
set "RC="
certutil -urlcache -split -f "https://github.com/PowerShell/PowerShell/releases/download/v7.6.5/PowerShell-7.6.5-win-x64.msi" "%TEMP%\pwsh_setup.msi" >nul 2>&1
if not errorlevel 1 (
    if exist "%TEMP%\pwsh_setup.msi" for %%S in ("%TEMP%\pwsh_setup.msi") do if %%~zS LSS 1000000 set "RC=BAD"
    if defined RC goto SG_DL_FAIL
    goto SG_MSI_INSTALL
)
goto SG_DL_FAIL
:SG_DL_PS5
:: 有 5.1: PowerShell 下载 (清华镜像 15s 超时 -> GitHub 20s 超时) - v1.50: 加文件大小校验
echo   [下载] 清华镜像 (15s 超时) ...
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://mirrors.tuna.tsinghua.edu.cn/github-release/PowerShell/PowerShell/LatestRelease/PowerShell-7.6.5-win-x64.msi' -OutFile \"$env:TEMP\pwsh_setup.msi\" -UseBasicParsing -TimeoutSec 15; if ((Get-Item \"$env:TEMP\pwsh_setup.msi\" -ErrorAction SilentlyContinue).Length -lt 1000000) { exit 1 }; exit 0 } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 goto SG_MSI_INSTALL
echo   [下载] 清华镜像失败或超时, 切换 GitHub (20s 超时) ...
del /q "%TEMP%\pwsh_setup.msi" >nul 2>&1
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://github.com/PowerShell/PowerShell/releases/download/v7.6.5/PowerShell-7.6.5-win-x64.msi' -OutFile \"$env:TEMP\pwsh_setup.msi\" -UseBasicParsing -TimeoutSec 20; if ((Get-Item \"$env:TEMP\pwsh_setup.msi\" -ErrorAction SilentlyContinue).Length -lt 1000000) { exit 1 }; exit 0 } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 goto SG_MSI_INSTALL
:SG_DL_FAIL
echo   [失败] 两个下载源均失败或超时
goto SG_MSI_DONE
:SG_MSI_INSTALL
if not exist "%TEMP%\pwsh_setup.msi" goto SG_DL_FAIL
echo   [安装] 静默安装 MSI (无需交互) ...
start /wait "" msiexec /i "%TEMP%\pwsh_setup.msi" /qn /norestart >nul 2>&1
:SG_MSI_DONE
if exist "%ProgramFiles%\PowerShell\7\pwsh.exe" set "PS_EXE=%ProgramFiles%\PowerShell\7\pwsh.exe"
if defined PS_EXE set "PS_AUTO=1"
if defined PS_EXE goto SG_INSTALL_OK
echo.
echo   [提示] 自动安装未成功 (下载超时或网络受限)。
echo   一般 Windows 系统自带 Windows PowerShell 5.1, 本工具兼容 5.1 可直接使用;
echo   如需完整功能, 可手动安装 PowerShell 7:
echo     1. 打开 https://aka.ms/powershell
echo     2. 下载并运行 PowerShell-7.x-win-x64.msi
echo     3. 重跑本脚本
goto STEP2_DONE
:SG_INSTALL_OK
echo   [OK] PowerShell 7 安装成功: %PS_EXE%
goto PS_FOUND
:STEP2_DONE
:: v1.50 自查修复: 强制断言 PS_EXE 非空, 避免后续 "%PS_EXE% -NoProfile" 触发 "Windows 找不到文件 -NoProfile"
if not defined PS_EXE goto FATAL_NO_PS
goto STEP3
:FATAL_NO_PS
echo.
echo   ============================================================
if "%SF_LANG%"=="zh" (echo   [FATAL] 未找到任何可用的 PowerShell, 无法继续) else (echo   [FATAL] No usable PowerShell found; cannot continue)
echo   ============================================================
echo   排查建议:
echo     1. 确认系统不是精简版 (LTSC/Server Core 等可能无 PS):
echo        控制面板 - 程序 - 启用或关闭 Windows 功能 - Windows PowerShell
echo     2. 手动安装 PowerShell 7: https://aka.ms/powershell
echo     3. 把 PowerShell 路径加到 PATH, 或用 scoop install pwsh
echo   ============================================================
>> "%~dp0sf_run.log" echo [FATAL] PS_EXE 未找到, 退出
echo.
echo 按任意键关闭窗口...
pause >nul
endlocal & exit /b 4
:STEP3

:: ---------- 步骤 3: 管理员权限 (现在可以用绝对路径申请 UAC) ----------
echo.
echo [步骤 3/5] 检查管理员权限 ...
net session >nul 2>&1
if errorlevel 1 goto NOT_ADMIN

echo   [OK] 管理员权限, 全部扫描项可用
>> "%~dp0sf_run.log" echo [步骤3] 管理员
goto ADMIN_DONE

:NOT_ADMIN
echo   [提示] 当前为普通权限, HKLM/服务扫描项将受限
echo.
echo   是否申请管理员权限?
echo   Y = 是, 弹出 UAC 申请
echo   N = 否, 以普通权限继续
echo.
set /p "UAC_CHOICE=请输入 Y 或 N, 直接回车默认 N: "
if /i "!UAC_CHOICE!"=="Y" goto TRY_UAC
echo   [提示] 以普通权限继续, 部分扫描项受限
>> "%~dp0sf_run.log" echo [步骤3] 普通权限继续
goto ADMIN_DONE

:TRY_UAC
echo   正在申请管理员权限, 会弹出 UAC 对话框...
>> "%~dp0sf_run.log" echo [步骤3] 尝试 UAC 申请
:: v2.15.3 修复: 原写法把 %* 拼成单个字符串传给 -ArgumentList, 导致 elevated 实例只收到一个合并参数,
::   引擎模式丢失 (/repair 等失效). 曾改为: 把 %* 作为 -Command 尾部参数, 期望 PowerShell $args 为数组 ——
::   但实测 -Command "字符串" 模式下 $args 恒为 null (v2.15.17 修复, 见 v1.58 说明).
set "SF_ELEV_ARGS=%*"
:: v1.58 补充: Start-Process -ArgumentList 不接受空集合(@() 也报 "为 Null、为空") —— 空参时省略 -ArgumentList.
"%PS_EXE%" -NoProfile -Command "$a=@(); if ($env:SF_ELEV_ARGS) { $a = $env:SF_ELEV_ARGS -split ' ' }; if ($a.Count -gt 0) { Start-Process -FilePath '%~f0' -ArgumentList $a -WorkingDirectory '%~dp0' -Verb RunAs } else { Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs }"
if errorlevel 1 goto UAC_FAIL
echo   已尝试申请管理员权限, 请在新窗口中继续操作
echo   此窗口可关闭
echo.
echo 按任意键关闭此窗口...
pause >nul
endlocal & exit /b 0

:UAC_FAIL
echo   [提示] 自动申请失败, UAC 拒绝或系统不支持
echo   建议关闭后右键本 bat 选择以管理员身份运行
echo   现在将以普通权限继续, 部分扫描受限
>> "%~dp0sf_run.log" echo [步骤3] UAC 失败, 降级
goto ADMIN_DONE

:ADMIN_DONE

:: ---------- 步骤 4: 运行引擎 (用绝对路径) ----------
echo.
echo [步骤 4/5] 启动检测引擎, 可能需要 10-60 秒, 请耐心等待...
echo   引擎日志: %USERPROFILE%\sf_debug.log
>> "%~dp0sf_run.log" echo [步骤4] 调用: %PS_EXE%
set "SF_TOOLROOT=%~dp0"
:: v2.15.8 安全整改: 原实现用 -Command 把 %* 直接拼进 PowerShell 命令字符串(命令行注入面:
::   若调用方传入含 PowerShell 元字符的参数, 会执行任意代码). 改为 -File 调用 —— -File 模式
::   把后续参数当作字面量参数(不解析为 PowerShell 代码), 引擎仍通过 $args 收到同样的参数,
::   功能等价但彻底消除注入。SF_LANG 仅为受控的 zh/en, 亦作为字面量传入。
:: v1.57: stderr 捕获 —— PowerShell 标准错误追加到 sf_run.log (stdout 仍走控制台保证交互菜单),
::   便于远程诊断 9020 / 引擎启动失败 (报错原文会落在日志里)
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%SF_TOOLROOT%bin\SilverFoxDetect.ps1" %* /lang=%SF_LANG% 2>> "%~dp0sf_run.log"
set "PS_RC=%errorlevel%"
>> "%~dp0sf_run.log" echo [步骤4] PowerShell 退出码: %PS_RC%

:: ---------- 步骤 4.5: 检查受控退出标记 (v1.11 加密版) ----------
::   引擎正常结束时会在 %TEMP% 写 sf_exit_<PID>_<nonce>.flag (XOR 加密, 含 PID/时间/原因),
::   bat 调用 Verify-ExitFlag.ps1 验签; 若验证失败 = 标记被伪造或引擎异常
set "SF_NORMAL_EXIT=NO"
set "SF_FLAG_INFO=未验证"
if not exist "%~dp0bin\Verify-ExitFlag.ps1" (
    echo   [警告] 未找到 Verify-ExitFlag.ps1, 跳过验签(只看标记是否存在)
    dir /b "%TEMP%\sf_exit_*.flag" >nul 2>&1 && (set "SF_NORMAL_EXIT=YES") || (set "SF_NORMAL_EXIT=NO")
) else (
    :: v1.42: 用临时文件捕获输出+退出码
    :: (for /f 循环体末尾 set 会覆盖 errorlevel, 导致验签恒"签名有效")
    set "SF_FLAG_INFO="
    set "SF_FLAG_RC=999"
    "%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0bin\Verify-ExitFlag.ps1" > "%TEMP%\sf_verify.txt" 2>nul
    set "SF_FLAG_RC=!errorlevel!"
    if exist "%TEMP%\sf_verify.txt" (
        set /p "SF_FLAG_INFO="<"%TEMP%\sf_verify.txt"
        del /q "%TEMP%\sf_verify.txt" >nul 2>&1
    )
    if "!SF_FLAG_RC!" neq "0" (
        echo   [警告] 退出标记验证失败 rc=!SF_FLAG_RC! (上次标记可能已清理, 状态未知)
        set "SF_NORMAL_EXIT=NO"
    ) else (
        echo   [OK] 引擎受控退出 (签名有效): !SF_FLAG_INFO!
        set "SF_NORMAL_EXIT=YES"
    )
    :: 验证后再清理 (保留证据给用户查看 sf_flag logs)
    if exist "%TEMP%\sf_exit_*.flag" del /q "%TEMP%\sf_exit_*.flag" >nul 2>&1
)
>> "%~dp0sf_run.log" echo [步骤4.5] 受控退出: %SF_NORMAL_EXIT%  %SF_FLAG_INFO%
if "%SF_NORMAL_EXIT%"=="YES" (
    echo   详细信息: %SF_FLAG_INFO%
) else (
    echo   请检查 %USERPROFILE%\sf_debug.log 最后几行
)

:: ---------- 步骤 5: 结果 ----------
echo.
echo [步骤 5/5] 检测完成, PowerShell 退出码: %PS_RC%
echo.
if exist "%~dp0银狐特攻扫描报告_*.txt" goto REPORT_EXISTS
echo [提示] 工具根目录下未发现报告文件
echo 请检查 %USERPROFILE%\sf_debug.log 和 "%~dp0sf_run.log"
goto DONE

:REPORT_EXISTS
echo 工具根目录下的最新报告:
dir /b "%~dp0银狐特攻扫描报告_*.txt" 2>nul
goto DONE

:DONE
echo.
echo ============================================================
echo   全部完成
echo ============================================================
echo 按任意键关闭窗口...
pause >nul
endlocal & exit /b %PS_RC%

:: ===================== v1.50: GUI 模式 (无参数双击入口) =====================
:GUI_MODE
echo.
echo ============================================================
if "%SF_LANG%"=="zh" (echo   顽固木马扫描专杀-银狐特攻 [SilverFox Detector]  v1.60 - 图形模式) else (echo   SilverFox Detector v1.60 - GUI mode)
echo ============================================================
set "GUI_PS_EXE="
for /f "delims=" %%P in ('where pwsh 2^>nul') do (
    if not defined GUI_PS_EXE if exist "%%P" set "GUI_PS_EXE=%%P"
)
if not defined GUI_PS_EXE for /f "delims=" %%P in ('where powershell 2^>nul') do (
    if not defined GUI_PS_EXE if exist "%%P" set "GUI_PS_EXE=%%P"
)
if not defined GUI_PS_EXE if exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" set "GUI_PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not defined GUI_PS_EXE if exist "%LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe" set "GUI_PS_EXE=%LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe"
if not defined GUI_PS_EXE (
    echo   [错误] 未找到 PowerShell, 无法启动图形界面
    echo   请运行: 银狐特攻扫描.bat /diag 查看诊断信息
    echo.
    pause
    exit /b 1
)
"%GUI_PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0bin\SilverFoxUI.ps1"
endlocal & exit /b 0

:: ===================== 想法11: 子工具集成模式 =====================
:: 子工具通过主入口参数调用 (旧独立 bat 已归档 bin\_legacy_bat\)
:TOOL_MODE
:: v2.15.4 修复: 子工具模式(含 /diag)由 arg 解析处直接 goto 进来, 跳过了主流程 STEP2 的
:: PowerShell 查找, 导致 PS_EXE 未定义 -> /diag 误报 "PowerShell not found". 入口统一兜底查找一次.
call :ENSURE_PS
if "%SF_TOOL%"=="diag" goto TOOL_DIAG
if "%SF_TOOL%"=="restoreav" goto TOOL_RESTOREAV
if "%SF_TOOL%"=="netblock"  goto TOOL_NETBLOCK
echo.
echo ============================================================
if "%SF_TOOL%"=="restore"    echo   银狐木马隔离文件恢复工具 (集成)
if "%SF_TOOL%"=="purge"      echo   银狐木马隔离区清理工具 (集成)
if "%SF_TOOL%"=="rollback"   echo   银狐木马回滚恢复工具 (集成)
if "%SF_TOOL%"=="clearcache" echo   银狐木马哈希缓存清理工具 (集成)
if "%SF_TOOL%"=="update"     echo   银狐木马 IOC 库更新 (集成)
echo ============================================================
>> "%~dp0sf_run.log" echo [子工具] %SF_TOOL% 模式
set "SF_SCRIPT=Restore.ps1"
if "%SF_TOOL%"=="purge" set "SF_SCRIPT=Purge.ps1"
if "%SF_TOOL%"=="rollback" set "SF_SCRIPT=Rollback.ps1"

:: ---------- 脚本存在检查 ----------
if "%SF_TOOL%"=="clearcache" goto TOOL_CK_CC
if "%SF_TOOL%"=="update" goto TOOL_CK_ENGINE
if not exist "%~dp0bin\%SF_SCRIPT%" goto TOOL_SCRIPT_MISSING
goto TOOL_CK_OK
:TOOL_CK_ENGINE
if not exist "%~dp0bin\SilverFoxDetect.ps1" goto TOOL_PS1_MISSING
goto TOOL_CK_OK
:TOOL_CK_CC
if not exist "%~dp0bin\Clear-Cache.ps1" goto TOOL_CC_MISSING
:TOOL_CK_OK

:: ---------- 查找 PowerShell (独立标签, 不干扰主流程; v1.50 与主流程一致的搜索策略) ----------
echo.
echo   正在查找 PowerShell ...
set "PS_EXE="
:: 1) PATH 搜索
for /f "delims=" %%P in ('where pwsh 2^>nul') do (
    if not defined PS_EXE if exist "%%P" set "PS_EXE=%%P"
)
if not defined PS_EXE for /f "delims=" %%P in ('where powershell 2^>nul') do (
    if not defined PS_EXE if exist "%%P" set "PS_EXE=%%P"
)
:: 2) 常见安装位置
set "PS_PATHS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe;%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe;C:\Program Files\PowerShell\7\pwsh.exe;C:\Program Files (x86)\PowerShell\7\pwsh.exe"
for %%P in ("%PS_PATHS:;=" "%") do (
    if not defined PS_EXE if exist "%%~P" set "PS_EXE=%%~P"
)
:: 3) WindowsApps
if not defined PS_EXE if exist "%LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe" set "PS_EXE=%LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe"
:: 4) 可执行验证
if defined PS_EXE (
    "%PS_EXE%" -NoProfile -Command "$null" 2>nul
    if errorlevel 1 set "PS_EXE="
)
if defined PS_EXE goto TOOL_PS_FOUND
goto TOOL_PS_FAIL

:TOOL_PS_FOUND
echo   [OK] PowerShell: %PS_EXE%
goto TOOL_ADMIN

:TOOL_PS_FAIL
echo   [错误] 未找到任何 PowerShell!
echo   请确认已安装 Windows PowerShell 5.x 或 PowerShell 7, 或参考主流程提示手动安装
echo.
echo 按任意键关闭窗口...
pause >nul
endlocal & exit /b 3

:TOOL_PS1_MISSING
echo   [错误] 未找到 bin\SilverFoxDetect.ps1
echo   请把本 bat 和 bin 目录放在同一目录!
echo.
echo 按任意键关闭窗口...
pause >nul
endlocal & exit /b 2

:TOOL_CC_MISSING
echo   [错误] 未找到 bin\Clear-Cache.ps1
echo   请把本 bat 和 bin 目录放在同一目录!
echo.
echo 按任意键关闭窗口...
pause >nul
endlocal & exit /b 2

:TOOL_SCRIPT_MISSING
echo   [错误] 未找到 bin\%SF_SCRIPT%
echo   请把本 bat 和 bin 目录放在同一目录!
echo.
echo 按任意键关闭窗口...
pause >nul
endlocal & exit /b 2

:: ---------- 管理员权限 (restore/purge/rollback/update 需要; clearcache 不需要) ----------
:TOOL_ADMIN
if "%SF_TOOL%"=="clearcache" goto TOOL_START
net session >nul 2>&1
if errorlevel 1 goto TOOL_NOT_ADMIN
echo   [OK] 管理员权限
goto TOOL_START

:TOOL_NOT_ADMIN
echo   [提示] 当前为普通权限, 恢复/清理系统目录文件可能需要管理员权限!
echo.
echo   是否申请管理员权限?
echo   Y = 是, 弹出 UAC 申请 (会以管理员身份重跑本工具并带当前参数)
echo   N = 否, 以普通权限继续
echo.
set /p "UAC_CHOICE=请输入 Y 或 N, 直接回车默认 N: "
if /i "!UAC_CHOICE!"=="Y" goto TOOL_TRY_UAC
echo   [提示] 以普通权限继续, 部分操作可能失败
goto TOOL_START

:TOOL_TRY_UAC
set "SF_UAC_ARG=/restore"
if "%SF_TOOL%"=="purge" set "SF_UAC_ARG=/purge"
if "%SF_TOOL%"=="rollback" set "SF_UAC_ARG=/rollback"
if "%SF_TOOL%"=="update" set "SF_UAC_ARG=/update"
echo   正在申请管理员权限, 会弹出 UAC 对话框...
"%PS_EXE%" -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList $env:SF_UAC_ARG -Verb RunAs" 2>nul
if errorlevel 1 goto TOOL_UAC_FAIL
echo   已尝试申请管理员权限, 请在新窗口中继续操作
echo   此窗口可关闭
echo.
echo 按任意键关闭此窗口...
pause >nul
endlocal & exit /b 0

:TOOL_UAC_FAIL
echo   [提示] 自动申请失败, UAC 拒绝或系统不支持
echo   建议关闭后右键本 bat 选择以管理员身份运行
echo   现在将以普通权限继续
goto TOOL_START

:: ---------- 调用 (restore/purge/rollback -> 子脚本; clearcache -> Clear-Cache; update -> 引擎) ----------
:TOOL_START
echo.
echo 按任意键开始... 关闭窗口可取消
pause >nul
>> "%~dp0sf_run.log" echo [子工具] 开始执行 %SF_TOOL%
set "SF_TOOLROOT=%~dp0"
:: v1.50 自查修复: 改用延迟展开 !SF_EXTRA! 累加 (避免 %SF_EXTRA% 在某些 cmd 行为下取旧值)
:: 同时加引号转义防参数含 & | < > 等特殊字符破坏 PS 解析
set "SF_EXTRA="
if not "%~2"=="" for %%A in ("%~2") do set "SF_EXTRA=!SF_EXTRA! %%~A"
if not "%~3"=="" for %%A in ("%~3") do set "SF_EXTRA=!SF_EXTRA! %%~A"
if not "%~4"=="" for %%A in ("%~4") do set "SF_EXTRA=!SF_EXTRA! %%~A"
if not "%~5"=="" for %%A in ("%~5") do set "SF_EXTRA=!SF_EXTRA! %%~A"
if not "%~6"=="" for %%A in ("%~6") do set "SF_EXTRA=!SF_EXTRA! %%~A"
if not "%~7"=="" for %%A in ("%~7") do set "SF_EXTRA=!SF_EXTRA! %%~A"
if not "%~8"=="" for %%A in ("%~8") do set "SF_EXTRA=!SF_EXTRA! %%~A"
if not "%~9"=="" for %%A in ("%~9") do set "SF_EXTRA=!SF_EXTRA! %%~A"
if defined SF_EXTRA set "SF_EXTRA=%SF_EXTRA:~1%"
if "%SF_TOOL%"=="clearcache" goto TOOL_RUN_CC
if "%SF_TOOL%"=="update" goto TOOL_RUN_UPDATE
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0bin\%SF_SCRIPT%" %SF_EXTRA%
set "RC=%errorlevel%"
goto TOOL_RC

:TOOL_RUN_CC
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0bin\Clear-Cache.ps1" %SF_EXTRA%
set "RC=%errorlevel%"
goto TOOL_RC

:TOOL_RUN_UPDATE
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create([IO.File]::ReadAllText('%SF_TOOLROOT%bin\SilverFoxDetect.ps1'))) /update %SF_EXTRA%"
set "RC=%errorlevel%"
goto TOOL_RC

:TOOL_RC
echo.
echo 子工具退出码: %RC%
echo 按任意键关闭窗口...
pause >nul
endlocal & exit /b %RC%

:: ===================== PowerShell 兜底查找 (v2.15.4 新增子程序) =====================
:: 主流程 STEP2 与子工具模式(:TOOL_MODE)共用: 若 PS_EXE 未定义, 兜底定位 PowerShell.
:: 复用 v1.50 的搜索策略(PATH + 常见路径 + WindowsApps + 可执行验证).
:ENSURE_PS
if defined PS_EXE goto :eof
:: 1) PATH 搜索
for /f "delims=" %%P in ('where pwsh 2^>nul') do (
    if not defined PS_EXE if exist "%%P" set "PS_EXE=%%P"
)
if not defined PS_EXE for /f "delims=" %%P in ('where powershell 2^>nul') do (
    if not defined PS_EXE if exist "%%P" set "PS_EXE=%%P"
)
:: 2) 常见安装位置 (系统自带 5.1 + PowerShell 7)
set "PS_PATHS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe;%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe;C:\Program Files\PowerShell\7\pwsh.exe;C:\Program Files (x86)\PowerShell\7\pwsh.exe"
for %%P in ("%PS_PATHS:;=" "%") do (
    if not defined PS_EXE if exist "%%~P" set "PS_EXE=%%~P"
)
:: 3) WindowsApps (Win11 微软商店版)
if not defined PS_EXE if exist "%LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe" set "PS_EXE=%LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe"
:: 4) 可执行验证 (避免 PATH 命中但文件损坏的假阳性)
if defined PS_EXE (
    "%PS_EXE%" -NoProfile -Command "$null" 2>nul
    if errorlevel 1 set "PS_EXE="
)
goto :eof

:: ===================== 想法11: 诊断模式 (/diag) =====================
:TOOL_NETBLOCK
:: v2.15.62: 网络封锁管理 (调用引擎 /netblock), 完成后直接退出不挂起
echo.
echo ============================================================
echo   网络封锁管理 (查看/解除恶意外联封锁) [v1.88]
echo ============================================================
set "SF_SCRIPT=SilverFoxDetect.ps1"
if not exist "%~dp0bin\%SF_SCRIPT%" goto TOOL_PS1_MISSING
call :ENSURE_PS
if not defined PS_EXE goto TOOL_PS_FAIL
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0bin\%SF_SCRIPT%" /netblock /lang=%SF_LANG% 2>> "%~dp0sf_run.log"
set "PS_RC=%errorlevel%"
echo.
echo [网络封锁管理] PowerShell 退出码: %PS_RC%
endlocal & exit /b %PS_RC%
:TOOL_RESTOREAV
:: v1.71: 恢复杀毒软件 (调用引擎 /restoreav, 可交互)
echo.
echo ============================================================
echo   恢复杀毒软件功能 (Defender 策略/服务/MpCmdRun) [v1.71]
echo ============================================================
set "SF_SCRIPT=SilverFoxDetect.ps1"
if not exist "%~dp0bin\%SF_SCRIPT%" goto TOOL_PS1_MISSING
call :ENSURE_PS
if not defined PS_EXE goto TOOL_PS_FAIL
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0bin\%SF_SCRIPT%" /restoreav /lang=%SF_LANG% 2>> "%~dp0sf_run.log"
set "PS_RC=%errorlevel%"
echo.
echo [恢复杀毒软件] PowerShell 退出码: %PS_RC%
pause >nul
exit /b
:TOOL_DIAG
:: v1.59: 不再 chcp 65001 (引擎 v1.61 已统一 936; chcp 65001 会让本 bat 的 GBK echo 中文乱码)
>  "%~dp0_diag.log" echo === Diagnostic run started ===
>> "%~dp0_diag.log" echo Time  : %DATE% %TIME%
>> "%~dp0_diag.log" echo Path  : %~dp0
>> "%~dp0_diag.log" echo User  : %USERNAME%
echo.
echo ============================================================
if "%SF_LANG%"=="zh" (echo   顽固木马扫描专杀-银狐特攻 v1.60 [集成模式]) else (echo   SilverFox Detector v1.60 - integrated mode)
echo ============================================================
echo.
echo [1/5] Current directory
echo   Path : %~dp0
echo   File : %~nx0
>> "%~dp0_diag.log" echo Step1 ok: cwd readable
echo.
echo [2/5] PowerShell availability
if defined PS_EXE (
    "%PS_EXE%" -NoProfile -Command "Set-Content -Path $env:TEMP\sf_diag_psver.txt -Value $PSVersionTable.PSVersion.ToString()" 2>nul
    if exist "%TEMP%\sf_diag_psver.txt" (
        set /p PSVER=<"%TEMP%\sf_diag_psver.txt"
        del /q "%TEMP%\sf_diag_psver.txt" >nul 2>&1
        echo   [OK] PowerShell: %PS_EXE%  version: !PSVER!
    ) else (
        echo   [OK] PowerShell: %PS_EXE%
    )
    >> "%~dp0_diag.log" echo Step2 ok: powershell found
) else (
    echo   [FAIL] PowerShell not found
    >> "%~dp0_diag.log" echo Step2 FAIL: powershell missing
)
echo.
echo [3/5] Administrator privilege
net session >nul 2>&1
if errorlevel 1 (
    echo   [INFO] Normal user
    >> "%~dp0_diag.log" echo Step3: not admin
) else (
    echo   [OK] Administrator
    >> "%~dp0_diag.log" echo Step3: admin
)
echo.
echo [4/5] Engine file check (bin\SilverFoxDetect.ps1)
if not exist "%~dp0bin\SilverFoxDetect.ps1" (
    echo   [ERROR] bin\SilverFoxDetect.ps1 NOT FOUND
    >> "%~dp0_diag.log" echo Step4 FAIL: ps1 missing
) else (
    echo   [OK] bin\SilverFoxDetect.ps1 found
    for %%A in ("%~dp0bin\SilverFoxDetect.ps1") do echo   Size : %%~zA bytes
    >> "%~dp0_diag.log" echo Step4 ok: ps1 present
)
echo.
echo [5/5] Desktop folder
if exist "%USERPROFILE%\Desktop" (
    echo   [OK] Desktop: %USERPROFILE%\Desktop
    >> "%~dp0_diag.log" echo Step5 ok: desktop present
) else (
    echo   [WARN] No Desktop folder, will fall back to %USERPROFILE%
    >> "%~dp0_diag.log" echo Step5 WARN: no desktop
)
echo.
echo ============================================================
echo   Diagnostic done. Paste _diag.log contents if you need help.
echo ============================================================
echo.
echo Press any key to close.
pause >nul
endlocal & exit /b 0
