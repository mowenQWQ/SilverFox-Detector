@echo off
chcp 936 >nul 2>&1
title 自动下载并打开 360 系统急救箱
setlocal enabledelayedexpansion
:: ============================================================
::  一键下载并打开 360 系统急救箱 v2.15.35 (便携版)
::  - 不写死任何本机路径, 整包可拷贝到其他电脑使用 (%~dp0 定位)
::  - 下载/解压/临时文件全部放在本脚本所在目录的独立文件夹:
::      tools\360急救箱\   (不污染主文件夹)
::  - 急救箱更新/改名/结构变化: 自动扫描识别, 不硬编码主程序名
::  - 启动后检测进程, 未正常运行则按结构顺序降级运行
::  - 下载失败自动排障: UAC 提权 -> 检测/移除 hosts 中 360 域名重定向 -> 重试下载
:: ============================================================

set "URL=https://dl.360safe.com/360c0mpkill_5.1.64.1289-0701.zip"
set "DLDIR=%~dp0tools\360急救箱"
set "EXTRACT=%DLDIR%\360compkill64"
set "ZIP=%DLDIR%\360c0mpkill_5.1.64.1289-0701.zip"
set "DRYRUN=%SF_360_DRYRUN%"

echo ============================================================
echo   一键下载并打开 360 系统急救箱
echo ============================================================
echo.

:: ---------- 1) 已有解压目录直接使用 ----------
if exist "%EXTRACT%" (
    echo [已安装] 找到急救箱目录: %EXTRACT%
    goto :FIND_MAIN
)

:: ---------- 2) 已有安装包直接解压 ----------
if exist "%ZIP%" (
    echo [已缓存] 找到安装包, 直接解压...
    goto :EXTRACT
)

:: ---------- 3) 下载 (curl 优先, 失败回退 PowerShell) ----------
:DOWNLOAD
echo [下载] 从官网下载急救箱 ...  (大小约 53MB, 请耐心)
if not exist "%DLDIR%" mkdir "%DLDIR%" >nul 2>&1
where curl.exe >nul 2>&1 && (
    curl.exe -L --connect-timeout 30 --max-time 600 -o "%ZIP%" "%URL%"
) || (
    echo   curl 不可用, 改用 PowerShell 下载...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri '%URL%' -OutFile '%ZIP%' -UseBasicParsing"
)

:: 下载成功 -> 直接解压 (避免继续穿入排障段)
if exist "%ZIP%" (
    echo [OK] 下载完成
    goto :EXTRACT
)

:: ---------- 下载失败排障链 ----------
echo.
echo [排障] 自动下载失败, 开始排障: 提权检查 hosts 是否劫持 360 域名...
if defined SF_FIXED goto :FIX_HOSTS_AFTER
if /i "%~1"=="/fix-hosts" goto :FIX_HOSTS
goto :TRY_UAC_FIXHOSTS

:: ---------- 下载失败: UAC 提权重跑 (携带 /fix-hosts 标记) ----------
:TRY_UAC_FIXHOSTS
whoami /groups | findstr /i "S-1-16-12288" >nul 2>&1 && goto :FIX_HOSTS
set "SF_ELEV_ARGS=/fix-hosts"
set "SF_FIX_DIR=%DLDIR%"
echo [排障] 需要管理员权限检查 hosts 文件, 正在弹出 UAC...
powershell.exe -NoProfile -Command "$a=@(); if ($env:SF_ELEV_ARGS) { $a = $env:SF_ELEV_ARGS -split ' ' }; if ($a.Count -gt 0) { Start-Process -FilePath '%~f0' -ArgumentList $a -WorkingDirectory '%~dp0' -Verb RunAs } else { Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs }"
echo [排障] 已弹出 UAC, 请在新窗口允许后继续 (新窗口会修复 hosts 并重试下载)
pause
exit /b 0

:: ---------- 修复 hosts (需管理员) 后重试下载 ----------
:FIX_HOSTS
if not exist "%DLDIR%" mkdir "%DLDIR%" >nul 2>&1
set "SF_FIX_DIR=%DLDIR%"
echo [排障] 检测 hosts 文件中 360 相关域名重定向...
set "SF_RESULT="
for /f "delims=" %%r in ('powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand "CgAkAEUAcgByAG8AcgBBAGMAdABpAG8AbgBQAHIAZQBmAGUAcgBlAG4AYwBlACAAPQAgACcAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAnAAoAJABoAG8AcwB0AHMAIAA9ACAAJwBDADoAXABXAGkAbgBkAG8AdwBzAFwAUwB5AHMAdABlAG0AMwAyAFwAZAByAGkAdgBlAHIAcwBcAGUAdABjAFwAaABvAHMAdABzACcACgAkAGQAaQByACAAPQAgACQAZQBuAHYAOgBTAEYAXwBGAEkAWABfAEQASQBSAAoAaQBmACAAKAAtAG4AbwB0ACAAKABUAGUAcwB0AC0AUABhAHQAaAAgACQAaABvAHMAdABzACkAKQAgAHsAIABXAHIAaQB0AGUALQBPAHUAdABwAHUAdAAgACcATgBPAFQAXwBGAE8AVQBOAEQAJwA7ACAAZQB4AGkAdAAgADMAIAB9AAoAJABiAGEAawAgAD0AIABKAG8AaQBuAC0AUABhAHQAaAAgACQAZABpAHIAIAAoACcAaABvAHMAdABzAF8AYgBhAGMAawB1AHAAXwAnACAAKwAgACgARwBlAHQALQBEAGEAdABlACAALQBGAG8AcgBtAGEAdAAgACcAeQB5AHkAeQBNAE0AZABkAF8ASABIAG0AbQBzAHMAJwApACAAKwAgACcALgB0AHgAdAAnACkACgAkAG8AcgBpAGcAIAA9ACAAWwBJAE8ALgBGAGkAbABlAF0AOgA6AFIAZQBhAGQAQQBsAGwAVABlAHgAdAAoACQAaABvAHMAdABzACkACgBbAEkATwAuAEYAaQBsAGUAXQA6ADoAVwByAGkAdABlAEEAbABsAFQAZQB4AHQAKAAkAGIAYQBrACwAIAAkAG8AcgBpAGcAKQAKACQAcABhAHQAIAA9ACAAJwAoAD8AaQApACgAMwA2ADAAcwBhAGYAZQB8ADMANgAwAFwALgBjAG4AfAAzADYAMABcAC4AYwBvAG0AfAAzADYAMABzAGEAZgBlAFwALgBjAG4AfAAzADYAMAB0AG8AdABhAGwAcwBlAGMAdQByAGkAdAB5AHwAdABvAHQAYQBsAHMAZQBjAHUAcgBpAHQAeQB8AHEAaQBoAG8AbwAzADYAMAB8AHEAaQBoAG8AbwApACcACgAkAGwAaQBuAGUAcwAgAD0AIAAkAG8AcgBpAGcAIAAtAHMAcABsAGkAdAAgACIAXAByAD8AXABuACIACgAkAHIAZQBtAG8AdgBlAGQAIAA9ACAAMAAKACQAbwB1AHQAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4AQwBvAGwAbABlAGMAdABpAG8AbgBzAC4ARwBlAG4AZQByAGkAYwAuAEwAaQBzAHQAWwBzAHQAcgBpAG4AZwBdAAoAZgBvAHIAZQBhAGMAaAAgACgAJABsACAAaQBuACAAJABsAGkAbgBlAHMAKQAgAHsACgAgACAAaQBmACAAKAAkAGwAIAAtAG0AYQB0AGMAaAAgACcAXgBcAHMAKgBbAF4AIwBdACcAIAAtAGEAbgBkACAAJABsACAALQBtAGEAdABjAGgAIAAkAHAAYQB0ACkAIAB7ACAAJAByAGUAbQBvAHYAZQBkACsAKwAgADsAIABjAG8AbgB0AGkAbgB1AGUAIAB9AAoAIAAgACQAbwB1AHQALgBBAGQAZAAoACQAbAApAAoAfQAKAFsASQBPAC4ARgBpAGwAZQBdADoAOgBXAHIAaQB0AGUAQQBsAGwAVABlAHgAdAAoACQAaABvAHMAdABzACwAIAAoACQAbwB1AHQAIAAtAGoAbwBpAG4AIAAiAFwAcgBcAG4AIgApACkACgBXAHIAaQB0AGUALQBPAHUAdABwAHUAdAAgACgAIgBSAEUATQBPAFYARQBEAD0AIgAgACsAIAAkAHIAZQBtAG8AdgBlAGQAIAArACAAIgAgAEIAQQBLAD0AIgAgACsAIAAkAGIAYQBrACkACgA="') do set "SF_RESULT=%%r"
echo [排障] !SF_RESULT!
echo.
set "SF_FIXED=1"
echo [排障] hosts 检查完成, 正在重试下载...
goto :DOWNLOAD

:: ---------- 修复后仍失败的提示 ----------
:FIX_HOSTS_AFTER
echo [失败] hosts 检查修复后下载仍失败。可能原因: 无网络/防火墙/杀软拦截。
echo        请手动下载后放到:
echo        %DLDIR%
echo        下载链接:
echo        %URL%
pause
exit /b 1

:: ---------- 4) 解压 ----------
:EXTRACT
echo [解压] 解压到 %EXTRACT% ...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -Path '%ZIP%' -DestinationPath '%DLDIR%' -Force"
if not exist "%EXTRACT%" (
    echo.
    echo [失败] 解压失败: 安装包可能损坏或被拦截。请手动解压 %ZIP% 到:
    echo        %EXTRACT%
    pause
    exit /b 1
)
echo [OK] 解压完成

:: ============================================================
::  动态识别主程序 + 启动检测 + 按序降级
::  (急救箱更新/改名也不影响: 通配扫描根目录候选)
::  顺序: 主程序(SuperKill*er.exe) -> 所有*请双击.com -> 运行不了*.exe
::        -> 请点我.bat -> 请点我-加强版.bat
::  每步: 启动 -> 等待 5 秒 -> 检查 SuperKill* 进程是否出现
:: ============================================================
:FIND_MAIN
echo.
echo [识别] 检查急救箱结构 (适配官方更新)...
set "P1="
set "P2="
set "P3="
set "P4="
set "P5="
for /f "delims=" %%a in ('dir /b /o:n "%EXTRACT%\SuperKill*er.exe" 2^>nul') do call :setfirst P1 "%%a"
for /f "delims=" %%a in ('dir /b /o:n "%EXTRACT%\所有*请双击.com" 2^>nul') do call :setfirst P2 "%%a"
for /f "delims=" %%a in ('dir /b /o:n "%EXTRACT%\*运行不了*.exe" 2^>nul') do call :setfirst P3 "%%a"
for /f "delims=" %%a in ('dir /b /o:n "%EXTRACT%\*请点我.bat" 2^>nul') do call :setfirst P4 "%%a"
for /f "delims=" %%a in ('dir /b /o:n "%EXTRACT%\*请点我-加强版.bat" 2^>nul') do call :setfirst P5 "%%a"

if not defined P1 if not defined P2 if not defined P3 if not defined P4 if not defined P5 (
    echo [警告] 未识别到任何可执行入口, 请检查 %EXTRACT% 目录。
    pause
    exit /b 1
)
echo [识别] 候选入口: P1=!P1!  P2=!P2!  P3=!P3!  P4=!P4!  P5=!P5!

if "%DRYRUN%"=="1" (
    echo.
    echo [DRYRUN] 检测模式 SF_360_DRYRUN=1: 仅下载解压识别, 不启动。
    pause
    exit /b 0
)

echo.
echo [启动] 开始运行急救箱 (按顺序尝试, 每次启动后检测进程) ...
call :tryrun "!P1!"
if defined OK_EXIT echo [OK] 主程序正常运行: !OK_EXIT! & goto :DONE
call :tryrun "!P2!"
if defined OK_EXIT echo [OK] 已运行: !OK_EXIT! & goto :DONE
call :tryrun "!P3!"
if defined OK_EXIT echo [OK] 已运行: !OK_EXIT! & goto :DONE
call :tryrun "!P4!"
if defined OK_EXIT echo [OK] 已运行: !OK_EXIT! & goto :DONE
call :tryrun "!P5!"
if defined OK_EXIT echo [OK] 已运行: !OK_EXIT! & goto :DONE

echo.
echo [失败] 所有入口尝试后仍未检测到运行。可能被杀软拦截/需要管理员。
echo        请手动右键 SuperKill*er.exe 以管理员身份运行, 或将文件夹改名校名重试。
echo        详见该目录内 "*急救箱*请看此文档*.txt"。
pause
exit /b 1

:DONE
echo.
echo [提示] 检测到急救箱进程正常运行, 请在其界面内操作。本窗口可关闭。
timeout /t 3 >nul 2>&1
exit /b 0

:: ---------- 子流程 ----------
:setfirst
set "%~1=%~2"
goto :eof

:tryrun
set "OK_EXIT="
if "%~1"=="" goto :eof
set "CNAME=%~1"
if not exist "%EXTRACT%\%CNAME%" goto :eof
echo   [尝试] %CNAME% ...
start "" "%EXTRACT%\%CNAME%"
:: 等待启动 (批处理/引导类给更多时间)
timeout /t 5 /nobreak >nul 2>&1
:: 检测: 主程序进程 (SuperKill*er 或 .com 同名) 是否出现
tasklist /FO CSV /NH 2>nul | findstr /I /C:"SuperKill" >nul
if errorlevel 1 (
    :: 再按候选名检测
    for %%z in ("%CNAME%") do set "PN=%%~nz"
    tasklist /FO CSV /NH 2>nul | findstr /I /C:"!PN!" >nul
)
if not errorlevel 1 set "OK_EXIT=%CNAME%"
goto :eof
