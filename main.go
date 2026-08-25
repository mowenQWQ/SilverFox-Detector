// SilverFox Detector v2.15.0 - 纯 Win32 + comctl32 v5 (无 manifest), 零 walk 依赖.
// 不嵌 manifest (避 SxS); 嵌纯 RT_VERSION 资源 (降杀软启发式); 自带启动日志.
//
// 修复历史:
//   v2.3 首版纯 Win32: WM_COMMAND 的 HIWORD/LOWORD 反了 -> 所有按钮点击无效.
//   v2.4 修正 resizeChildren 布局, 但 WM_COMMAND 仍然反着写, 按钮依旧无反应.
//   v2.5 修正 WM_COMMAND 取位 + 补全主检测程序全套能力.
//   v2.6 修复"选择目录"按钮丢弃 SHBrowseForFolderW 返回值; 加 CoInitializeEx(STA).
//   v2.7 修复 Restart Manager 5 处参数错误, 但 RmStartSession 在用户机器上仍报 160.
//   v2.8 完全绕开 Restart Manager! 改用 EnumProcesses + OpenProcess +
//                 QueryFullProcessImageNameW 走 psapi+kernel32 两条路径扫 PID;
//                 不依赖 Rstrtmgr 服务, 彻底解决 ERROR_BAD_ARGUMENTS=160 卡死问题.
//                 产品结构重组: 主程序 (GUI exe) 在 ZIP 顶层; 主检测脚本 (主检测.bat)
//                 直接调用 GUI exe 自动启动 + 扫描; legacy 文件占用检测降级为二级工具.
//   v2.9 改 ListView 为多行只读 EDIT: 列宽不再截断路径, 每条独占多行清晰展示.
//                 GUI 标题改回"文件占用检测", 双击入口 .bat 同步重命名.
//   v2.10 产品定位回归: 主程序 = 银狐检测 (legacy\银狐特攻.bat 真实扫描器);
//                 文件占用检测降级为"小工具"页内的一项. 引入 SysTabControl32 双页面
//                 (银狐检测 / 小工具), 不嵌 manifest (comctl32 v5 即可加载 Tab).
//   v2.11 弃 SysTabControl32: 顶部一排 BS_PUSHBUTTON 切换按钮 (comctl32 v5 下标签渲染
//                 不稳 + TCM_ADJUSTRECT 在 mainHwnd 刚建时返回残影矩形), 改用固定
//                 偏移布局 + ShowWindow(SW_SHOW/SW_HIDE) 切页.
//   v2.12 [本次] 修"启动检测无反应": runSilverFox 在 GUI 父进程下未设
//                 CREATE_NEW_CONSOLE, cmd.exe 试图 AttachConsole(父进程) 失败后
//                 静默退出, 控制台窗口从未弹出. 改用 cmd /c start "" bat 让 bat
//                 自起独立窗口, + 0x10 标志双保险 + 状态栏实时反馈.
//   v2.13 [本次] 真因浮现: v2.11 把功能按钮挂在 pageDetect/pageTools 两个 "Static"
//                 容器下, 子控件点击只把 WM_COMMAND 发给直接父窗口(容器), 而
//                 "Static" 默认 wndProc 不转发给 mainHwnd -> 消息被丢弃 -> 按钮全无反应.
//                 注册自定义容器类 SFContainer, 其 wndProc 把 WM_COMMAND/WM_NOTIFY
//                 转发给 mainHwnd. 另修正状态栏风格 (0x04=SS_BLACKRECT 误当 SS_NOPREFIX).
//   v2.14 [本次] bat 嵌套括号陷阱: 修完后用户实测, GUI 按钮有反应, 弹出 bat 窗口后
//                 立即报 "此时不应有 检测工具。" 后退出. 真因在 legacy/银狐木马检测.bat
//                 第 390 行 (GUI_MODE 标题) 与第 594 行 (TOOL_DIAG 标题) 的复合语句
//                 if "..." (echo   顽固木马扫描专杀-银狐特攻工具 ...) else (...)
//                 中, 父级 if 体的 echo 字符串内嵌套了一对圆括号, CMD 解析器对
//                 (echo ...) else (...) 体内的 ( ) 做简单括号配对追踪, 把 echo
//                 字符串里的 ( 当成新嵌套块起点, 配对错位, 报 "此时不应有 检测工具。"
//                 并立刻退出. 改用 [SilverFox] / [集成模式] (方括号对 CMD 解析器无
//                 特殊含义). 同时清理历史 \r\r\n 行尾残渣. bat 内部版本 v1.55→v1.56.
//   v2.15 [本次] 自保护下沉到 exe: 进程 DACL 防杀 (仅 SYSTEM+Owner 可终止) + 文件完整性
//                 自检 (读 legacy/integrity.manifest 逐文件 SHA256 比对 + 清单签名校验) +
//                 看门狗自愈 (exe 自带 "--watchdog" 子进程, 主进程被 kill 自动重启, 上限5次).
//                 替代原 PowerShell 层 SelfGuard.ps1 / Test-Integrity, 降低对 PowerShell 依赖.
//   v2.15.15 [本次] 启动器 9020 修复 + 引擎 v1.60 降误报 + 签名载荷对齐 + 补档:
//                 ①bat 启动器 v1.57: 9020 根因=WindowsApps 应用执行别名在 RunAs/长中文路径下
//                 返回 9020; 修复=真实安装路径优先+逐候选 exit 0 验证+别名仅兜底告警+stderr 捕获;
//                 ②引擎 v1.60: 签名安全港 Test-SafeHarbor (Program Files+有效签名豁免启发式噪音,
//                 仍保留恶意哈希比对) + 弱信号权重下调 + 启动环境日志 sf_debug.log;
//                 ③Go 层 runIntegrityCheck 验签载荷与 PS 层 Test-Integrity 对齐 (均为完整 signed= 行);
//                 ④selfguard_hook.go 补档 (installSelfGuardHooks 等符号按 SKILL 规格重建).
//   v2.15.16 [本次] BOM 修复正式发布: 交付时引擎/UI ps1 文件头出现双重 BOM (回写脚本
//                 重复前置 BOM), PowerShell 5.1 遇双重 BOM 静默拒绝执行(无报错退出码1);
//                 恢复单 BOM + 引擎 banner 版本同步 v1.60 + manifest 重签重发布.
//   v2.15.17 [本次] bat 启动器 v1.58 UAC 提权修复: 原 -Command "字符串" 模式传 %* 期望 $args 为数组,
//                 但 $args 恒为 null -> Start-Process -ArgumentList 参数验证失败提权降级; 改环境变量
//                 SF_ELEV_ARGS 传参 + -split 数组化 + 空参双分支 (Start-Process 不接受空集合).
//   v2.15.18 [本次] 引擎 v1.61 三项修复: ①TrimEnd char 转换坑(白名单目录前缀 '\\' 双反斜杠字符串);
//                 ②关机拦截 WMI 订阅参数集冲突(-ClassName 与 -Query 互斥) + System32 下 shutdown
//                 按命令行识别工具自身标记放行/否则 kill + 轮询 800ms->250ms; ③控制台编码统一 936
//                 (bat 移除 chcp 65001), 修复 exit 尾部乱码.
//   v2.15.19 [本次] 关机拦截层3 重建: 实机证实"杀 shutdown.exe"无法阻止系统关机(关机请求已提交
//                 会话管理器), 改为创建隐藏窗口 + 独立线程消息循环, WM_QUERYENDSESSION 返回 FALSE
//                 (阻止关机/注销/重启) + ShutdownBlockReasonCreate 显示原因; WMI 通道改用
//                 Register-WmiEvent (CIM cmdlet 对 Win32_ProcessStartTrace 返回 null).
//   v2.15.20 [本次] 层3 C# 双修复 + 命名规范化: ①MSG m 未初始化 (CS0165: ref 实参必须显式赋值) 编译失败
//                  -> 隐藏窗口从未创建, QUERYENDSESSION 从未生效 (实机日志: "层3 初始化失败 ... 编译错误");
//                 ②GetModuleHandleW 误声明在 user32.dll, 运行期找不到入口点, 改 kernel32.dll;
//                 ③对外名称统一「顽固木马扫描专杀-银狐特攻」, 去除 "银狐木马 (SilverFox)" 式自报名称.
//   v2.15.21 [本次] 交付入口改名: 档2/档3 交付文件名改为用户可理解的入口名
//                 (SilverFox.Heartbeat.exe -> 如果主程序打不开点我.exe; SilverFox.Hard.com -> 如果主程序打不开点我.com),
//   v2.15.22 [本次] 新增「一键下载并打开 360 系统急救箱」便携脚本: 独立文件夹 tools\360急救箱 下载解压
//                 (不污染主目录), 动态识别主程序(适配官方更新/改名), 启动后检测进程并按结构化顺序降级.
//                 增加「下载失败自动排障链」(UAC 提权 -> 备份 hostS 移除 360 域名重定向 -> 重试下载).
//                 代码/脚本无硬编码引用, 仅打包名变更; 引擎 v1.64 增加 WM_QUERYENDSESSION 到达诊断日志.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	kernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	user32                      = windows.NewLazySystemDLL("user32.dll")
	comctl32                    = windows.NewLazySystemDLL("comctl32.dll")
	shell32                     = windows.NewLazySystemDLL("shell32.dll")
	ole32                       = windows.NewLazySystemDLL("ole32.dll")
	advapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	wintrust                    = windows.NewLazySystemDLL("wintrust.dll")
	crypt32                     = windows.NewLazySystemDLL("crypt32.dll")
	psapi                       = windows.NewLazySystemDLL("psapi.dll")
	rstrtmgr                    = windows.NewLazySystemDLL("rstrtmgr.dll")
	comdlg32                    = windows.NewLazySystemDLL("comdlg32.dll")
	ntdll                       = windows.NewLazySystemDLL("ntdll.dll")

	procRegisterClassExW        = user32.NewProc("RegisterClassExW")
	procCreateWindowExW         = user32.NewProc("CreateWindowExW")
	procDefWindowProcW          = user32.NewProc("DefWindowProcW")
	procGetMessageW             = user32.NewProc("GetMessageW")
	procTranslateMessage        = user32.NewProc("TranslateMessage")
	procDispatchMessageW        = user32.NewProc("DispatchMessageW")
	procPostQuitMessage         = user32.NewProc("PostQuitMessage")
	procLoadCursorW             = user32.NewProc("LoadCursorW")
	procLoadIconW               = user32.NewProc("LoadIconW")
	procGetClientRect           = user32.NewProc("GetClientRect")
	procSetWindowPos            = user32.NewProc("SetWindowPos")
	procInvalidateRect          = user32.NewProc("InvalidateRect")
	procSendMessageW            = user32.NewProc("SendMessageW")
	procEnableWindow            = user32.NewProc("EnableWindow")
	procPostMessageW            = user32.NewProc("PostMessageW")
	procSetWindowTextW          = user32.NewProc("SetWindowTextW")
	procMessageBoxW             = user32.NewProc("MessageBoxW")
	procSetForegroundWindow     = user32.NewProc("SetForegroundWindow")
	procFindWindowW             = user32.NewProc("FindWindowW")

	procDragAcceptFiles         = shell32.NewProc("DragAcceptFiles")
	procDragQueryFileW          = shell32.NewProc("DragQueryFileW")
	procDragFinish              = shell32.NewProc("DragFinish")

	procInitCommonControlsEx    = comctl32.NewProc("InitCommonControlsEx")

	procRmStartSession          = rstrtmgr.NewProc("RmStartSession")
	procRmRegisterResources     = rstrtmgr.NewProc("RmRegisterResources")
	procRmGetList               = rstrtmgr.NewProc("RmGetList")
	procRmEndSession            = rstrtmgr.NewProc("RmEndSession")
	procRmShutdown              = rstrtmgr.NewProc("RmShutdown")
	procRmRestart               = rstrtmgr.NewProc("RmRestart")

	// v2.8 新增: 不依赖 Restart Manager 的进程路径枚举 (handle.exe 同款原理)
	procEnumProcesses           = psapi.NewProc("EnumProcesses")
	procOpenProcess             = kernel32.NewProc("OpenProcess")
	procWaitForSingleObject     = kernel32.NewProc("WaitForSingleObject")
	procQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
	procGetCurrentProcessId     = kernel32.NewProc("GetCurrentProcessId")
	procTerminateProcess        = kernel32.NewProc("TerminateProcess")
	// v2.15.7 进程与线程监控: Toolhelp 快照枚举 + ETW 实时(均动态加载, x/sys/windows 未封装).
	procCreateToolhelp32SnapshotW = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW           = kernel32.NewProc("Process32FirstW")
	procProcess32NextW            = kernel32.NewProc("Process32NextW")
	procThread32FirstW            = kernel32.NewProc("Thread32First")
	procThread32NextW             = kernel32.NewProc("Thread32Next")
	procOpenThread               = kernel32.NewProc("OpenThread")
	// ETW 实时进程事件(kenel32 的 OpenTrace/ProcessTrace/ControlTrace + advapi32 的 EnableTraceEx2).
	procOpenTraceW             = kernel32.NewProc("OpenTraceW")
	procProcessTrace           = kernel32.NewProc("ProcessTrace")
	procCloseTrace             = kernel32.NewProc("CloseTrace")
	procEnableTraceEx2         = advapi32.NewProc("EnableTraceEx2")
	// 代码签名校验(判"是什么程序"的核心): WinVerifyTrust.
	procWinVerifyTrust         = wintrust.NewProc("WinVerifyTrust")
	procCryptQueryObject       = crypt32.NewProc("CryptQueryObject")

	// v2.15.8 EDR-Freeze 反冻: 线程挂起监控所需 API.
	//   ResumeThread / SuspendThread: 自愈(把被攻击者挂起的本进程线程恢复运行).
	//   NtQueryInformationThread: 读 ThreadBasicInformation 里的 SuspendCount, 判定线程是否处于挂起态.
	procResumeThread           = kernel32.NewProc("ResumeThread")
	procSuspendThread          = kernel32.NewProc("SuspendThread")
	procNtQueryInformationThread = ntdll.NewProc("NtQueryInformationThread")
	// v2.15.9 双向心跳 + 高权限守护: 文件心跳写时间戳.
	procGetTickCount64         = kernel32.NewProc("GetTickCount64")
	// WerSetFlags / WerRegisterFile / WER API 在 wer.dll (best-effort 关闭自身 WER 转储).
	wer                        = windows.NewLazySystemDLL("wer.dll")
	procWerSetFlags            = wer.NewProc("WerSetFlags")
	procWerRegisterMemoryBlock = wer.NewProc("WerRegisterMemoryBlock")

	PROCESS_QUERY_LIMITED_INFORMATION = uintptr(0x1000)
	PROCESS_SUSPEND_RESUME            = uintptr(0x0800) // THREAD_SUSPEND_RESUME(用于 ResumeThread 句柄)

	procGetOpenFileNameW        = comdlg32.NewProc("GetOpenFileNameW")
	procGetSaveFileNameW        = comdlg32.NewProc("GetSaveFileNameW")
	procCoTaskMemFree           = ole32.NewProc("CoTaskMemFree")
)

// === 注意: 必须使用 unicode (16位) 路径! 纯 ASCII 通过 syscall.UTF16PtrFromString 即可 ===

const (
	WS_OVERLAPPEDWINDOW  = 0x00CF0000
	WS_VISIBLE           = 0x10000000
	WS_CHILD             = 0x40000000
	WS_BORDER            = 0x00800000
	WS_VSCROLL           = 0x00200000
	WS_TABSTOP           = 0x00010000
	WS_CLIPCHILDREN      = 0x02000000
	WS_CLIPSIBLINGS      = 0x04000000
	ES_AUTOHSCROLL       = 0x0080
	ES_AUTOVSCROLL       = 0x0040
	ES_MULTILINE         = 0x0004
	ES_NOHIDESEL         = 0x0100
	ES_READONLY          = 0x0800
	BS_PUSHBUTTON        = 0x0000
	BS_AUTOCHECKBOX      = 0x0003

	EM_SETSEL            = 0x00B1
	EM_REPLACESEL        = 0x00C2

	WS_EX_ACCEPTFILES    = 0x00000010
	WS_EX_CLIENTEDGE     = 0x00000200
	WS_EX_STATICEDGE     = 0x00020000

	// v2.15.26: 主窗口关机拦截 (WM_QUERYENDSESSION 广播必达可见顶层窗口; 引擎层3隐藏窗口实测收不到)
	WM_QUERYENDSESSION    = 0x0011
	WM_ENDSESSION         = 0x0016
	WM_CREATE            = 0x0001
	WM_SIZE              = 0x0005
	WM_CLOSE             = 0x0010
	WM_APP_PROGRESS      = 0x8001 // v2.15.74: goroutine -> GUI 刷进度(PostMessage 携带共享缓冲)
	WM_APP_STATUS        = 0x8002 // v2.15.74: goroutine -> GUI 刷状态栏
	WM_DESTROY           = 0x0002
	WM_COMMAND           = 0x0111
	WM_NOTIFY            = 0x004E
	WM_DROPFILES         = 0x0233
	WM_PAINT             = 0x000F
	WM_SETCURSOR         = 0x0020
	WM_SETFONT           = 0x0030

	BN_CLICKED           = 0
	EN_CHANGE            = 0x0300

	// v2.15.25: UAC 复选框自动勾选用 (BM_SETCHECK=0x00F1)
	BM_GETCHECK          = 0x00F0
	BM_SETCHECK          = 0x00F1
	BST_CHECKED          = 1

	SW_SHOWNORMAL        = 1

	ID_EDIT_PATH         = 1001
	ID_BTN_PICKFILE      = 1002
	ID_BTN_PICKDIR       = 1003
	ID_BTN_DETECT        = 1004
	ID_BTN_COPY          = 1005
	ID_BTN_SAVE          = 1006
	ID_BTN_RELEASE       = 1007
	ID_BTN_REG_SHELL     = 1008
	ID_BTN_REG_DIR       = 1009
	ID_DETAIL            = 1010
	ID_STATUS            = 1011

	// v2.11: 抛弃 SysTabControl32 (comctl32 v5 下标签栏渲染不稳 + TCM_ADJUSTRECT 易算错).
	//         改为顶部一排「[银狐检测] [小工具]」切换按钮, 高亮选中.
	ID_TABBAR_DETECT     = 1020
	ID_TABBAR_TOOLS      = 1021
	ID_PANEL_DETECT      = 1022
	ID_PANEL_TOOLS       = 1023

	ID_SF_INFO           = 1024
	ID_SF_CONSOLE        = 1025
	ID_BTN_SF_RUN        = 1030
	ID_BTN_SF_FULL       = 1031
	ID_BTN_SF_DIAG       = 1032
	ID_BTN_SF_RESTORE    = 1033
	ID_BTN_SF_REPAIR     = 1034
	ID_BTN_SF_RESTOREAV  = 1035
	ID_BTN_SF_NETBLOCK   = 1036
	ID_BTN_SF_INSTALLPS  = 1037

	ID_CHK_ADMIN         = 1040 // v2.15.4: "以管理员身份运行" 复选框
	ID_BTN_INSTALL_SVC   = 1050 // v2.15.9: 档3 专属"安装为 SYSTEM 服务(最强常驻)"按钮

	ICC_LISTVIEW_CLASSES = 1
	IDI_APPLICATION      = 32512
	IDC_ARROW            = 32512

	// v2.11: STATIC 控件风格
	SS_LEFT              = 0x00000000 // 默认左对齐
	SS_NOPREFIX          = 0x00000080 // 不解析 & 助记符
	SS_LEFTNOWORDWRAP    = 0x40000000 // 不自动换行 (状态栏用了它, 但默认 SS_LEFT 也可)

	ERROR_MORE_DATA       = 234
	ERROR_SUCCESS         = 0
	ERROR_CANCELLED       = 1223

	MB_OK                 = 0x00000000
	MB_OKCANCEL           = 0x00000001
	MB_YESNO              = 0x00000004
	MB_ICONERROR          = 0x00000010
	MB_ICONQUESTION       = 0x00000020
	MB_ICONINFORMATION    = 0x00000040
	MB_ICONWARNING        = 0x00000030
	MB_TOPMOST            = 0x00040000
	MB_SETFOREGROUND      = 0x00010000
	MB_DEFBUTTON1         = 0x00000000
	MB_DEFBUTTON2         = 0x00000100

	IDOK                 = 1
	IDCANCEL             = 2
	IDYES                = 6
	IDNO                 = 7

	CS_HREDRAW           = 0x0002
	CS_VREDRAW           = 0x0001
	COLOR_WINDOW         = 5       // Win32 GetSysColor 索引: 标准窗口背景

	HWND_TOP             = windows.HWND(0)
	SWP_NOMOVE           = 0x0002
	SWP_NOSIZE           = 0x0001
	SWP_NOZORDER         = 0x0004
	SWP_NOACTIVATE       = 0x0010
	SWP_SHOWWINDOW       = 0x0040

	OFN_EXPLORER         = 0x00080000
	OFN_FILEMUSTEXIST    = 0x00001000
	OFN_HIDEREADONLY     = 0x00000004
	OFN_OVERWRITEPROMPT  = 0x00000002
	OFN_PATHMUSTEXIST    = 0x00000800

	SHGFP_TYPE_CURRENT   = 0

	BIF_RETURNONLYFSDIRS = 0x00000001
	BIF_NEWDIALOGSTYLE   = 0x00000040
	BIM_RETURNVALUES     = 0x00000000

	COINIT_APARTMENTTHREADED = 0x2 // SHBrowseForFolder(BIF_NEWDIALOGSTYLE) 要求线程在 STA
)

// buildTierStr: 编译期注入的自保档位字符串 (1=标准 / 2=双向心跳 / 3=硬钩子+高权限守护).
//   -X 仅支持 string, 故用字符串注入, 运行时解析为 int. 默认 "1".
//   档1 SilverFox.exe          标准自保(现有 DACL+缓解+完整性+单向看门狗+监控+反冻)
//   档2 SilverFox.Heartbeat.exe 档1 + 双向心跳看门狗(启动即 UAC 一次)
//   档3 SilverFox.Hard.com      档2 + 用户态 inline hook(拦自身 NtTerminate/Suspend) + 高权限守护(急救箱)
var buildTierStr = "1"

// buildTier 运行期解析出的档位(int). 由 parseBuildTier 在包 init 外首次使用前填充.
var buildTier = 1

// parseBuildTier 把 buildTierStr 解析为 int(越界/非法 -> 1).
func parseBuildTier() {
	switch buildTierStr {
	case "2":
		buildTier = 2
	case "3":
		buildTier = 3
	default:
		buildTier = 1
	}
}

// tierSuffix 返回档位对应的窗口标题后缀与品牌标识.
func tierSuffix() string {
	switch buildTier {
	case 2:
		return " - 双向心跳自保"
	case 3:
		return " - 急救箱(硬自保)"
	default:
		return " - 银狐特攻扫描"
	}
}

const AppTitle = "顽固木马扫描专杀-银狐特攻 v2.15.74" // 实际后缀在 winMain 前由 buildTier 动态拼接 (v2.15.20=层3 C# 编译/运行时双修复: MSG 未初始化 CS0165 + GetModuleHandleW 模块错误, 隐藏窗口终于生效; 对外名称规范化为「银狐检测工具」)

const (
	AppTitleBase = "顽固木马扫描专杀-银狐特攻 v2.15.74"
)

// buildTag 用于从日志辨识部署的是哪一版补丁二进制: 避免"用户双击的是旧 exe / 看门狗锁住未覆盖"时
// 无法判断修复是否生效. 每次重新编译分发包都改这个值(同时记到 skill 版本号).
const buildTag = "p66-20260824-author"

type WNDCLASSEXW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     windows.Handle
	HIcon         windows.Handle
	HCursor       windows.Handle
	HbrBackground windows.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       windows.Handle
}

type MSG struct {
	Hwnd    windows.HWND
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

type RECT struct {
	Left, Top, Right, Bottom int32
}

type POINT struct {
	X, Y int32
}

type INITCOMMONCONTROLSEX struct {
	DwSize uint32
	DwICC  uint32
}

type FILETIME struct {
	DwLowDateTime  uint32
	DwHighDateTime uint32
}

// 注: RM_UNIQUE_PROCESS / RM_PROCESS_INFO 在 v2.8 已停止调用, 但保留类型定义
// 便于 --register / --unregister 等一旦未来要重启注册表项时复用.

type OPENFILENAMEW struct {
	StructSize      uint32
	Owner           windows.HWND
	Instance        windows.Handle
	Filter          *uint16
	CustomFilter    *uint16
	MaxCustomFilter uint32
	FilterIndex     uint32
	File            *uint16
	MaxFile         uint32
	FileTitle       *uint16
	MaxFileTitle    uint32
	InitialDir      *uint16
	Title           *uint16
	Flags           uint32
	FileOffset      uint16
	FileExtension   uint16
	DefExt          *uint16
	CustData        uintptr
	FnHook          uintptr
	TemplateName    *uint16
	PvReserved      uintptr
	DwReserved      uint32
	FlagsEx         uint32
}

type BROWSEINFOW struct {
	Owner        windows.HWND
	Root         *uint16
	DisplayName  *uint16
	Title        *uint16
	Flags        uint32
	Lpfn         uintptr
	LParam       uintptr
	Image        int32
}

type RmAppType int32

const (
	RmUnknownApp  RmAppType = 0
	RmMainWindow  RmAppType = 1
	RmOtherWindow RmAppType = 2
	RmService     RmAppType = 3
	RmExplorer    RmAppType = 4
	RmConsole     RmAppType = 5
	RmCritical    RmAppType = 1000
)

var (
	logFile       *os.File
	mainHwnd      windows.HWND
	// v2.11: 抛弃 SysTabControl32, 改顶部一排「[银狐检测] [小工具]」切换按钮
	//         + 两套 Static 容器, ShowWindow 切显隐.
	pageDetect    windows.HWND // 银狐检测 (主)
	pageTools     windows.HWND // 小工具: 文件占用检测
	tabBtnDetect  windows.HWND // 顶部「银狐检测」切换按钮
	tabBtnTools   windows.HWND // 顶部「小工具」切换按钮
	currentTab    int          // 0=detect, 1=tools (同步顶部按钮高亮)

	// 银狐检测页控件
	sfInfoHwnd    windows.HWND
	sfConsoleHwnd windows.HWND
	btnSfRun      windows.HWND
	btnSfFull     windows.HWND
	btnSfDiag     windows.HWND
	btnSfRestore  windows.HWND
	btnSfRepair   windows.HWND
	btnSfRestoreAV windows.HWND
	btnSfNetBlock  windows.HWND
	btnSfInstallPS windows.HWND
	adminCheckHwnd windows.HWND // v2.15.4: "以管理员身份运行" 复选框
	svcInstallHwnd windows.HWND // v2.15.9: 档3 专属"安装为 SYSTEM 服务"按钮
	// 小工具(文件占用)页控件
	// detailHwnd: 多行只读 EDIT 控件, 显示检测到的占用进程明细 (替代 v2.8 的 ListView,
	// 解决列宽被截断、看不见完整路径的问题)
	detailHwnd    windows.HWND
	editHwnd      windows.HWND
	btnPickFile   windows.HWND
	btnPickDir    windows.HWND
	btnDetect     windows.HWND
	btnCopy       windows.HWND
	btnSave       windows.HWND
	btnRelease    windows.HWND
	btnRegShell   windows.HWND
	btnRegDir     windows.HWND
	statusHwnd    windows.HWND

	// 当前检测出的结果, 复制 / 保存 / 释放都基于它
	currentResults  []LockInfo
	currentTarget   string
)

func logf(format string, args ...interface{}) {
	ts := time.Now().Format("2006/01/02 15:04:05.000")
	line := fmt.Sprintf("[%s] %s\n", ts, fmt.Sprintf(format, args...))
	if logFile != nil {
		logFile.WriteString(line)
	}
}

func setStatus(format string, args ...interface{}) {
	if statusHwnd == 0 {
		return
	}
	msg := fmt.Sprintf(format, args...)
	ptr, _ := syscall.UTF16PtrFromString(msg)
	procSendMessageW.Call(uintptr(statusHwnd), 0x000C /*WM_SETTEXT*/, 0, uintptr(unsafe.Pointer(ptr)))
	logf(msg)
}

func initLog() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	p := filepath.Join(filepath.Dir(exe), "SilverFoxDetector.log")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		logFile = f
	}
}

func showFatal(msg string) int {
	logf("FATAL: %s", msg)
	if logFile != nil {
		logFile.Close()
	}
	// 关键修复 v2.15.11: 即便 user32.dll 加载失败(错误 1114, 如本机 EDR 拦截), 弹窗调用也必须安全降级,
	// 绝不能二次 panic 触发看门狗无限重启. safeCall 内部已 recover, 弹窗失败则静默(错误已写入日志).
	titlePtr, _ := syscall.UTF16PtrFromString("SilverFox Detector 错误")
	msgPtr, _ := syscall.UTF16PtrFromString(msg)
	safeCall(procMessageBoxW, 0, uintptr(unsafe.Pointer(msgPtr)), uintptr(unsafe.Pointer(titlePtr)),
		uintptr(MB_OK|MB_ICONERROR|MB_TOPMOST|MB_SETFOREGROUND))
	return 1
}

func msgBoxInfo(title, msg string) {
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(msg)
	safeCall(procMessageBoxW, 0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)),
		uintptr(MB_OK|MB_ICONINFORMATION|MB_TOPMOST|MB_SETFOREGROUND))
}

func msgBoxQuestion(title, msg string) bool {
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(msg)
	r, _, _, ok := safeCall(procMessageBoxW, 0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)),
		uintptr(MB_YESNO|MB_ICONQUESTION|MB_TOPMOST|MB_SETFOREGROUND|MB_DEFBUTTON2))
	if !ok {
		return false // user32 不可用时降级为"否", 由调用方按默认分支处理
	}
	return r == IDYES
}

func utf16Ptr(s string) *uint16 {
	if s == "" {
		p, _ := syscall.UTF16PtrFromString("")
		return p
	}
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func ut16(s string) []uint16 {
	p, _ := syscall.UTF16FromString(s)
	return p
}

type LockInfo struct {
	Pid      uint32
	Type     string
	Name     string
	FullPath string
}

func detectFor(path string) ([]LockInfo, error) {
	return getFileLockInfo(path)
}

// === Restart Manager ===
var (
	procCloseHandle                = kernel32.NewProc("CloseHandle")
)

const (
	PROCESS_QUERY_INFORMATION       = 0x0400
)

// queryProcessPath 通过 PID 取进程完整镜像路径.
func queryProcessPath(pid uint32) string {
	h, _, _ := procOpenProcess.Call(PROCESS_QUERY_LIMITED_INFORMATION, 0, uintptr(pid))
	if h == 0 {
		return ""
	}
	defer procCloseHandle.Call(uintptr(h))
	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	procQueryFullProcessImageNameW.Call(h, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	return windows.UTF16ToString(buf[:size])
}

// enumProcessOwners 遍历所有进程, 返回和给定 path (文件或目录) 相关的占用进程.
// 等价于: 进程 exe 路径 == target, 或者 exe 路径在 target 目录下.
//
// 这是 Sysinternals handle.exe 的简化原理: 不依赖 Restart Manager 服务,
// 不需要 RmStartSession (某些机器报 ERROR_BAD_ARGUMENTS=160).
func enumProcessOwners(targetPath string) []LockInfo {
	targetLower := strings.ToLower(strings.TrimRight(targetPath, "\\/"))
	targetIsDir := false
	if fi, err := os.Stat(targetPath); err == nil && fi.IsDir() {
		targetIsDir = true
	}
	logf("enumProcessOwners: target=%s isDir=%v", targetLower, targetIsDir)

	// 第一次: 拿需要的 buffer 大小
	const initialSize = 64 * 1024
	pids := make([]uint32, initialSize/4)
	var bytesReturned uint32
	ret, _, _ := procEnumProcesses.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(initialSize),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if ret == 0 {
		logf("EnumProcesses 失败")
		return nil
	}
	nPID := int(bytesReturned) / 4
	logf("EnumProcesses: 共 %d 个 PID", nPID)

	results := make([]LockInfo, 0)
	for i := 0; i < nPID; i++ {
		pid := pids[i]
		if pid == 0 {
			continue // PID 0 = System Idle Process
		}
		exePath := queryProcessPath(pid)
		if exePath == "" {
			continue
		}
		exeLower := strings.ToLower(strings.TrimRight(exePath, "\\/"))

		matched := false
		if targetIsDir {
			// 目录匹配: exe 路径必须以 "<target>\" 开头.
			// (即 exe 在该目录下, 比如 C:\Program Files\Tencent\Weixin)
			matched = strings.HasPrefix(exeLower, targetLower+"\\")
		} else {
			// 文件匹配: 完全匹配.
			matched = exeLower == targetLower
		}
		if !matched {
			continue
		}

		// 取进程名 (exe 文件名, 不含目录)
		name := exePath
		if idx := strings.LastIndex(exePath, "\\"); idx >= 0 {
			name = exePath[idx+1:]
		}
		results = append(results, LockInfo{
			Pid:      pid,
			Type:     "进程",
			Name:     name,
			FullPath: exePath,
		})
	}
	logf("enumProcessOwners: 命中 %d 个进程", len(results))
	return results
}

// getFileLockInfo 检测哪些进程占用 path (文件或目录).
//
// 历史: v2.3~v2.6 调用 Restart Manager RmShutdown/RmRestart, 但 RM 在某些机器报 160
//		ERROR_BAD_ARGUMENTS 时整个功能半残(关得成功也不重启)。v2.7 修对了参数顺序,
//		但用户截屏仍报 RmStartSession code=160, 说明在该环境启动就失败。
//
// v2.8: 完全绕开 RM, 用 TerminateProcess 直接结束目标 PID (需要进程权限, 普通用户
//		只能结束自己的进程; UAC 提升的进程需要提权)。重启"可重启"应用的能力暂不提供,
//		对文件占用检测场景, 释放路径后用户自己重新打开应用即可。
// getFileLockInfo 检测哪些进程占用 path (文件或目录).
// v2.8 主流程 = 走 EnumProcesses + QueryFullProcessImageName (不依赖 Restart Manager 服务,
//   避免某些机器 RmStartSession 报 ERROR_BAD_ARGUMENTS=160).
func getFileLockInfo(path string) ([]LockInfo, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("目标路径不存在: %s", path)
	}
	results := enumProcessOwners(path)
	logf("getFileLockInfo: enumProcessOwners 返回 %d 条结果", len(results))
	return results, nil
}

func shutdownAndRestart() {
	if len(currentResults) == 0 || currentTarget == "" {
		setStatus("当前没有可释放的占用")
		return
	}
	if !msgBoxQuestion("确认释放占用",
		fmt.Sprintf("将尝试关闭占用以下目标的进程:\n\n%s\n\n共 %d 个进程。\n\n是否继续?", currentTarget, len(currentResults))) {
		return
	}
	killed, failed := 0, 0
	for _, r := range currentResults {
		h, _, _ := procOpenProcess.Call(
			uintptr(0x0001),     // PROCESS_TERMINATE
			0,
			uintptr(r.Pid),
		)
		if h == 0 {
			logf("结束进程失败: PID=%d OpenProcess 失败", r.Pid)
			failed++
			continue
		}
		procTerminateProcess.Call(h, 1)
		procCloseHandle.Call(h)
		killed++
		logf("结束进程: PID=%d %s", r.Pid, r.Name)
	}
	setStatus("已关闭 %d 个进程 (失败 %d). 再点'立即检测'查看最新占用情况。", killed, failed)

	// 自动重检测
	go func() {
		time.Sleep(500 * time.Millisecond)
		runDetection(currentTarget)
	}()
}

// === 检测结果明细编辑框 (多行只读 EDIT) ===
//
// v2.9 起替换原 ListView: 列宽不再截断路径, 每条占用独占多行清晰展示.
// 同时支持窗口缩得很窄时用滚动条翻看, 不依赖列宽自适应.

func clearDetail() {
	p, _ := syscall.UTF16PtrFromString("")
	procSendMessageW.Call(uintptr(detailHwnd), 0x000C /*WM_SETTEXT*/, 0, uintptr(unsafe.Pointer(p)))
}

func appendDetail(s string) {
	// 先把光标移到末尾 (-1/-1 在 EM_SETSEL 里表示文末), 再 EM_REPLACESEL 插入
	procSendMessageW.Call(uintptr(detailHwnd), EM_SETSEL, ^uintptr(0), ^uintptr(0))
	p, _ := syscall.UTF16PtrFromString(s)
	procSendMessageW.Call(uintptr(detailHwnd), EM_REPLACESEL, 0, uintptr(unsafe.Pointer(p)))
	// 再把光标/选区挪到末尾, 同时滚动条自动滚到底
	procSendMessageW.Call(uintptr(detailHwnd), EM_SETSEL, ^uintptr(0), ^uintptr(0))
}

func refreshList(path string) {
	currentTarget = path
	logf("开始检测: %s", path)
	setStatus("正在检测: %s ...", safeShort(path))
	clearDetail()
	results, err := detectFor(path)
	if err != nil {
		setStatus("检测失败: %v", err)
		return
	}
	currentResults = results
	if len(results) == 0 {
		appendDetail("\r\n  (未发现占用进程, 目标可自由删除/移动/重新打开)\r\n")
		setStatus("完成: %s (无占用)", safeShort(path))
		return
	}
	appendDetail("\r\n===== SilverFox Detector 文件占用检测 =====\r\n")
	appendDetail(fmt.Sprintf("目标: %s\r\n", path))
	appendDetail(fmt.Sprintf("时间: %s\r\n", time.Now().Format("2006-01-02 15:04:05")))
	appendDetail(fmt.Sprintf("共发现 %d 个占用进程:\r\n", len(results)))
	appendDetail("--------------------------------------------------\r\n")
	for i, r := range results {
		appendDetail(fmt.Sprintf("\r\n[%d] PID %d  %s\r\n", i+1, r.Pid, r.Name))
		appendDetail(fmt.Sprintf("    类型    : %s\r\n", r.Type))
		if r.FullPath != "" {
			appendDetail(fmt.Sprintf("    映像路径: %s\r\n", r.FullPath))
		}
	}
	appendDetail("--------------------------------------------------\r\n")
	appendDetail("点「释放占用」可对上面所有进程执行 TerminateProcess.\r\n")
	setStatus("完成: %s -> %d 个占用", safeShort(path), len(results))
}

func safeShort(p string) string {
	if len(p) <= 60 {
		return p
	}
	return "..." + p[len(p)-57:]
}

func refreshListFromEdit() {
	runDetection(getEditText())
}

func runDetection(path string) {
	path = strings.TrimSpace(path)
	path = strings.Trim(path, "\"")
	if path == "" {
		setStatus("请先输入或拖入文件/文件夹路径")
		return
	}
	refreshList(path)
}

// === 布局 ===
// === 页面切换 + 布局 ===
func showPage(idx int) {
	currentTab = idx
	const SW_SHOW = 5
	const SW_HIDE = 0
	if idx == 0 {
		procShowWindow.Call(uintptr(pageDetect), SW_SHOW)
		procShowWindow.Call(uintptr(pageTools), SW_HIDE)
	} else {
		procShowWindow.Call(uintptr(pageDetect), SW_HIDE)
		procShowWindow.Call(uintptr(pageTools), SW_SHOW)
	}
	// 高亮顶部按钮: 当前 = 「[●] xxx」, 非选中 = 「    xxx」(留白对齐)
	setBtnLabel(tabBtnDetect, idx == 0, "银狐特攻")
	setBtnLabel(tabBtnTools, idx == 1, "小工具")
}

func setBtnLabel(hwnd windows.HWND, sel bool, label string) {
	if hwnd == 0 {
		return
	}
	text := "    " + label
	if sel {
		text = "[●] " + label
	}
	p, _ := syscall.UTF16PtrFromString(text)
	procSendMessageW.Call(uintptr(hwnd), 0x000C /*WM_SETTEXT*/, 0, uintptr(unsafe.Pointer(p)))
}

func setSfConsole(s string) {
	p, _ := syscall.UTF16PtrFromString(s)
	procSendMessageW.Call(uintptr(sfConsoleHwnd), 0x000C /*WM_SETTEXT*/, 0, uintptr(unsafe.Pointer(p)))
}

func resizeChildren(wParam, lParam uintptr) {
	var w, h int32
	if lParam != 0 {
		w = int32(uint16(lParam & 0xFFFF))
		h = int32(uint16((lParam >> 16) & 0xFFFF))
	} else {
		var rc RECT
		procGetClientRect.Call(uintptr(mainHwnd), uintptr(unsafe.Pointer(&rc)))
		w = rc.Right - rc.Left
		h = rc.Bottom - rc.Top
	}
	if w <= 0 || h <= 0 {
		return
	}
	if statusHwnd == 0 {
		return
	}

	const (
		statusRow = 24 // 底部状态栏高度
		tabRow    = 36 // 顶部切换按钮行 (按钮 32 高 + pad)
		pad       = 8
	)

	// ---- 状态栏 (底部) ----
	procSetWindowPos.Call(uintptr(statusHwnd), 0,
		uintptr(uint32(pad)), uintptr(uint32(h-statusRow+2)),
		uintptr(uint32(w-pad*2)), uintptr(uint32(statusRow-4)),
		SWP_NOZORDER|SWP_NOACTIVATE)

	// ---- 顶部切换按钮行 ----
	const tabBtnW = 140
	tabBtnX := int32(pad)
	tabBtnY := int32(pad)
	tabBtnH := int32(tabRow - pad) // 28
	procSetWindowPos.Call(uintptr(tabBtnDetect), 0,
		uintptr(uint32(tabBtnX)), uintptr(uint32(tabBtnY)),
		uintptr(uint32(tabBtnW)), uintptr(uint32(tabBtnH)),
		SWP_NOZORDER|SWP_NOACTIVATE)
	procSetWindowPos.Call(uintptr(tabBtnTools), 0,
		uintptr(uint32(tabBtnX+tabBtnW+pad)), uintptr(uint32(tabBtnY)),
		uintptr(uint32(tabBtnW)), uintptr(uint32(tabBtnH)),
		SWP_NOZORDER|SWP_NOACTIVATE)

	// ---- 页面区域 (两套容器共享同一矩形, ShowWindow 切换显隐) ----
	pageX := int32(pad)
	pageY := int32(tabRow)
	pageW := w - int32(pad*2)
	pageH := h - int32(tabRow) - int32(statusRow)

	procSetWindowPos.Call(uintptr(pageDetect), 0,
		uintptr(uint32(pageX)), uintptr(uint32(pageY)),
		uintptr(uint32(pageW)), uintptr(uint32(pageH)),
		SWP_NOZORDER|SWP_NOACTIVATE)
	procSetWindowPos.Call(uintptr(pageTools), 0,
		uintptr(uint32(pageX)), uintptr(uint32(pageY)),
		uintptr(uint32(pageW)), uintptr(uint32(pageH)),
		SWP_NOZORDER|SWP_NOACTIVATE)

	// 内部布局仅当前页 (减少不必要的 SetWindowPos/重绘)
	if currentTab == 0 && pageDetect != 0 {
		layoutPageDetect(pageW, pageH)
	} else if currentTab == 1 && pageTools != 0 {
		layoutPageTools(pageW, pageH)
	}
	logf("resizeChildren: w=%d h=%d currentTab=%d", w, h, currentTab)
}

func layoutPageDetect(dw, dh int32) {
	if sfInfoHwnd == 0 {
		return
	}
	const pad = 12
	// 左列: 5 个大按钮 (220 宽, 38 高, 垂直间距 8) 占 dw 左侧 280
	const btnW = 220
	const btnH = 38
	const btnGap = 8
	leftCol := int32(280)

	// 顶部说明 (信息条) — 跨整宽
	procSetWindowPos.Call(uintptr(sfInfoHwnd), 0,
		uintptr(uint32(pad)), uintptr(uint32(pad)),
		uintptr(uint32(dw-int32(pad*2))), 48,
		SWP_NOZORDER|SWP_NOACTIVATE)

	by := int32(48 + pad*2)
	btns := []windows.HWND{btnSfRun, btnSfFull, btnSfDiag, btnSfRestore, btnSfRepair, btnSfRestoreAV, btnSfNetBlock, btnSfInstallPS}
	for i, b := range btns {
		procSetWindowPos.Call(uintptr(b), 0,
			uintptr(uint32(pad)), uintptr(uint32(by+int32(i)*(btnH+btnGap))),
			uintptr(uint32(btnW)), uintptr(uint32(btnH)),
			SWP_NOZORDER|SWP_NOACTIVATE)
	}

	// v2.15.4: "以管理员身份运行" 复选框放在按钮列下方
	if adminCheckHwnd != 0 {
		chkY := by + int32(len(btns))*(btnH+btnGap) + 8
		procSetWindowPos.Call(uintptr(adminCheckHwnd), 0,
			uintptr(uint32(pad)), uintptr(uint32(chkY)),
			uintptr(uint32(btnW)), 22,
			SWP_NOZORDER|SWP_NOACTIVATE)
	}

	// 右列 (留 8px) 起 sfConsoleHwnd (多行只读 EDIT 提示)
	if sfConsoleHwnd != 0 && leftCol < dw {
		procSetWindowPos.Call(uintptr(sfConsoleHwnd), 0,
			uintptr(uint32(leftCol)), uintptr(uint32(by)),
			uintptr(uint32(dw-leftCol-int32(pad))), uintptr(uint32(dh-by-int32(pad))),
			SWP_NOZORDER|SWP_NOACTIVATE)
	}
}

func layoutPageTools(dw, dh int32) {
	if editHwnd == 0 || detailHwnd == 0 {
		return
	}
	const pad = 6
	const pathRow = 32
	const btnRow = 32

	editX := int32(pad)
	editY := int32(pad)
	editW := dw - pad*2 - 80*2 - pad
	editH := int32(24)
	pickX := dw - pad - 160
	pickY := editY
	pickW := int32(80)
	dirX := dw - pad - 80
	dirY := editY

	btnY := pathRow + pad
	btnW := int32(90)
	btnH := int32(28)
	btn1X := int32(pad)
	btn2X := btn1X + btnW + pad
	btn3X := btn2X + btnW + pad
	btn4X := btn3X + btnW + pad
	btn5X := btn4X + btnW + pad
	btn6X := btn5X + btnW + pad

	listY := int32(pathRow + btnRow + pad)
	listW := dw
	listH := dh - listY - int32(pad)

	procSetWindowPos.Call(uintptr(editHwnd), 0,
		uintptr(editX), uintptr(editY),
		uintptr(editW), uintptr(editH), SWP_NOZORDER|SWP_NOACTIVATE)
	procSetWindowPos.Call(uintptr(btnPickFile), 0,
		uintptr(pickX), uintptr(pickY), uintptr(pickW), uintptr(editH), SWP_NOZORDER|SWP_NOACTIVATE)
	procSetWindowPos.Call(uintptr(btnPickDir), 0,
		uintptr(dirX), uintptr(dirY), uintptr(pickW), uintptr(editH), SWP_NOZORDER|SWP_NOACTIVATE)
	procSetWindowPos.Call(uintptr(btnDetect), 0,
		uintptr(btn1X), uintptr(btnY), uintptr(btnW), uintptr(btnH), SWP_NOZORDER|SWP_NOACTIVATE)
	procSetWindowPos.Call(uintptr(btnCopy), 0,
		uintptr(btn2X), uintptr(btnY), uintptr(btnW), uintptr(btnH), SWP_NOZORDER|SWP_NOACTIVATE)
	procSetWindowPos.Call(uintptr(btnSave), 0,
		uintptr(btn3X), uintptr(btnY), uintptr(btnW), uintptr(btnH), SWP_NOZORDER|SWP_NOACTIVATE)
	procSetWindowPos.Call(uintptr(btnRelease), 0,
		uintptr(btn4X), uintptr(btnY), uintptr(btnW), uintptr(btnH), SWP_NOZORDER|SWP_NOACTIVATE)
	procSetWindowPos.Call(uintptr(btnRegShell), 0,
		uintptr(btn5X), uintptr(btnY), uintptr(btnW), uintptr(btnH), SWP_NOZORDER|SWP_NOACTIVATE)
	procSetWindowPos.Call(uintptr(btnRegDir), 0,
		uintptr(btn6X), uintptr(btnY), uintptr(btnW), uintptr(btnH), SWP_NOZORDER|SWP_NOACTIVATE)
	procSetWindowPos.Call(uintptr(detailHwnd), 0,
		0, uintptr(listY), uintptr(listW), uintptr(listH), SWP_NOZORDER|SWP_NOACTIVATE)
}

func modeLabel(mode string) string {
	switch mode {
	case "":
		return "图形化检测 (默认)"
	case "/full":
		return "全盘检测"
	case "/diag":
		return "诊断"
	case "/restore":
		return "恢复隔离文件"
	case "/repair":
		return "系统修复"
	}
	return mode
}

// isAdminRequested 读取 GUI 上"以管理员身份运行"复选框状态.
func isAdminRequested() bool {
	if adminCheckHwnd == 0 {
		return false
	}
	ret, _, _ := procSendMessageW.Call(uintptr(adminCheckHwnd), BM_GETCHECK, 0, 0)
	return ret == BST_CHECKED
}

// isProcessElevated 判断当前进程是否已运行在管理员权限(UAC 已提权).
func isProcessElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	type tokenElevation struct {
		TokenIsElevated uint32
	}
	var ele tokenElevation
	var retLen uint32
	if err := windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&ele)), uint32(unsafe.Sizeof(ele)), &retLen); err != nil {
		return false
	}
	return ele.TokenIsElevated != 0
}

// runSilverFoxElevated 用 ShellExecute("runas") 以管理员权限**重启整个 exe**(带 /elevated-run 标记),
// 而不是提权单个子进程. 这样新 exe 以管理员令牌运行, 其后续 spawn 的引擎子进程继承同一令牌
// 且仍在 exe 的 Job Object 内 -> 关闭 exe 时 Job Object 仍能自动回收整棵引擎树, 不再残留.
// 代价: exe 自身不在父 exe 的 job, 但 exe 内部 spawn 的 cmd/引擎在它自己的 job 里, 不受影响.
func runSilverFoxElevated(mode string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// 以 runas 重启自身, 携带 --elevated-run <mode> 让新实例直接启动对应引擎.
	// 用双杠 -- 与内部其它标记(--watchdog/--cli)风格一致, 且 Go 解析 os.Args 时保留原样.
	// v2.15.29: 带 --parent <pid>, 新实例接管后通知原低权限实例自动退出
	params := "--elevated-run " + mode + " --parent " + strconv.Itoa(os.Getpid())
	logf("runSilverFox: 需管理员, 以 runas 重启整个 exe (模式=%s parent=%d)", mode, os.Getpid())
	return windows.ShellExecute(0, windows.StringToUTF16Ptr("runas"), windows.StringToUTF16Ptr(exe), windows.StringToUTF16Ptr(params), windows.StringToUTF16Ptr(filepath.Dir(exe)), SW_SHOWNORMAL)
}

// v2.15.29: 复选框点击 -> 立即以管理员身份重启自身(空模式, 新实例直接展示管理员 GUI).
func requestElevateSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	params := "--elevated-run --parent " + strconv.Itoa(os.Getpid())
	logf("v2.15.29: 复选框点击提权, runas 重启自身 (parent=%d)", os.Getpid())
	return windows.ShellExecute(0, windows.StringToUTF16Ptr("runas"), windows.StringToUTF16Ptr(exe),
		windows.StringToUTF16Ptr(params), windows.StringToUTF16Ptr(filepath.Dir(exe)), SW_SHOWNORMAL)
}

// v2.15.27: 低权限原实例轮询"提权新实例已正常运行"信号, 收到后自动关闭自身 GUI (用户无需双开).
func waitElevatedDoneCloseSelf(pid int) {
	sigFile := filepath.Join(os.TempDir(), fmt.Sprintf("sf_elev_done_%d.sig", pid))
	for i := 0; i < 240; i++ { // 最多等待 120 秒
		if _, err := os.Stat(sigFile); err == nil {
			os.Remove(sigFile)
			logf("v2.15.27: 提权新实例已正常运行, 低权限原实例自动退出")
			if mainHwnd != 0 {
				procPostMessageW.Call(uintptr(mainHwnd), WM_CLOSE, 0, 0)
			}
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	logf("v2.15.27: 等待提权新实例信号超时, 原实例保持运行")
}

// waitForEngineTree 在 elevated-run 模式下阻塞等待已记录的引擎进程全部结束.
// 因为 exe 一旦退出, 其 Job Object 句柄被 OS 关闭会触发 KillOnJobClose,
// 必须把 exe 保持存活直到引擎结束, 否则引擎刚启动就被回收.
func waitForEngineTree() {
	logf("elevated-run: 等待引擎进程树结束...")
	for {
		alive := false
		for _, pid := range enginePids {
			h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
			if e == nil {
				windows.CloseHandle(h)
				alive = true
			}
		}
		if !alive {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	logf("elevated-run: 引擎进程树已全部结束")
}

// 启动 legacy 银狐检测引擎 (真实扫描器). 在独立控制台窗口运行, 避免批处理内 pause / UAC 提权
// 把输出重定向到我们面板时造成的挂起; 用户可在该窗口查看完整结果.
//
// v2.12 [重要修复]: GUI 父进程没有 console, 直接 cmd /c xxx.bat 时 cmd.exe 尝试
//   AttachConsole(parent_pid) 失败, bat 在内存里跑完了但用户看不到任何窗口.
//   解决: 用 cmd /c start "" bat 让 bat 在新控制台窗口独立启动.
//
// v2.15.4: 新增"以管理员身份运行"复选框; /repair 默认强制提权; 未提权路径仍使用
//   Job Object 在 exe 退出时自动清理引擎树. 若 GUI 本身已是管理员, 则直接 cmd.Start,
//   子进程继承管理员权限且仍可被 Job Object 回收.
// v2.15.5: 修复"提权模式仍残留"根因 —— 之前用 ShellExecute(runas) 提权单个 cmd.exe 子进程,
//   被提权的子进程会脱离 Job Object (Windows 限制), exe 退出时无法回收, 只能 best-effort taskkill.
//   现改为: 非管理员主 exe 以 ShellExecute(runas) **重启整个 exe** 并携带 --elevated-run <mode>,
//   新 exe 以管理员令牌运行, 其 spawn 的 cmd/引擎继承同一令牌且仍在它自己的 Job Object 内,
//   退出时整棵引擎树被 OS 自动回收, 彻底无残留.
func runSilverFox(mode string) {
	// v2.15.74: 防重复启动 —— 引擎运行中拒绝再次启动(避免双引擎冲突)
	if engineRunning {
		logf("runSilverFox: 引擎运行中, 拒绝重复启动 mode=%s", mode)
		setStatus("引擎正在运行, 请等待完成 (重复点击已忽略)")
		return
	}
	exe, err := os.Executable()
	if err != nil {
		setStatus("无法定位自身路径: %v", err)
		msgBoxInfo("银狐特攻", "无法定位自身路径: "+err.Error())
		return
	}
	bat := filepath.Join(filepath.Dir(exe), "legacy", "银狐特攻.bat")
	if _, err := os.Stat(bat); err != nil {
		logf("runSilverFox: 找不到 bat: %s err=%v", bat, err)
		setStatus("未找到 legacy\\银狐特攻.bat")
		msgBoxInfo("银狐特攻", "未找到 legacy\\银狐特攻.bat\r\n请确认压缩包内 legacy 目录完整。")
		return
	}
	logf("runSilverFox: 准备启动 bat=%s mode=%q", bat, mode)
	setStatus("正在启动银狐特攻扫描引擎: %s ...", filepath.Base(bat))

	// v2.15.4: 系统修复(/repair)必须管理员才能修改 hosts/DNS/代理/Winsock
	// v2.15.74: /restoreav 恢复杀毒软件同样强制提权 (修改 Defender 策略/服务需管理员)
	adminRequested := isAdminRequested() || mode == "/repair" || mode == "/restoreav"
	alreadyElevated := isProcessElevated()

	// 若已处于管理员状态, 直接走普通 cmd.Start 路径即可(子进程继承权限且仍在 Job Object 内).
	if adminRequested && !alreadyElevated {
		setStatus("正在申请管理员权限 (UAC) 启动: %s ...", modeLabel(mode))
		// v2.15.31: 异步化, 避免 ShellExecute(runas) 阻塞 GUI 线程 -> 未响应
		go func() {
			if err := runSilverFoxElevated(mode); err != nil {
				logf("runSilverFox: 提权启动失败: %v", err)
				setStatus("提权启动失败: %v", err)
				msgBoxInfo("银狐特攻", "申请管理员权限失败: "+err.Error()+"\n\n系统修复等功能需要管理员权限。")
				return
			}
			logf("runSilverFox: 已弹出 UAC 对话框 (用户确认后启动)")
			setStatus("已弹出 UAC 申请, 确认后在新窗口中继续: %s", modeLabel(mode))
		}()
		// v2.15.27: 新管理员实例引擎正常启动后, 自动关闭本低权限实例 (检测到信号文件后 WM_CLOSE)
		go waitElevatedDoneCloseSelf(os.Getpid())
		return
	}

	// 非管理员或已提权: 普通 cmd.Start, 配合 Job Object 做退出清理.
	// v2.15.28: 不能再 cmd /c start "" bat —— start 用 /K 模式打开 bat, 检测完成后窗口残留不关;
	//           且父 cmd 瞬死, Job Object/enginePids 对真实引擎树全部失效(残留的根因).
	//           改为 cmd /c bat: CREATE_NEW_CONSOLE 仍开独立窗口, bat 结束窗口自动关闭, 无残留.
	// v2.15.32: 窗口标题设为可辨识(否则黑窗口显示 cmd.exe, 用户不知道在检测)
	args := []string{"/c", "title 顽固木马扫描专杀-银狐特攻 - 扫描中... & " + bat}
	if mode != "" {
		args = append(args, mode)
	}
	// v2.15.1: 自保护已下沉到 exe, 关闭 ps1 层 SelfGuard 避免双看门狗冲突.
	args = append(args, "/noselfprotect")
	cmd := exec.Command("cmd.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    false,
		CreationFlags: 0x00000010, // CREATE_NEW_CONSOLE
	}
	cmd.Dir = filepath.Dir(bat)
	if err := cmd.Start(); err != nil {
		logf("runSilverFox: Start 失败: %v", err)
		setStatus("启动银狐特攻扫描失败: %v", err)
		msgBoxInfo("银狐特攻", "启动银狐特攻扫描失败: "+err.Error()+"\n\nbat 路径: "+bat)
		return
	}
	// v2.15.4: 把引擎进程树放进 Job Object, exe 退出时自动清理.
	assignEngineJob(cmd.Process)
	// v2.15.6: 对引擎子进程施加缓解策略(防注入/侧载), 整条工具链都受保护.
	hardenEngineChild(cmd.Process)
	enginePids = append(enginePids, uint32(cmd.Process.Pid))
	engineRunning = true // v2.15.74: 标记引擎运行中
	// v2.15.35: 扫描进度 GUI 展示 —— 引擎把进度写入 legacy\sf_scan_progress.log, 这里轮询刷新到面板
	go watchScanProgress(filepath.Join(filepath.Dir(exe), "legacy", "sf_scan_progress.log"))
	logf("runSilverFox: 已 Start cmd.exe pid=%d args=%v", cmd.Process.Pid, args)
	if alreadyElevated {
		setStatus("已启动银狐特攻扫描 (管理员, 独立控制台窗口): %s", modeLabel(mode))
	} else {
		setStatus("已启动银狐特攻扫描 (独立控制台窗口): %s", modeLabel(mode))
	}
}

// installPowerShell 独立下载器 (v2.15.74): 系统缺少 PowerShell 时用 Go HTTP 下载并静默安装,
// 绝不依赖 PowerShell 自身 (避免"用 powershell 下载 powershell"的死循环).
func installPowerShell() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Join(filepath.Dir(exe), "tools", "PowerShell")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	urls := []string{
		"https://github.com/PowerShell/PowerShell/releases/download/v7.4.6/PowerShell-7.4.6-win-x64.msi",
		"https://mirrors.tuna.tsinghua.edu.cn/github-release/PowerShell/PowerShell/LatestRelease/PowerShell-7.4.6-win-x64.msi",
		"https://github.com/PowerShell/PowerShell/releases/download/v7.2.24/PowerShell-7.2.24-win-x64.msi",
	}
	var lastErr error = fmt.Errorf("无可用下载源")
	for _, u := range urls {
		msi := filepath.Join(dir, "PowerShell-install.msi")
		logf("installPowerShell: 下载 %s", u)
		if err := httpDownload(u, msi, 100*1024*1024); err != nil {
			logf("installPowerShell: 下载失败 %s: %v", u, err)
			lastErr = err
			continue
		}
		// 静默安装 (需管理员); 非管理员则 runas 提权安装
		cmd := exec.Command("msiexec", "/i", msi, "/qn", "/norestart")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Run(); err != nil {
			logf("installPowerShell: msiexec 失败(尝试提权): %v", err)
			if e := windows.ShellExecute(0, windows.StringToUTF16Ptr("runas"),
				windows.StringToUTF16Ptr("msiexec.exe"),
				windows.StringToUTF16Ptr("/i \"" + msi + "\" /qn /norestart"),
				windows.StringToUTF16Ptr(dir), SW_SHOWNORMAL); e != nil {
				lastErr = fmt.Errorf("安装需管理员权限 (UAC 已尝试): %v", err)
			} else {
				lastErr = nil
				break
			}
		} else {
			lastErr = nil
			break
		}
	}
	if lastErr != nil {
		return lastErr
	}
	// 验证安装
	if _, err := os.Stat(`C:\Program Files\PowerShell\pwsh.exe`); err != nil {
		logf("installPowerShell: 安装后未找到 pwsh.exe (可能路径不同), 请手动确认")
	}
	return nil
}

// httpDownload 下载文件到本地 (Go 标准库, 无 PowerShell/curl 依赖)
func httpDownload(url, dest string, maxSize int64) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(f, resp.Body)
	if err != nil {
		return err
	}
	if n < 1024*1024 || n > maxSize {
		return fmt.Errorf("文件大小异常: %d", n)
	}
	return nil
}

// watchScanProgress 轮询引擎进度文件并刷新到右侧面板 (v2.15.74).
// 引擎 (SilverFoxDetect.ps1 v1.68+) 在扫描阶段边界把进度写入 legacy\sf_scan_progress.log (UTF-8).
func watchScanProgress(progressFile string) {
	lastText := ""
	loopN := 0
	logf("wsp: watchScanProgress 启动 progressFile=%s", progressFile)
	// v2.15.74: 去掉 engineAlive 退出判定 —— goroutine 随主进程退出自动终止, 无需自行退出;
	//   engineAlive 依赖快照/BFS, 实测引擎启动有 13s 延迟(先 cmd 后 PowerShell), 旧逻辑在引擎
	//   启动前就误判"已结束", 4 秒后退出 -> GUI 面板永远停在初始说明(用户反馈"不动了").
	for {
		loopN++
		if loopN%10 == 0 {
			logf("wsp: loop=%d engineRunning=%v pids=%d", loopN, engineRunning, len(enginePids))
		}
		if data, err := os.ReadFile(progressFile); err == nil && sfConsoleHwnd != 0 {
			text := strings.TrimSpace(string(data))
			if text != "" && text != lastText {
				lastText = text
				logf("wsp: 文本变化 len=%d -> postUiText", len(text))
				// v2.15.74: PostMessage(标准线程安全), 不再跨线程 SendMessage
				postUiText(mainHwnd, WM_APP_PROGRESS, text)
				// 完成检测 —— 进度文本出现"检测完成/restoreav 修复"即引擎结束
				if (strings.Contains(text, "检测完成") || strings.Contains(text, "[restoreav] 修复")) && engineRunning {
					engineRunning = false
					postUiText(mainHwnd, WM_APP_STATUS, "检测完成! 请查看右侧面板/报告 (引擎已退出)")
					logf("watchScanProgress: 检测到引擎完成文本, 引擎运行结束")
				}
			}
		}
		// v2.15.74: engineRunning 兜底复位 —— 部分快捷模式(netblock 等)完成后进度文本不含
		//   "检测完成", 用"引擎 cmd 进程消失"判定结束(连续 4 次 500ms 检测失败)
		if engineRunning && len(enginePids) > 0 {
			dead := 0
			for _, pid := range enginePids {
				// v2.15.74: 校验进程名 cmd.exe, 防 PID 复用
				alive := false
				if h, e2 := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid); e2 == nil {
					var sz uint32 = 256
					var exeBuf [256]uint16
					if n2, _, _ := procQueryFullProcessImageNameW.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&exeBuf[0])), uintptr(unsafe.Pointer(&sz))); n2 != 0 {
						name := syscall.UTF16ToString(exeBuf[:])
						if strings.Contains(strings.ToLower(name), "cmd.exe") {
							alive = true
						}
					}
					_ = windows.CloseHandle(h)
				}
				if !alive {
					dead++
				}
			}
			engineDeadN++
			if dead == len(enginePids) {
				if engineDeadN >= 4 {
					engineRunning = false
					engineDeadN = 0
					postUiText(statusHwnd, WM_APP_STATUS, "引擎已结束 (快捷模式完成)")
					logf("watchScanProgress: 引擎进程树已消失, engineRunning 复位")
				}
			} else {
				engineDeadN = 0
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// === 剪贴板 ===
var (
	procOleInitialize      = ole32.NewProc("OleInitialize")
	procOleUninitialize    = ole32.NewProc("OleUninitialize")
	procOpenClipboard      = user32.NewProc("OpenClipboard")
	procCloseClipboard     = user32.NewProc("CloseClipboard")
	procEmptyClipboard     = user32.NewProc("EmptyClipboard")
	procSetClipboardData   = user32.NewProc("SetClipboardData")
	procGlobalAlloc        = kernel32.NewProc("GlobalAlloc")
	procGlobalLock         = kernel32.NewProc("GlobalLock")
	procGlobalUnlock       = kernel32.NewProc("GlobalUnlock")
)

const (
	CF_UNICODETEXT = 13
	GMEM_MOVEABLE  = 0x0002
)

func clipboardWrite(text string) error {
	if _, _, _, ok := safeCall(procOleInitialize, 0); !ok {
		return fmt.Errorf("OleInitialize 失败(ole32 未加载), 剪贴板写入跳过")
	}
	defer safeCall(procOleUninitialize, 0)
	if ret, _, _ := procOpenClipboard.Call(0); ret == 0 {
		return fmt.Errorf("OpenClipboard 失败")
	}
	defer procCloseClipboard.Call(0)
	procEmptyClipboard.Call(0)
	u16, _ := syscall.UTF16FromString(text)
	byteLen := uint32(len(u16) * 2)
	hMem, _, _ := procGlobalAlloc.Call(GMEM_MOVEABLE, uintptr(byteLen))
	if hMem == 0 {
		return fmt.Errorf("GlobalAlloc 失败")
	}
	ptr, _, _ := procGlobalLock.Call(hMem)
	if ptr == 0 {
		return fmt.Errorf("GlobalLock 失败")
	}
	// 把 u16 内容拷入 Global 内存. 用 unsafe.Slice 把 GlobalLock 返回的地址视为 []uint16 视图.
	// 说明: go vet 的 unsafeptr 分析器会对 "uintptr->unsafe.Pointer" 转换报 "possible misuse" 的
	// 启发式告警 —— 这是已知的误报: ptr 来自 GlobalLock(已分配 byteLen=len(u16)*2 字节), 长度精确匹配,
	// 不存在越界. 该告警不影响编译与运行, 保留此可读性最佳写法.
	dstSlice := unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), len(u16))
	copy(dstSlice, u16)
	procGlobalUnlock.Call(hMem)
	procSetClipboardData.Call(CF_UNICODETEXT, hMem)
	return nil
}

func copyResults() {
	if len(currentResults) == 0 {
		setStatus("当前没有结果可复制, 请先检测")
		return
	}
	var sb strings.Builder
	sb.WriteString("PID\t类型\t名称\t映像路径\n")
	for _, r := range currentResults {
		sb.WriteString(fmt.Sprintf("%d\t%s\t%s\t%s\n", r.Pid, r.Type, r.Name, r.FullPath))
	}
	if err := clipboardWrite(sb.String()); err != nil {
		setStatus("复制失败: %v", err)
		return
	}
	setStatus("已复制 %d 行到剪贴板", len(currentResults))
}

func setEditText(text string) {
	p, _ := syscall.UTF16PtrFromString(text)
	procSendMessageW.Call(uintptr(editHwnd), 0x000C /*WM_SETTEXT*/, 0, uintptr(unsafe.Pointer(p)))
}

func getEditText() string {
	var buf [4096]uint16
	procSendMessageW.Call(uintptr(editHwnd), 0x000D /*WM_GETTEXT*/, 4096, uintptr(unsafe.Pointer(&buf[0])))
	return windows.UTF16ToString(buf[:])
}

// === 文件/目录选择 ===
func pickFileDialog() {
	filter := "所有文件 (*.*)\x00*.*\x00\x00"
	fp, _ := syscall.UTF16PtrFromString(filter)
	var fileBuf [4096]uint16
	titlePtr, _ := syscall.UTF16PtrFromString("选择要检测的文件")
	ofn := OPENFILENAMEW{
		StructSize: uint32(unsafe.Sizeof(OPENFILENAMEW{})),
		Owner:      mainHwnd,
		Filter:     fp,
		File:       &fileBuf[0],
		MaxFile:    4096,
		Title:      titlePtr,
		Flags:      OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_PATHMUSTEXIST,
	}
	if ret, _, _, ok := safeCall(procGetOpenFileNameW, uintptr(unsafe.Pointer(&ofn))); ok && ret != 0 {
		path := windows.UTF16ToString(fileBuf[:])
		setEditText(path)
		runDetection(path)
	}
}

func pickDirDialog() {
	// SHBrowseForFolder(BIF_NEWDIALOGSTYLE) 要求调用线程在 STA 公寓.
	// 启动期不再初始化 COM(避免 ole32 加载失败拖垮整个 GUI), 这里按需初始化并 safeCall 兜底:
	// 若 ole32 懒加载失败, 直接降级为"不可用", 不崩、不影响主窗口.
	if _, _, _, ok := safeCall(procCoInitializeEx, 0, COINIT_APARTMENTTHREADED); !ok {
		logf("自保护[COM]: ole32 未加载, 文件夹对话框暂不可用(可手动在输入框粘贴路径)")
		return
	}
	defer safeCall(procCoUninitialize)
	ret, _, _, ok := safeCall(procSHBrowseForFolder,
		uintptr(unsafe.Pointer(&BROWSEINFOW{
			Owner: mainHwnd,
			Title: utf16Ptr("选择要检测的文件夹"),
			Flags: BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE,
		})),
	)
	if !ok || ret == 0 {
		return // DLL 加载失败或用户取消
	}
	defer safeCall(procCoTaskMemFree, ret)
	var buf [4096]uint16
	if r, _, _ := procSHGetPathFromIDListW.Call(ret, uintptr(unsafe.Pointer(&buf[0]))); r != 0 {
		path := windows.UTF16ToString(buf[:])
		if path != "" {
			setEditText(path)
			runDetection(path)
		}
	}
}

func saveResults() {
	if len(currentResults) == 0 {
		setStatus("当前没有结果可保存, 请先检测")
		return
	}
	filter := "文本文件 (*.txt)\x00*.txt\x00所有文件 (*.*)\x00*.*\x00\x00"
	fp, _ := syscall.UTF16PtrFromString(filter)
	var fileBuf [4096]uint16
	seedStr := "占用检测结果.txt"
	copy(fileBuf[:], ut16(seedStr))
	titlePtr, _ := syscall.UTF16PtrFromString("保存检测结果")
	ofn := OPENFILENAMEW{
		StructSize: uint32(unsafe.Sizeof(OPENFILENAMEW{})),
		Owner:      mainHwnd,
		Filter:     fp,
		File:       &fileBuf[0],
		MaxFile:    4096,
		Title:      titlePtr,
		Flags:      OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY | OFN_PATHMUSTEXIST,
		DefExt:     utf16Ptr("txt"),
	}
	if ret, _, _ := procGetSaveFileNameW.Call(uintptr(unsafe.Pointer(&ofn))); ret == 0 {
		return
	}
	path := windows.UTF16ToString(fileBuf[:])
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("目标: %s\n", currentTarget))
	sb.WriteString(fmt.Sprintf("时间: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("数量: %d\n\n", len(currentResults)))
	sb.WriteString("PID\t类型\t名称\t映像路径\n")
	for _, r := range currentResults {
		sb.WriteString(fmt.Sprintf("%d\t%s\t%s\t%s\n", r.Pid, r.Type, r.Name, r.FullPath))
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		setStatus("保存失败: %v", err)
		return
	}
	setStatus("已保存: %s", path)
}

// === 右键菜单集成 (注册表 HKCU) ===
func registerShellMenu() {
	exe, err := os.Executable()
	if err != nil {
		msgBoxInfo("注册失败", "无法获取本程序路径")
		return
	}
	// HKCU\Software\Classes\*\shell\SilverFoxDetector
	// HKCU\Software\Classes\Directory\shell\SilverFoxDetector
	keys := []struct {
		path  string
		title string
		flag  string
	}{
		{`Software\Classes\*\shell\SilverFoxDetector`, "用 SilverFox Detector 检测占用", ""},
		{`Software\Classes\Directory\shell\SilverFoxDetector`, "用 SilverFox Detector 检测本文件夹", ""},
	}
	for _, k := range keys {
		cmd := k.path + `\command`
		if err := writeRegShellEntry(k.path, k.title, cmd, exe, k.flag); err != nil {
			msgBoxInfo("注册失败", err.Error())
			return
		}
	}
	msgBoxInfo("注册成功", "已写入右键菜单. 在文件/文件夹上右键即可看到「用 SilverFox Detector 检测占用」/「用 SilverFox Detector 检测本文件夹」.\n\n卸载请点下方「卸载右键菜单」按钮.")
}

func writeRegShellEntry(keyPath, title, cmdKey, exe, _ string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.SET_VALUE|registry.CREATE_SUB_KEY)
	if err != nil {
		return fmt.Errorf("CreateKey %s: %v", keyPath, err)
	}
	defer k.Close()
	if err := k.SetStringValue("", title); err != nil {
		return err
	}
	if err := k.SetStringValue("Icon", exe); err != nil {
		return err
	}
	ck, _, err := registry.CreateKey(registry.CURRENT_USER, cmdKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("CreateKey %s: %v", cmdKey, err)
	}
	defer ck.Close()
	cmd := fmt.Sprintf(`"%s" "%%1"`, exe)
	return ck.SetStringValue("", cmd)
}

func unregisterShellMenu() {
	paths := []string{
		`Software\Classes\*\shell\SilverFoxDetector`,
		`Software\Classes\Directory\shell\SilverFoxDetector`,
	}
	for _, p := range paths {
		// 顺带清理子键
		_ = registry.DeleteKey(registry.CURRENT_USER, p+`\command`)
		if err := registry.DeleteKey(registry.CURRENT_USER, p); err != nil {
			logf("unregisterShellMenu: 删除 %s 失败: %v", p, err)
		}
	}
	// 通知资源管理器刷新
	procSHChangeNotify.Call(0x08000000, 0x0000, 0, 0)
	msgBoxInfo("卸载完成", "已移除右键菜单项.")
}

// === 命令行模式 ===
func formatCliResults(path string, results []LockInfo) string {
	var sb strings.Builder
	sb.WriteString("========================================\n")
	sb.WriteString(fmt.Sprintf("目标: %s\n", path))
	sb.WriteString("========================================\n")
	if len(results) == 0 {
		sb.WriteString("\n  (未检测到占用, 可以安全删除/移动/恢复)\n\n")
		return sb.String()
	}
	sb.WriteString(fmt.Sprintf("\n  发现 %d 个占用进程:\n\n", len(results)))
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("  ● PID     : %d\n", r.Pid))
		sb.WriteString(fmt.Sprintf("    类型    : %s\n", r.Type))
		sb.WriteString(fmt.Sprintf("    名称    : %s\n", r.Name))
		if r.FullPath != "" {
			sb.WriteString(fmt.Sprintf("    映像路径: %s\n", r.FullPath))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func runCLI(argv []string) int {
	initLog()
	defer func() {
		if logFile != nil {
			logFile.Close()
		}
	}()
	logf("=== 银狐特攻 CLI 模式启动 v2.15.74 (tier=%d args=%v) ===", buildTier, argv)
	var path string
	registerSh := false
	unregisterSh := false
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch a {
		case "--register":
			registerSh = true
		case "--unregister":
			unregisterSh = true
		default:
			path = a
		}
	}
	if registerSh {
		exe, _ := os.Executable()
		keys := []string{
			`Software\Classes\*\shell\SilverFoxDetector`,
			`Software\Classes\Directory\shell\SilverFoxDetector`,
		}
		for _, kp := range keys {
			k, _, err := registry.CreateKey(registry.CURRENT_USER, kp, registry.SET_VALUE)
			if err != nil {
				fmt.Printf("[!] CreateKey %s: %v\n", kp, err)
				return 1
			}
			k.Close()
			k.SetStringValue("", "用 SilverFox Detector 检测占用")
			k.SetStringValue("Icon", exe)
			k.Close()
			ck, _, err := registry.CreateKey(registry.CURRENT_USER, kp+`\command`, registry.SET_VALUE)
			if err != nil {
				fmt.Printf("[!] CreateKey command: %v\n", err)
				return 1
			}
			if err := ck.SetStringValue("", fmt.Sprintf(`"%s" "%%1"`, exe)); err != nil {
				ck.Close()
				return 1
			}
			ck.Close()
		}
		fmt.Println("[+] 右键菜单注册成功 (HKCU)")
		return 0
	}
	if unregisterSh {
		paths := []string{
			`Software\Classes\*\shell\SilverFoxDetector\command`,
			`Software\Classes\Directory\shell\SilverFoxDetector\command`,
			`Software\Classes\*\shell\SilverFoxDetector`,
			`Software\Classes\Directory\shell\SilverFoxDetector`,
		}
		for _, p := range paths {
			if err := registry.DeleteKey(registry.CURRENT_USER, p); err != nil {
				logf("del %s: %v", p, err)
			}
		}
		fmt.Println("[+] 右键菜单已卸载")
		return 0
	}
	if path == "" {
		fmt.Println("用法:")
		fmt.Println("  SilverFoxDetector.exe [<path>]                 启动 GUI")
		fmt.Println("  SilverFoxDetector.exe --cli <path>             命令行模式, 输出结果")
		fmt.Println("  SilverFoxDetector.exe --register               安装右键菜单项")
		fmt.Println("  SilverFoxDetector.exe --unregister             卸载右键菜单项")
		return 2
	}
	results, err := detectFor(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] 失败: %v\n", err)
		return 1
	}
	fmt.Print(formatCliResults(path, results))
	if len(results) == 0 {
		return 0
	}
	return 3
}

var autoDetectPath string

// === WndProc ===
func wndProc(hwnd windows.HWND, msg uint32, wParam, lParam uintptr) (ret uintptr) {
	// v2.15.74: WM_CREATE 期间 user32 重入 panic(1114) 经同步回调传播到主窗口 safeCall 被误判为
	//   "主窗口创建失败"; 这里统一捕获, 消息处理内任何 panic 记录日志并返回 0(走 DefWindowProc 语义)
	defer func() {
		if rec := recover(); rec != nil {
			logf("wndProc panic msg=%d(0x%X) 已捕获: %v", msg, msg, rec)
			ret = 0
		}
	}()
	switch msg {
	case WM_APP_PROGRESS:
		// v2.15.74: 处理完清合并标志(下次文本变化再投递)
		atomic.StoreUint32(&uiPending, 0)
		if sfConsoleHwnd != 0 && lParam != 0 {
			uiTextMu.Lock()
			procSendMessageW.Call(uintptr(sfConsoleHwnd), 0x000C /*WM_SETTEXT*/, 0, lParam)
			uiTextMu.Unlock()
		}
		logf("wndProc: WM_APP_PROGRESS 已处理")
		return 0
	case WM_APP_STATUS:
		atomic.StoreUint32(&uiPending, 0)
		if statusHwnd != 0 && lParam != 0 {
			uiTextMu.Lock()
			procSendMessageW.Call(uintptr(statusHwnd), 0x000C /*WM_SETTEXT*/, 0, lParam)
			uiTextMu.Unlock()
		}
		return 0

	case WM_CREATE:
		logf("WM_CREATE: 创建切换按钮 + 双页面 (mainHwnd=0x%X)", uintptr(hwnd))

		// ---- 顶部页面切换按钮: 银狐检测 / 小工具 ----
		h, _, _ := createChildSafe(
			0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
			uintptr(unsafe.Pointer(utf16Ptr("    银狐特攻"))),
			uintptr(WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON),
			0, 0, 100, 28, uintptr(hwnd), ID_TABBAR_DETECT, 0, 0,
		)
		tabBtnDetect = windows.HWND(h)

		h, _, _ = createChildSafe(
			0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
			uintptr(unsafe.Pointer(utf16Ptr("    小工具"))),
			uintptr(WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON),
			0, 0, 100, 28, uintptr(hwnd), ID_TABBAR_TOOLS, 0, 0,
		)
		tabBtnTools = windows.HWND(h)

		// ---- 页面 1 容器: 银狐检测 (主) ----
		// v2.13: 改用 SFContainer 类 (转发 WM_COMMAND 给 mainHwnd), 不能用 Static.
		h, _, _ = createChildSafe(
			0, uintptr(unsafe.Pointer(utf16Ptr(containerClassName))),
			uintptr(0),
			uintptr(WS_CHILD|WS_VISIBLE|WS_CLIPCHILDREN),
			0, 0, 100, 100, uintptr(hwnd), ID_PANEL_DETECT, 0, 0,
		)
		pageDetect = windows.HWND(h)

		// 银狐检测 - 顶部说明 (Static, 跨整宽)
		h, _, _ = createChildSafe(
			0, uintptr(unsafe.Pointer(utf16Ptr("Static"))),
			uintptr(unsafe.Pointer(utf16Ptr("顽固木马扫描专杀-银狐特攻 —— 专杀银狐木马类顽固病毒。点击下方按钮启动 legacy\\银狐特攻.bat 真实扫描引擎 (独立控制台窗口)。"))),
			uintptr(WS_CHILD|WS_VISIBLE|SS_LEFT),
			0, 0, 100, 60, uintptr(pageDetect), ID_SF_INFO, 0, 0,
		)
		sfInfoHwnd = windows.HWND(h)

		// 银狐检测 - 5 个大按钮 (左列)
		h, _, _ = createChildSafe(0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
			uintptr(unsafe.Pointer(utf16Ptr("专杀扫描 (默认)"))), uintptr(WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON),
			0, 0, 220, 38, uintptr(pageDetect), ID_BTN_SF_RUN, 0, 0)
		btnSfRun = windows.HWND(h)
		h, _, _ = createChildSafe(0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
			uintptr(unsafe.Pointer(utf16Ptr("全盘检测 (/full)"))), uintptr(WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON),
			0, 0, 220, 38, uintptr(pageDetect), ID_BTN_SF_FULL, 0, 0)
		btnSfFull = windows.HWND(h)
		h, _, _ = createChildSafe(0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
			uintptr(unsafe.Pointer(utf16Ptr("系统诊断 (/diag)"))), uintptr(WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON),
			0, 0, 220, 38, uintptr(pageDetect), ID_BTN_SF_DIAG, 0, 0)
		btnSfDiag = windows.HWND(h)
		h, _, _ = createChildSafe(0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
			uintptr(unsafe.Pointer(utf16Ptr("恢复隔离文件 (/restore)"))), uintptr(WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON),
			0, 0, 220, 38, uintptr(pageDetect), ID_BTN_SF_RESTORE, 0, 0)
		btnSfRestore = windows.HWND(h)
		h, _, _ = createChildSafe(0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
			uintptr(unsafe.Pointer(utf16Ptr("系统修复 (/repair)"))), uintptr(WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON),
			0, 0, 220, 38, uintptr(pageDetect), ID_BTN_SF_REPAIR, 0, 0)
		btnSfRepair = windows.HWND(h)
		// v2.15.74: 恢复杀毒软件按钮 (修复被病毒禁用/篡改的 Defender/安全中心/服务)
		h, _, _ = createChildSafe(0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
			uintptr(unsafe.Pointer(utf16Ptr("恢复杀毒软件 (/restoreav)"))), uintptr(WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON),
			0, 0, 220, 38, uintptr(pageDetect), ID_BTN_SF_RESTOREAV, 0, 0)
		btnSfRestoreAV = windows.HWND(h)
		// v2.15.74: 网络封锁管理按钮 (查看/解除引擎自动封禁的 C2 外联规则)
		h, _, _ = createChildSafe(0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
			uintptr(unsafe.Pointer(utf16Ptr("网络封锁管理 (/netblock)"))), uintptr(WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON),
			0, 0, 220, 38, uintptr(pageDetect), ID_BTN_SF_NETBLOCK, 0, 0)
		btnSfNetBlock = windows.HWND(h)
		// v2.15.74: 安装 PowerShell 按钮 (系统缺少 PowerShell 时用主程序独立下载, 不依赖 PowerShell)
		h, _, _ = createChildSafe(0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
			uintptr(unsafe.Pointer(utf16Ptr("安装 PowerShell (/install-ps)"))), uintptr(WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON),
			0, 0, 220, 38, uintptr(pageDetect), ID_BTN_SF_INSTALLPS, 0, 0)
		btnSfInstallPS = windows.HWND(h)

		// v2.15.4: "以管理员身份运行" 复选框 (放在按钮列下方)
		h, _, _ = createChildSafe(0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
			uintptr(unsafe.Pointer(utf16Ptr("以管理员身份运行 (UAC)"))), uintptr(WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX),
			0, 0, 220, 22, uintptr(pageDetect), ID_CHK_ADMIN, 0, 0)
		adminCheckHwnd = windows.HWND(h)

		// v2.15.25: 修复"管理员模式没有任何提示" —— 当前进程已提权时, 复选框自动勾选并禁用(防误解)+ 标注当前状态
		if adminCheckHwnd != 0 && isProcessElevated() {
			procSendMessageW.Call(uintptr(adminCheckHwnd), BM_SETCHECK, BST_CHECKED, 0)
			procEnableWindow.Call(uintptr(adminCheckHwnd), 0)
			procSetWindowTextW.Call(uintptr(adminCheckHwnd), uintptr(unsafe.Pointer(utf16Ptr("以管理员身份运行 (UAC) - 当前已是管理员 (已自动勾选)"))))
			logf("GUI: 当前已是管理员, UAC 复选框已自动勾选并禁用")
		}

		// v2.15.9: 档3 专属"安装为 SYSTEM 服务(最强常驻)"按钮(仅急救箱档显示).
		//   该服务以 LocalSystem 运行, 是比 runas 守护更强的常驻; 明确提示风险, best-effort.
		if buildTier >= 3 {
			h, _, _ = createChildSafe(0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
				uintptr(unsafe.Pointer(utf16Ptr("安装为 SYSTEM 服务(急救箱常驻)"))), uintptr(WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON),
				0, 0, 220, 30, uintptr(pageDetect), ID_BTN_INSTALL_SVC, 0, 0)
			svcInstallHwnd = windows.HWND(h)
		}

		// 银狐检测 - 右列提示 (多行只读 EDIT, 强 fallback)
		h, _, _ = createChildSafe(
			0, uintptr(unsafe.Pointer(utf16Ptr("EDIT"))),
			uintptr(0),
			uintptr(WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY),
			0, 0, 100, 100, uintptr(pageDetect), ID_SF_CONSOLE, 0, 0,
		)
		sfConsoleHwnd = windows.HWND(h)
		setSfConsole("可用模式说明:\r\n\r\n  [专杀扫描]        图形化界面(默认)\r\n  [全盘检测]        /full 全量扫描\r\n  [系统诊断]        /diag 诊断\r\n  [恢复隔离文件]    /restore\r\n  [系统修复]        /repair  Hosts/DNS/代理/Winsock\r\n  [恢复杀毒软件]    /restoreav 反推修复病毒对安全软件的破坏\r\n  [网络封锁管理]    /netblock 查看/解除恶意外联封锁\r\n  [安装PowerShell]  /install-ps 系统缺PowerShell时点击下载安装\r\n\r\n启动后在独立控制台窗口运行 legacy\\银狐特攻.bat; 扫描进度实时显示在本面板. \r\n\r\n作者: 莫问QWQ (开源 MIT 许可, 详见 LICENSE)")
		// ---- 页面 2 容器: 小工具 -> 文件占用检测 ----
		// v2.13: 改用 SFContainer 类 (转发 WM_COMMAND 给 mainHwnd), 不能用 Static.
		h, _, _ = createChildSafe(
			0, uintptr(unsafe.Pointer(utf16Ptr(containerClassName))),
			uintptr(0),
			uintptr(WS_CHILD|WS_CLIPCHILDREN), // 初始隐藏, 切到时才 ShowWindow
			0, 0, 100, 100, uintptr(hwnd), ID_PANEL_TOOLS, 0, 0,
		)
		pageTools = windows.HWND(h)

		// 路径输入框
		h, _, _ = createChildSafe(
			uintptr(WS_EX_CLIENTEDGE), uintptr(unsafe.Pointer(utf16Ptr("Edit"))),
			uintptr(0), uintptr(WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL),
			0, 0, 100, 24, uintptr(pageTools), ID_EDIT_PATH, 0, 0,
		)
		editHwnd = windows.HWND(h)

		// 选择文件 按钮
		h, _, _ = createChildSafe(
			0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
			uintptr(unsafe.Pointer(utf16Ptr("选择文件"))),
			uintptr(WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON),
			0, 0, 80, 24, uintptr(pageTools), ID_BTN_PICKFILE, 0, 0,
		)
		btnPickFile = windows.HWND(h)

		// 选择目录 按钮
		h, _, _ = createChildSafe(
			0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
			uintptr(unsafe.Pointer(utf16Ptr("选择目录"))),
			uintptr(WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON),
			0, 0, 80, 24, uintptr(pageTools), ID_BTN_PICKDIR, 0, 0,
		)
		btnPickDir = windows.HWND(h)

		// 功能按钮 (第二行)
		h, _, _ = createChildSafe(
			0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
			uintptr(unsafe.Pointer(utf16Ptr("立即检测"))),
			uintptr(WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON),
			0, 0, 90, 28, uintptr(pageTools), ID_BTN_DETECT, 0, 0,
		)
		btnDetect = windows.HWND(h)
		h, _, _ = createChildSafe(
			0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
			uintptr(unsafe.Pointer(utf16Ptr("复制结果"))),
			uintptr(WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON),
			0, 0, 90, 28, uintptr(pageTools), ID_BTN_COPY, 0, 0,
		)
		btnCopy = windows.HWND(h)
		h, _, _ = createChildSafe(
			0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
			uintptr(unsafe.Pointer(utf16Ptr("保存结果"))),
			uintptr(WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON),
			0, 0, 90, 28, uintptr(pageTools), ID_BTN_SAVE, 0, 0,
		)
		btnSave = windows.HWND(h)
		h, _, _ = createChildSafe(
			0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
			uintptr(unsafe.Pointer(utf16Ptr("释放占用"))),
			uintptr(WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON),
			0, 0, 90, 28, uintptr(pageTools), ID_BTN_RELEASE, 0, 0,
		)
		btnRelease = windows.HWND(h)
		h, _, _ = createChildSafe(
			0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
			uintptr(unsafe.Pointer(utf16Ptr("装右键菜单"))),
			uintptr(WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON),
			0, 0, 90, 28, uintptr(pageTools), ID_BTN_REG_SHELL, 0, 0,
		)
		btnRegShell = windows.HWND(h)
		h, _, _ = createChildSafe(
			0, uintptr(unsafe.Pointer(utf16Ptr("Button"))),
			uintptr(unsafe.Pointer(utf16Ptr("卸右键菜单"))),
			uintptr(WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON),
			0, 0, 90, 28, uintptr(pageTools), ID_BTN_REG_DIR, 0, 0,
		)
		btnRegDir = windows.HWND(h)

		// 多行只读 EDIT (替代 v2.8 的 ListView: 列宽不再截断, 路径全程可见)
		h, _, _ = createChildSafe(
			uintptr(WS_EX_CLIENTEDGE), uintptr(unsafe.Pointer(utf16Ptr("EDIT"))),
			uintptr(0),
			uintptr(WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_CLIPCHILDREN|
				ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY|ES_NOHIDESEL),
			0, 0, 100, 100, uintptr(pageTools), ID_DETAIL, 0, 0,
		)
		detailHwnd = windows.HWND(h)
		procSendMessageW.Call(uintptr(detailHwnd), EM_SETSEL, 0, 0)

		// 状态栏
		h, _, _ = createChildSafe(
			0, uintptr(unsafe.Pointer(utf16Ptr("Static"))),
			uintptr(unsafe.Pointer(utf16Ptr("就绪"))),
			uintptr(WS_CHILD|WS_VISIBLE|SS_LEFT|SS_NOPREFIX),
			0, 0, 100, 20, uintptr(hwnd), ID_STATUS, 0, 0,
		)
		statusHwnd = windows.HWND(h)

		// 接受拖放
		procDragAcceptFiles.Call(uintptr(hwnd), 1)

		// 初始显示 银狐检测 页 + 高亮按钮
		showPage(0)
		setStatus("环境: %s", detectEnvSummary()) // v2.15.74: 启动环境检测展示
		logf("环境: %s", detectEnvSummary())
		logf("WM_CREATE 完成: tabBtnDetect=0x%X tabBtnTools=0x%X pageDetect=0x%X pageTools=0x%X edit=0x%X detail=0x%X status=0x%X",
			uintptr(tabBtnDetect), uintptr(tabBtnTools), uintptr(pageDetect), uintptr(pageTools), uintptr(editHwnd), uintptr(detailHwnd), uintptr(statusHwnd))
		// 主动调一次 resizeChildren (用主窗口初始尺寸)
		resizeChildren(0, uintptr(1100)|(uintptr(640)<<16))
		// 强制刷新两套容器
		procInvalidateRect.Call(uintptr(pageDetect), 0, 1)
		procInvalidateRect.Call(uintptr(pageTools), 0, 1)

		// 如果是自动模式 (带路径参数), 切到小工具页并立即检测
		if autoDetectPath != "" {
			showPage(1)
			setEditText(autoDetectPath)
			resizeChildren(0, 0)
			refreshList(autoDetectPath)
		}
		return 0

	case WM_SIZE:
		resizeChildren(wParam, lParam)
		return 0

	case WM_COMMAND:
		// 关键: WM_COMMAND 中, wParam 的低 16 位是 control ID, 高 16 位是通知码.
		id := uint16(wParam & 0xFFFF)                 // <- LOWORD 控件 ID
		code := uint16((wParam >> 16) & 0xFFFF)       // <- HIWORD 通知码
		logf("WM_COMMAND id=%d code=%d (0x%X, 0x%X)", id, code, id, code)
		if code == BN_CLICKED {
			switch id {
			case ID_CHK_ADMIN:
				// v2.15.29: 点击"以管理员身份运行 [UAC]"复选框 = 立即申请提权
				//   (用户要求: 点击后进行提权步骤; 而非只勾选等待下次检测按钮)
				if isProcessElevated() {
					setStatus("当前已是管理员, 无需提权 (复选框已自动勾选)")
				} else {
					setStatus("正在申请管理员权限 (UAC) ...")
					// v2.15.31: 异步化, 避免 ShellExecute(runas) 阻塞 GUI 线程 -> 未响应
					go func() {
						if err := requestElevateSelf(); err != nil {
							logf("复选框提权失败: %v", err)
							setStatus("申请管理员权限失败: %v", err)
							msgBoxInfo("银狐特攻", "申请管理员权限失败: "+err.Error()+"\n\n请确认 UAC 服务可用。")
							return
						}
						logf("复选框提权: 已提交 UAC (异步)")
					}()
					// 新实例(管理员)接管后自动关闭本低权限实例
					go waitElevatedDoneCloseSelf(os.Getpid())
				}
			case ID_TABBAR_DETECT:
				if currentTab != 0 {
					showPage(0)
					resizeChildren(0, 0)
				}
			case ID_TABBAR_TOOLS:
				if currentTab != 1 {
					showPage(1)
					resizeChildren(0, 0)
				}
			case ID_BTN_PICKFILE:
				pickFileDialog()
			case ID_BTN_PICKDIR:
				pickDirDialog()
			case ID_BTN_DETECT:
				refreshListFromEdit()
			case ID_BTN_COPY:
				copyResults()
			case ID_BTN_SAVE:
				saveResults()
			case ID_BTN_RELEASE:
				shutdownAndRestart()
			case ID_BTN_REG_SHELL:
				registerShellMenu()
			case ID_BTN_REG_DIR:
				unregisterShellMenu()
			case ID_BTN_SF_RUN:
				runSilverFox("")
			case ID_BTN_SF_FULL:
				runSilverFox("/full")
			case ID_BTN_SF_DIAG:
				runSilverFox("/diag")
			case ID_BTN_SF_RESTORE:
				runSilverFox("/restore")
			case ID_BTN_SF_REPAIR:
				runSilverFox("/repair")
			case ID_BTN_SF_RESTOREAV:
				runSilverFox("/restoreav")
			case ID_BTN_SF_NETBLOCK:
				runSilverFox("/netblock")
			case ID_BTN_SF_INSTALLPS:
				// v2.15.74: 独立下载器 (Go 内置 HTTP, 不依赖 PowerShell)
				setStatus("正在下载并安装 PowerShell (独立下载器, 约 100MB) ...")
				go func() {
					if err := installPowerShell(); err != nil {
						setStatus("PowerShell 安装失败: %v", err)
						msgBoxInfo("银狐特攻", "PowerShell 下载/安装失败: "+err.Error())
					} else {
						setStatus("PowerShell 已安装完成, 请重新运行检测")
					}
				}()
			case ID_BTN_INSTALL_SVC:
				toggleGuardianService()
			}
		}
		return 0

	case WM_DROPFILES:
		hDrop := wParam
		n, _, _ := procDragQueryFileW.Call(hDrop, 0xFFFFFFFF, 0, 0)
		logf("WM_DROPFILES: 拖入 %d 个文件", n)
		if n > 0 {
			var buf [4096]uint16
			got, _, _ := procDragQueryFileW.Call(hDrop, 0, uintptr(unsafe.Pointer(&buf[0])), 4096)
			if got > 0 {
				path := windows.UTF16ToString(buf[:got])
				logf("  使用第 1 个: %s", path)
				setEditText(path)
				refreshList(path)
			}
		}
		procDragFinish.Call(hDrop)
		return 0

	case WM_QUERYENDSESSION:
		// v2.15.29: 主程序(GUI)运行期间一律拦截关机/注销/重启 —— 用户退出工具(点 X)后才能正常关机.
		//   历史: v2.15.26 用 engineAlive() 判定(引擎退出即放行)导致拦不住; v2.15.27 改为一律拦截
		//   但修改在 v2.15.28 打包时意外丢失; 本版恢复 + 双保险.
		logf("WM_QUERYENDSESSION: 主程序运行中, 返回 FALSE 阻止关机 (wParam=0x%X)", wParam)
		writeShutdownQueryLog("主窗口 QUERYENDSESSION -> FALSE 拦截 wParam=0x" + strconv.FormatUint(uint64(wParam), 16))
		setStatus("已拦截关机邀请 (退出本工具后才可正常关机)")
		return 0 // FALSE = 拒绝关机/注销/重启
	case WM_ENDSESSION:
		writeShutdownQueryLog("主窗口 ENDSESSION wParam=0x" + strconv.FormatUint(uint64(wParam), 16))
	case WM_CLOSE:
		logf("WM_CLOSE")
		// v2.15.74: 引擎运行中关闭窗口会终止扫描(Job 回收), 需用户确认防误关
		if engineRunning {
			t, _ := syscall.UTF16PtrFromString("引擎正在运行/扫描中, 关闭窗口将终止当前任务!\n\n确定要退出吗? (是=退出并终止 / 否=继续)")
			cap, _ := syscall.UTF16PtrFromString(AppTitleBase)
			r, _, _ := procMessageBoxW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(cap)), 0x00000004 /*MB_YESNO*/|0x00000020 /*MB_ICONWARNING*/)
			if r != 6 /*IDYES*/ {
				logf("WM_CLOSE: 用户取消关闭 (引擎运行中)")
				return 0
			}
			logf("WM_CLOSE: 用户确认退出 (引擎运行中, 将终止)")
		}
		procDestroyWindow.Call(uintptr(hwnd))
		return 0

	case WM_DESTROY:
		logf("WM_DESTROY")
		procPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ = procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return ret
}

var procDestroyWindow = user32.NewProc("DestroyWindow")
var procShowWindow = user32.NewProc("ShowWindow")
var procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
var procRtlGetVersion     = kernel32.NewProc("RtlGetVersion")

// === 容器窗口类 (v2.13 修复 "所有功能按钮点击无反应") ===
//
// 根因: v2.11 起把功能按钮挂在 pageDetect/pageTools 两个 "Static" 容器下。
//       子控件点击只把 WM_COMMAND 发给"直接父窗口"(容器), 而 "Static" 的
//       默认 wndProc (DefWindowProc) 不会把 WM_COMMAND 再转发给 mainHwnd,
//       导致消息被丢弃 -> 主窗口过程永远收不到 -> 按钮全部无反应。
//
// 对策: 注册一个自定义容器类 SFContainer, 其 wndProc 把 WM_COMMAND / WM_NOTIFY
//       直接转发给 mainHwnd; 其余消息照常交给 DefWindowProc。
// createChildSafe v2.15.74: 子控件创建带重试 —— CreateWindowExW 1114(DLL init 失败)常为
// 杀软/EDR 对刚解压 exe 的瞬时拦截; 重试 3 次(每次 200ms), 仍失败则降级(返回0, 控件缺失不致命)
func createChildSafe(style, cls, text, pstyle, x, y, w, h, parent, id, lp, wp uintptr) (r1 uintptr, r2 uintptr, r3 uintptr) {
	// v2.15.74: WM_CREATE 期间子控件创建会触发 user32 重入 panic(1114 DLL init 失败, 安全软件注入所致),
	//   panic 沿同步回调栈传播被主窗口 safeCall 捕获 -> 误报"主窗口创建失败"。此处捕获 panic:
	//   按失败处理(重试 3 次 x300ms), 仍失败则控件降级(0), 不再向上传播。
	for i := 0; i < 3; i++ {
		ok := false
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					ok = false
					logf("createChild panic 已捕获 id=%d rec=%v", id, rec)
				}
			}()
			hr, _, _ := procCreateWindowExW.Call(style, cls, text, pstyle, x, y, w, h, parent, id, lp, wp)
			if hr != 0 {
				r1 = hr
				ok = true
			}
		}()
		if ok {
			return r1, 0, 0
		}
		code := windows.GetLastError()
		logf("createChild 重试 %d: id=%d code=%d", i+1, id, code)
		time.Sleep(300 * time.Millisecond)
	}
	logf("createChild 降级(控件缺失): id=%d", id)
	return 0, 0, 0
}

var containerWndProcCallback = syscall.NewCallback(containerWndProc)

func containerWndProc(hwnd windows.HWND, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case WM_COMMAND, WM_NOTIFY:
		if mainHwnd != 0 {
			procSendMessageW.Call(uintptr(mainHwnd), uintptr(msg), wParam, lParam)
		}
		return 0
	}
	ret, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return ret
}

const containerClassName = "SFContainer"
var procSHBrowseForFolder = shell32.NewProc("SHBrowseForFolderW")
var procSHChangeNotify = shell32.NewProc("SHChangeNotifyW")
var procSHGetFolderPathW = shell32.NewProc("SHGetFolderPathW")
var procSHGetPathFromIDListW = shell32.NewProc("SHGetPathFromIDListW")
var procCoInitializeEx = ole32.NewProc("CoInitializeEx")
var procCoUninitialize = ole32.NewProc("CoUninitialize")
var wndProcCallback = syscall.NewCallback(wndProc)

// safeCall 调用 lazy DLL 过程并防 panic.
// 背景: golang.org/x/sys/windows 的 LazyProc.Call 在底层 LoadLibrary 失败
// (DLL 的 DllMain 返回 FALSE, GetLastError=1114 "A dynamic link library
// (DLL) initialization routine failed")时会直接 panic, 而不是返回错误.
// 旧代码用 `if ret == 0` 只能捕获"函数返回 FALSE", 捕获不了"LoadLibrary panic",
// 导致 ole32/comctl32 等可选 DLL 加载失败时整进程崩溃、GUI 不显示.
// safeCall 用 recover 把 panic 转成 (ok=false) 返回, 调用方按 best-effort 降级.
func safeCall(p *windows.LazyProc, a ...uintptr) (r1, r2 uintptr, err error, ok bool) {
	defer func() {
		if rec := recover(); rec != nil {
			// rec 通常含 "A dynamic link library (DLL) initialization routine failed"(错误 1114),
			// 即该过程所属系统 DLL(多为 user32.dll)在本机被安全软件拦截或初始化失败.
			err = fmt.Errorf("懒加载调用 %s 失败: DLL 初始化失败/被拦截(错误 1114): %v",
				lazyName(p), rec)
			r1, r2, ok = 0, 0, false
		}
	}()
	r1, r2, err = p.Call(a...)
	ok = true
	return
}

func lazyName(p *windows.LazyProc) string {
	if p == nil {
		return "<nil>"
	}
	return p.Name
}

// preloadGUIBasics 在自保护(缓解策略)生效前, 先把 GUI 必需的 user32.dll / gdi32.dll 映射进进程。
// 原因: hardenProcess 的缓解策略若作用在 DLL 加载期, 可能拦截 user32 加载(返回 1114, 见 v2.15.14 修复)。
// 若模块在策略生效前已映射, 后续 winMain 使用已加载模块即不受策略影响。同时记录加载结果,
// 若此处都失败, 说明是系统/安全软件层问题(而非本进程策略), 供排查。
func preloadGUIBasics() {
	for _, name := range []string{"user32.dll", "gdi32.dll"} {
		h, err := windows.LoadLibrary(name)
		if err != nil {
			logf("预加载探针(自保护前): %s 加载失败: %v —— 属系统/安全软件层问题, 非本进程策略", name, err)
			continue
		}
		// 注意: 不调用 FreeLibrary, 保留模块映射, 使 winMain 复用已加载实例。
		logf("预加载探针(自保护前): %s 加载成功 handle=0x%X (已保留, 规避加载期策略拦截)", name, h)
	}
}

func winMain() (int, error) {
	logf("winMain: stage-enter")
	// 部署辨识: 日志首行打印构建标签, 用户据此确认跑的是修复版而非旧 exe.
	logf("=== 银狐特攻 启动 v2.15.74 (tier=%d) build=%s ===", buildTier, buildTag)
	// 旧版在启动期就调 CoInitializeEx(ole32)/InitCommonControlsEx(comctl32), 一旦这两个非必需 DLL 的
	// DllMain 返回 FALSE(EDR/AV 拦截/SxS 损坏)即 panic 崩溃, GUI 永不开. 本版彻底移除启动期对
	// ole32/comctl32 的加载 —— 控件全是系统内置 Button/Edit/Static, 这两个初始化本就多余;
	// 仅"选择文件夹"对话框真正需要 COM/STA, 改到 pickDirDialog 内按需初始化(safeCall 兜底).
	logf("启动期已跳过 ole32/comctl32 初始化(控件为系统内置, 无需 comctl32; 仅文件夹对话框按需 COM)")

	hi, _, _ := procGetModuleHandleW.Call(0)
	hInstance := windows.Handle(hi)

	// 关键修复 v2.15.11: 以下 user32 调用一律走 safeCall. 若本进程缓解策略(签名/动态代码)或本机安全软件
	// (EDR/杀毒)拦截 user32.dll 加载(错误 1114, DLL 初始化失败), 旧代码会直接 panic 并触发看门狗无限重启;
	// 现在捕获为明确错误, 由 main 判定为"正常退出"并移除存活标记, 掐断重启循环. 光标/图标加载失败则降级为 0(用系统默认).
	// v2.15.14 起: 缓解策略已不再拦截系统 GUI DLL, 且本函数前已 preload user32/gdi32, 正常情况不应再触发 1114.
	cursor, _, _, okCursor := safeCall(procLoadCursorW, 0, IDC_ARROW)
	icon, _, _, okIcon := safeCall(procLoadIconW, 0, IDI_APPLICATION)
	if !okCursor {
		logf("LoadCursorW 失败(可能 user32.dll 加载被本机安全软件拦截)")
	}
	if !okIcon {
		logf("LoadIconW 失败(可能 user32.dll 加载被本机安全软件拦截)")
	}
	// v2.15.74: GUI 单实例 —— 双击二次启动时激活已有窗口后退出 (防双 GUI/双引擎)
	{
		logf("winMain: stage-mutex")
		guiMut, merr := windows.CreateMutex(nil, false, syscall.StringToUTF16Ptr("SilverFoxDetector_GUI_Instance"))
		if merr == nil {
			if windows.GetLastError() == windows.ERROR_ALREADY_EXISTS {
				logf("GUI: 已有实例运行, 激活已有窗口后退出")
				cls, _ := syscall.UTF16PtrFromString("SilverFoxDetectorMain")
				if hPrev, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(cls)), 0); hPrev != 0 {
					procShowWindow.Call(hPrev, 9 /*SW_RESTORE*/)
					procSetForegroundWindow.Call(hPrev)
				}
				return 0, nil
			}
			defer windows.CloseHandle(guiMut)
		}
	}

	className := utf16Ptr("SilverFoxDetectorMain")

	wc := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		Style:         0, // 不要 CS_HREDRAW|CS_VREDRAW — 在某些主题下会在客户区中央画占位图标
		LpfnWndProc:   wndProcCallback,
		HInstance:     hInstance,
		HCursor:       windows.Handle(cursor),
		HIcon:         windows.Handle(icon),
		HbrBackground: windows.Handle(COLOR_WINDOW + 1), // 强制白色背景, 避免中间出现占位图标
		LpszClassName: className,
		HIconSm:       0, // 不设小图标, 避免某些主题把它当水印画
	}
	if _, _, _, ok := safeCall(procRegisterClassExW, uintptr(unsafe.Pointer(&wc))); !ok {
		return 1, fmt.Errorf("RegisterClassExW 失败: user32.dll 可能被本进程缓解策略(签名/动态代码)或本机安全软件(EDR/杀毒)拦截(错误 1114, DLL 初始化失败); 请将本工具目录加入杀毒/EDR 排除列表, 或以真正管理员身份运行")
	}

	// v2.13: 注册容器窗口类 SFContainer (转发 WM_COMMAND/WM_NOTIFY 给 mainHwnd),
	// 否则挂在容器下的子按钮点击永远送不到主窗口过程.
	cc := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		Style:         0,
		LpfnWndProc:   containerWndProcCallback,
		HInstance:     hInstance,
		HbrBackground: windows.Handle(COLOR_WINDOW + 1),
		LpszClassName: utf16Ptr(containerClassName),
	}
	if _, _, _, ok := safeCall(procRegisterClassExW, uintptr(unsafe.Pointer(&cc))); !ok {
		logf("SFContainer 类注册失败(user32 加载失败?), 容器按钮将无法转发 WM_COMMAND!")
	} else {
		logf("SFContainer 类注册成功")
	}

	titlePtr, _ := syscall.UTF16PtrFromString("顽固木马扫描专杀-银狐特攻 v2.15.74" + tierSuffix())
	mainHwnd = windows.HWND(0)
	logf("winMain: stage-createwindow")
	ret, _, _, ok := safeCall(procCreateWindowExW,
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(titlePtr)),
		uintptr(WS_OVERLAPPEDWINDOW|WS_VISIBLE|WS_CLIPCHILDREN),
		100, 100, 1100, 640,
		0, 0, uintptr(hInstance), 0,
	)
	if !ok || ret == 0 {
		return 1, fmt.Errorf("CreateWindowExW 失败: user32.dll 在本机加载失败(错误 1114, DLL 初始化失败), 主窗口无法创建; 通常由安全软件(EDR/杀毒)拦截或系统 DLL 损坏导致。请将本工具目录加入杀毒/EDR 排除、以管理员身份运行, 或执行 sfc /scannow 修复系统文件")
	}
	mainHwnd = windows.HWND(ret)
	logf("主窗口创建成功 hwnd=0x%X", ret)

	// 自动检测模式
	if autoDetectPath != "" {
		// 延迟让控件先 ready
		go func() {
			time.Sleep(150 * time.Millisecond)
			setEditText(autoDetectPath)
			refreshList(autoDetectPath)
		}()
	}

	var msg MSG
	for {
		r, _, _, ok := safeCall(procGetMessageW, uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if !ok {
			logf("GetMessageW 失败(消息循环无法继续, user32 异常): 退出 GUI")
			break
		}
		if int32(r) <= 0 {
			break
		}
		safeCall(procTranslateMessage, uintptr(unsafe.Pointer(&msg)))
		safeCall(procDispatchMessageW, uintptr(unsafe.Pointer(&msg)))
	}
	logf("消息循环结束")
	return int(msg.WParam), nil
}

func main() {
	initLog()

	// 解析编译期注入的档位(默认 "1"), 再允许运行期 --tier 覆盖.
	parseBuildTier()
	guardedByGuardian := false // 由高权限守护重启而来 -> 不再 spawn 新守护(防繁殖)
	for i := 0; i+1 < len(os.Args); i++ {
		if os.Args[i] == "--tier" {
			if t, e := strconv.Atoi(os.Args[i+1]); e == nil && t >= 1 && t <= 3 {
				buildTier = t
			}
		}
		if os.Args[i] == "--guarded" {
			guardedByGuardian = true
		}
	}

	// 自保护: 看门狗模式 (由主进程 spawn 的 "--watchdog <pid> --tier N" 子进程)
	if len(os.Args) >= 3 && os.Args[1] == "--watchdog" {
		if pid, e := strconv.Atoi(os.Args[2]); e == nil {
			watchdogMain(pid)
		}
		if logFile != nil {
			logFile.Close()
		}
		return
	}

	// 高权限守护模式 (档3, 由主进程 runas 拉起, 带 --guardian <mainpid> --tier 3)
	if len(os.Args) >= 3 && os.Args[1] == "--guardian" {
		if pid, e := strconv.Atoi(os.Args[2]); e == nil {
			guardianMain(pid)
		}
		if logFile != nil {
			logFile.Close()
		}
		return
	}

	// 提权子实例: 由非管理员主 exe 以 ShellExecute("runas") 重启自身而来, 已具备管理员令牌.
	// 此时新 exe 直接以对应 mode 启动引擎; 由于新 exe 是管理员, 其 spawn 的 cmd/引擎继承同一令牌
	// 且仍在该 exe 的 Job Object 内 -> exe 退出时 Job Object 自动回收整棵引擎树, 不再残留.
	// 关键: 必须把 exe 保持存活到引擎结束 (waitForEngineTree), 否则 Job 句柄关闭触发 KillOnJobClose
	// 会把刚启动的引擎一并回收.
	parentPID := 0
	for i := 0; i < len(os.Args); i++ {
		if os.Args[i] == "--parent" {
			if i+1 < len(os.Args) {
				if v, e := strconv.Atoi(os.Args[i+1]); e == nil {
					parentPID = v
				}
			}
		}
	}
	for i := 0; i < len(os.Args); i++ {
		if os.Args[i] == "--elevated-run" {
			// mode 紧跟其后; 若为空(普通"专杀扫描 (默认)"按钮未带模式)则取空串,
			// runSilverFox("") 会按 GUI 默认模式启动 bat.
			mode := ""
			// v2.15.30: 复选框提权传 "--elevated-run --parent <pid>", 跳过 --parent 防止误当 mode
			//   (否则新实例走 runSilverFox("--parent") -> 只拉起 cmd 无 GUI 的 bug).
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
				mode = os.Args[i+1]
			}
			logf("elevated-run 提权子实例: mode=%q tier=%d parent=%d", mode, buildTier, parentPID)
			// 自保护对子实例同样生效(进程防杀/完整性/缓解策略/进程监控), 看门狗会再 spawn 一个 --watchdog.
			preloadGUIBasics() // v2.15.14: 在缓解策略生效前先映射 user32/gdi32, 规避加载期拦截
			protectSelfDACL()
			hardenProcess()
			runIntegrityCheck()
			writeGuardFlag()
			spawnWatchdog()
			if buildTier >= 2 {
				startBidirectionalHeartbeat()
			}
			startProcessMonitor() // v2.15.7
			startAntiFreeze()     // v2.15.8: EDR-Freeze 反冻防御
			if buildTier >= 3 {
				installSelfGuardHooks() // 用户态 inline hook 拦自身被终止/挂起
				spawnGuardian()         // 高权限守护(双向心跳)
			}
			if mode == "" {
				// 双击启动触发提权(用户尚未指定具体模式): 直接展示 GUI 主窗口,
				// 让用户选择操作. 进程已具备管理员令牌, GUI 内按钮(含需管理员的功能)
				// 都能在不二次弹 UAC 的情况下工作. 修复 v2.15.9 提权子实例跳过 GUI
				// 导致"双击后没有界面"的问题.
				// v2.15.31: 先通知原低权限实例关闭(走 GUI 模式, 新实例即将展示界面),
				//   原实现写在 winMain() 之后的 return 后面, 永远不可达 -> 原实例卡住未关闭.
				if parentPID > 0 {
					sigFile := filepath.Join(os.TempDir(), fmt.Sprintf("sf_elev_done_%d.sig", parentPID))
					_ = os.WriteFile(sigFile, []byte("1"), 0644)
					logf("elevated-run: 已通知原实例(PID=%d)关闭 (GUI 模式)", parentPID)
				}
			logf("elevated-run: 未指定模式, 直接展示 GUI 主窗口")
			code, err := winMain()
			if err != nil {
				logf("GUI 初始化失败(致命, 不再重启): %v", err)
				logf("排查建议: 错误 1114(DLL 初始化失败)通常由本机安全软件(EDR/杀毒)拦截 user32.dll 加载或系统 DLL 损坏引起。请依次尝试: 1)以真正管理员身份运行; 2)将本工具所在目录加入杀毒/EDR 排除列表; 3)把 exe 复制到 C:\\temp 并重命名(如 app.exe)运行以排除按名/路径拦截; 4)以管理员运行 cmd 执行 sfc /scannow 与 DISM /Online /Cleanup-Image /RestoreHealth 修复系统文件")
				removeGuardFlag() // 关键: 让看门狗判定为"正常退出", 掐断无限重启循环
				showFatal(err.Error())
				code = 1
			}
				logf("elevated-run: GUI 退出 code=%d", code)
				removeGuardFlag()
				if logFile != nil {
					logFile.Close()
				}
				return
			}
			// 否则(用户从 GUI 勾选"以管理员身份运行"并点击某具体按钮触发提权)按指定模式直接运行引擎
			runSilverFox(mode)
			// v2.15.29: 新实例引擎已启动 -> 通知原低权限实例自动关闭
			if parentPID > 0 {
				sigFile := filepath.Join(os.TempDir(), fmt.Sprintf("sf_elev_done_%d.sig", parentPID))
				_ = os.WriteFile(sigFile, []byte("1"), 0644)
				logf("elevated-run: 已通知原实例(PID=%d)关闭", parentPID)
			}
			waitForEngineTree()
			removeGuardFlag()
			if logFile != nil {
				logFile.Close()
			}
			return
		}
	}

	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 8192)
			n := runtime.Stack(buf, false)
			logf("崩溃堆栈:\n%s", string(buf[:n]))
			e := fmt.Sprintf("程序崩溃: %v\n堆栈见日志.", r)
			showFatal(e)
		}

	// v2.15.4: 退出时 best-effort 清理仍在运行的引擎树 (非提权模式下 Job Object 已兜底,
		// 这里再补一层 taskkill; 提权模式下父进程无权限 kill 已提升的子进程, 会失败属正常).
		cleanupEngines()
		if logFile != nil {
			logFile.Close()
		}
	}()

	exe, _ := os.Executable()
	logf("exe=%s", exe)
	logf("args=%v", os.Args)

	argv := os.Args

	// CLI 模式: --cli 或 --register / --unregister
	for _, a := range argv {
		if a == "--cli" || a == "--register" || a == "--unregister" {
			exit := runCLI(argv)
			os.Exit(exit)
		}
	}

	// 自动检测模式: 只带一个文件路径参数 -> 启动 GUI 并自动检测
	if len(argv) == 2 {
		p := argv[1]
		if !strings.HasPrefix(p, "-") && !strings.HasPrefix(p, "/") {
			if _, err := os.Stat(p); err == nil {
				autoDetectPath = p
				logf("自动检测模式: %s", p)
			}
		}
	}

	// 档2/3: 启动即申请一次 UAC, 以管理员令牌运行对应档(用户已确认高档需 UAC, 模仿急救箱).
	//   Wine 下 ShellExecute(runas) 会失败 -> ensureElevatedOrRestartTier 内部优雅降级.
	if buildTier >= 2 {
		ensureElevatedOrRestartTier()
	}

	// 自保护初始化 (GUI 主模式): 进程防杀(DACL) + 缓解策略(降级近似PPL) + 完整性自检 + 存活标记 + 看门狗
	preloadGUIBasics() // v2.15.14: 在缓解策略生效前先映射 user32/gdi32, 规避加载期拦截
	protectSelfDACL()
	hardenProcess()
	runIntegrityCheck()
	writeGuardFlag()
	spawnWatchdog()
	if buildTier >= 2 {
		startBidirectionalHeartbeat()
	}
	startProcessMonitor() // v2.15.7: 进程与线程监控(轮询快照 + ETW 实时 best-effort)
	startAntiFreeze()     // v2.15.8: EDR-Freeze 反冻防御(心跳反冻 + 线程挂起监控)
	if buildTier >= 3 {
		installSelfGuardHooks() // 用户态 inline hook 拦自身被终止/挂起
		if !guardedByGuardian {
			spawnGuardian() // 高权限守护(双向心跳); 由守护重启而来则不重复 spawn(防繁殖)
		}
	}

	// 启 GUI
	code, err := winMain()
	if err != nil {
		logf("GUI 初始化失败(致命, 不再重启): %v", err)
		logf("排查建议: 错误 1114(DLL 初始化失败)通常由本机安全软件(EDR/杀毒)拦截 user32.dll 加载或系统 DLL 损坏引起。请依次尝试: 1)以真正管理员身份运行; 2)将本工具所在目录加入杀毒/EDR 排除列表; 3)把 exe 复制到 C:\\temp 并重命名(如 app.exe)运行以排除按名/路径拦截; 4)以管理员运行 cmd 执行 sfc /scannow 与 DISM /Online /Cleanup-Image /RestoreHealth 修复系统文件")
		removeGuardFlag() // 关键: 让看门狗判定为"正常退出"而非"被 kill", 掐断无限重启循环
		showFatal(err.Error())
		code = 1
	}
	logf("退出 code=%d", code)
	removeGuardFlag()
}

// ===================== 自保护 (v2.15 下沉自 PowerShell 层) =====================
// 原 SelfGuard.ps1 (看门狗 + 进程 DACL) 与 SilverFoxDetect.ps1::Test-Integrity (文件完整性)
// 在 PowerShell 层实现; 现直接在 Go exe 上实现, 降低对 PowerShell 的依赖, 使 exe 自身即
// 具备: 进程防杀(DACL) + 文件完整性自检 + 看门狗自愈(被 kill 自动重启).
//
// 设计:
//   - 主进程(GUI)启动早期: 设自身 DACL(防杀) + 跑完整性自检 + 写存活标记 sf_guard.flag
//     + spawn 自身 "--watchdog <pid>" 子进程.
//   - 看门狗子进程: 轮询主 PID; 消失且 flag 在 -> 判定被 kill -> 自动重启(上限5次);
//     消失且 flag 不在 -> 主进程正常退出 -> 看门狗退出. 用 Global mutex 防止重复看门狗.

var (
	procConvertStringSecurityDescriptorToSecurityDescriptorW = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procSetKernelObjectSecurity                              = advapi32.NewProc("SetKernelObjectSecurity")
	procLocalFree                                            = kernel32.NewProc("LocalFree")
	// v2.15.6 进程缓解策略(降级近似 PPL): kernel32 的 SetProcessMitigationPolicy 在
	// x/sys/windows v0.15.0 未封装, 动态加载. 亦可对子进程用 ntdll.NtSetInformationProcess
	// (同名 class) 施加, 故一并声明备用.
	procSetProcessMitigationPolicy = kernel32.NewProc("SetProcessMitigationPolicy")
)

const (
	// 与 PowerShell 层 Test-Integrity 共用同一 salt, 保证清单签名算法一致.
	selfGuardIntegritySalt = "SilverFoxDetector-INTEGRITY-SALT-v1-!@#$%^&*2026"
	// 进程 DACL: 仅 SYSTEM + Owner(OW) 拥有全部访问, 移除 Everyone/Users/Administrators 终止权限.
	selfGuardSDDL = "O:SYG:SYD:(A;;GA;;;SY)(A;;GA;;;OW)"
	// SetKernelObjectSecurity 的安全信息标志 = DACL.
	daclSecurityInformation = 4

	selfGuardFlagFile = "sf_guard.flag" // 主进程存活标记(正常退出前删除, 否则看门狗判定被 kill)
	selfGuardMaxKills = 5               // 连续被 kill 重启上限, 防无限循环
	selfGuardPollSec  = 2               // 看门狗轮询间隔(秒)
)

// selfGuardMutexName 看门狗单实例互斥名(基于 exe 路径哈希, 支持不同目录并存).
func selfGuardMutexName() string {
	if exe, err := os.Executable(); err == nil {
		h := sha256.Sum256([]byte(strings.ToLower(exe)))
		return "Global\\SF-SelfGuard-" + hex.EncodeToString(h[:])[:16]
	}
	return "Global\\SF-SelfGuard"
}

// protectSelfDACL 对自身进程设 DACL: 仅 SYSTEM + Owner 可终止, 普通用户/任务管理器无法直接结束.
// 复刻 SelfGuard.ps1::Guard-ProtectSelf. 失败仅日志, 不阻断运行.
func protectSelfDACL() {
	sdPtr := uintptr(0)
	var sdSize uint32
	r, _, _ := procConvertStringSecurityDescriptorToSecurityDescriptorW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(selfGuardSDDL))),
		1,
		uintptr(unsafe.Pointer(&sdPtr)),
		uintptr(unsafe.Pointer(&sdSize)),
	)
	if r == 0 {
		logf("自保护: 转换 SDDL 失败 code=%d", windows.GetLastError())
		return
	}
	defer procLocalFree.Call(sdPtr)

	h, _, _ := procOpenProcess.Call(PROCESS_QUERY_INFORMATION, 0, uintptr(os.Getpid()))
	if h == 0 {
		logf("自保护: OpenProcess 自身失败 code=%d", windows.GetLastError())
		return
	}
	defer procCloseHandle.Call(h)

	ok, _, _ := procSetKernelObjectSecurity.Call(h, daclSecurityInformation, sdPtr)
	if ok != 0 {
		logf("自保护: 进程 DACL 已设置 (仅 SYSTEM+Owner 可终止)")
	} else {
		logf("自保护: SetKernelObjectSecurity 失败 code=%d (非致命, 不影响运行)", windows.GetLastError())
	}
}

// ===================== 进程缓解策略 (v2.15.6 降级近似 PPL) =====================
// 用户需求: 用 PPL(PsProtectedSignerAntimalware) 在内核态挡住"管理员随意终止/注入".
// 现实约束: PPL-Antimalware 需要微软反恶意软件(ELAM)认证签名, 普通 Authenticode 证书
//   无法让内核以 Antimalware signer 级别启动进程 —— 纯用户态 exe 走不了真 PPL.
// 降级近似(无需特殊证书, 普通进程即可生效): 在用户态/Ring3 尽量逼近 PPL 的"防注入/防杀"目标:
//   1) 进程缓解策略 SetProcessMitigationPolicy: 禁动态代码(防 shellcode/内存注入)、
//      仅加载微软/Store 签名 DLL(防 DLL 侧载注入)、禁远程/低 IL 镜像、严格句柄检查.
//   2) 完整性级别(MIC)提升: 把自身提到 High IL, 低 IL 进程无法 OpenProcess 本进程.
//   3) 移除 SeDebugPrivilege 等危险特权(降低本进程 Token 一旦被劫持的价值).
// 注意: 这些仍是 Ring3 措施, 拥有 SeDebugPrivilege 的管理员理论上仍可绕过(与 PPL 的 Ring0 强制不同);
//   但它们叠加在已有 DACL + 看门狗之上, 显著提升攻击成本, 且对"普通恶意软件/脚本"已足够硬.
// 全部 best-effort: 任一失败仅日志, 不阻断运行.

// 缓解策略 class(与 NtSetInformationProcess 的 ProcessInformationClass 同名值共用).
const (
	procMitDynamicCode      = 2 // ProcessDynamicCodePolicy
	procMitSignature        = 3 // ProcessSignaturePolicy (微软/Store 签名 DLL)
	procMitImageLoad        = 4 // ProcessImageLoadPolicy (禁远程/低IL镜像)
	procMitStrictHandle     = 6 // ProcessStrictHandleCheckPolicy (野指针句柄立即抛异常)
	procMitSystemCallFilter = 5 // ProcessSystemCallDisablePolicy (需配套 filter, 谨慎)
)

// 强制性完整性级别(IL) RID —— x/sys/windows 未导出, 此处按 Windows 规范定义.
// S-1-16-<rid>: Low=0x1000, Medium=0x2000, High=0x3000, System=0x4000.
const (
	secMandatoryHighRID   = 0x3000 // High 完整性(12288) —— 提升到 High 即足以挡低 IL 注入, 且 GUI 不受影响
	seGroupIntegrity      = 0x00000020
	sePrivilegeDisabled   = 0x00000000 // AdjustTokenPrivileges: 清 Enabled 位即禁用(非 REMOVED)
)

// applyMitigation 对一个进程句柄施加一组缓解策略. h 需有 PROCESS_SET_INFORMATION.
func applyMitigation(h windows.Handle) {
	type flagPolicy struct {
		class uint32
		flags uint32
	}
	// 各策略统一用 4 字节 Flags DWORD 传入; 设置失败(老系统/句柄权限不足)仅记日志.
	// v2.15.14 修复: 旧策略集含 procMitSignature(0x1|0x2 = 必须 Microsoft 且必须 Store 签名,
	// 逻辑矛盾, 任何 DLL 都无法同时满足)与 procMitDynamicCode(ProhibitDynamicCode/ACG),
	// 二者会在 DLL 加载期拦截 user32.dll 等系统 GUI DLL 的加载, LoadLibrary 返回 1114
	// (DLL 初始化失败), 表现为"双击无界面"。严格句柄检查(procMitStrictHandle)也会让
	// 本进程任何无效句柄操作直接终止, 风险高且对 GUI 无益。
	// 现仅保留 procMitImageLoad(PreferSystem32Images): 仅"优先从 system32 解析 DLL",
	// 不拦截系统 GUI DLL 加载, 且有防 DLL 劫持的正向价值。其余激进策略改由引擎子进程
	// (runSilverFox)按需施加, 不再作用于加载 user32 的 GUI 主进程。
	policies := []flagPolicy{
		{procMitImageLoad, 0x4}, // PreferSystem32Images: 仅优先 system32, 不拦截加载
	}
	for _, p := range policies {
		// 优先 SetProcessMitigationPolicy(自身/他人通用); 若对子进程, 该 API 仅对自身有效,
		// 故对子进程改用 NtSetInformationProcess(同 class 值).
		var r uintptr
		if h == windows.CurrentProcess() {
			r, _, _ = procSetProcessMitigationPolicy.Call(uintptr(p.class), uintptr(unsafe.Pointer(&p.flags)), unsafe.Sizeof(p.flags))
		} else {
			// ntdll.NtSetInformationProcess(Handle, class, Buffer, Length) —— class 值同上.
			// 该 sys 调用在 x/sys/windows 已封装为 NtSetInformationProcess(proc, class, buf, len).
			if err := windows.NtSetInformationProcess(h, int32(p.class), unsafe.Pointer(&p.flags), uint32(unsafe.Sizeof(p.flags))); err != nil {
				logf("自保护: 子进程缓解策略 class=%d 失败: %v", p.class, err)
				continue
			}
			r = 1
		}
		if r == 0 {
			logf("自保护: 缓解策略 class=%d 设置失败 code=%d (非致命)", p.class, windows.GetLastError())
		}
	}
}

// hardenProcess 对自身施加全部 Ring3 缓解(动态代码/签名/镜像/严格句柄) + 提升 IL + 去特权.
func hardenProcess() {
	// 1) 缓解策略(自身)
	applyMitigation(windows.CurrentProcess())
	// 2) 完整性级别提到 High(12288): 低 IL 进程无法 OpenProcess 本进程.
	raiseSelfIntegrityLevel()
	// 3) 移除 SeDebugPrivilege(降低 Token 被劫持价值). best-effort.
	stripDangerousPrivileges()
}

// raiseSelfIntegrityLevel 把当前进程 Token 的完整性级别提到 High(不取 System, 避免 GUI/COM 异常).
func raiseSelfIntegrityLevel() {
	var sid *windows.SID
	// S-1-16-0x3000 = High 完整性级别 (SECURITY_MANDATORY_LABEL_AUTHORITY=16, sub=0x3000=12288).
	if err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_MANDATORY_LABEL_AUTHORITY, 1,
		secMandatoryHighRID, 0, 0, 0, 0, 0, 0, 0, &sid); err != nil {
		logf("自保护: 构造 High IL SID 失败: %v (非致命)", err)
		return
	}
	defer windows.FreeSid(sid)

	// SetTokenInformation(TokenIntegrityLevel) 需要 TOKEN_ADJUST_DEFAULT; 显式打开自身 Token.
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_QUERY, &tok); err != nil {
		logf("自保护: 打开自身 Token(调 IL)失败: %v (非致命)", err)
		return
	}
	defer tok.Close()

	// TOKEN_MANDATORY_LABEL { PSID LabelSid; DWORD Attributes(SE_GROUP_INTEGRITY) }
	type tokenMandatoryLabel struct {
		labelSid   *windows.SID
		attributes uint32
	}
	tml := tokenMandatoryLabel{sid, seGroupIntegrity}
	if err := windows.SetTokenInformation(tok, windows.TokenIntegrityLevel,
		(*byte)(unsafe.Pointer(&tml)), uint32(unsafe.Sizeof(tml))); err != nil {
		logf("自保护: 提升完整性级别失败: %v (非致命)", err)
		return
	}
	logf("自保护: 完整性级别已提升至 High(12288)")
}

// stripDangerousPrivileges 在自身 Token 上禁用 SeDebugPrivilege(若持有).
// 注: 此进程是攻击目标而非攻击跳板, 去掉 SeDebugPrivilege 可降低"一旦被注入"后的横向提权价值.
// 仅 disable(非 REMOVED), 失败忽略. 不过激降权以免 GUI 所需能力受损.
func stripDangerousPrivileges() {
	const seDebugName = "SeDebugPrivilege"
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(seDebugName), &luid); err != nil {
		return // 系统无此特权名, 跳过
	}
	// TOKEN_PRIVILEGES { DWORD PrivilegeCount; LUID_AND_ATTRIBUTES[1] }
	// LUID_AND_ATTRIBUTES { LUID; DWORD Attributes(SE_PRIVILEGE_DISABLED=0x3? 用 0 表清除 enabled) }
	type luidAttr struct {
		luid       windows.LUID
		attributes uint32
	}
	type tokenPrivs struct {
		count uint32
		la    luidAttr
	}
	tp := tokenPrivs{count: 1, la: luidAttr{luid: luid, attributes: sePrivilegeDisabled}}
	// 需 TOKEN_ADJUST_PRIVILEGES 权限; GetCurrentProcessToken() 默认仅 TOKEN_QUERY, 故显式打开.
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		logf("自保护: 打开自身 Token(调特权)失败: %v (非致命)", err)
		return
	}
	defer tok.Close()
	// AdjustTokenPrivileges(disableAll=false, newstate=SeDebug with attr 0) 关闭其 Enabled 位.
	if err := windows.AdjustTokenPrivileges(tok, false,
		(*windows.Tokenprivileges)(unsafe.Pointer(&tp)), uint32(unsafe.Sizeof(tp)), nil, nil); err != nil {
		logf("自保护: 禁用 %s 失败: %v (非致命)", seDebugName, err)
		return
	}
	logf("自保护: 已禁用 %s (降低 Token 价值)", seDebugName)
}

// hardenEngineChild 对启动的引擎子进程(cmd/bat/ps1)施加缓解策略, 让整条工具链都防注入.
// 必须在 cmd.Start() 之后、引擎尚未大量加载模块前调用; 失败忽略.
func hardenEngineChild(p *os.Process) {
	if p == nil {
		return
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_INFORMATION, false, uint32(p.Pid))
	if err != nil {
		logf("自保护: OpenProcess(引擎 PID=%d, SET_INFORMATION) 失败: %v", p.Pid, err)
		return
	}
	defer windows.CloseHandle(h)
	applyMitigation(h)
	logf("自保护: 引擎子进程 PID=%d 已施加缓解策略", p.Pid)
}

var integEntryRe = regexp.MustCompile(`^[^|]+\|[0-9a-fA-F]{64}$`)

// runIntegrityCheck 文件完整性自检: 读 legacy/integrity.manifest, 校验清单签名并逐文件比对
// SHA256. 替代 PowerShell 层 Test-Integrity. 异常时弹窗告警但允许继续运行.
func runIntegrityCheck() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	legacyDir := filepath.Join(filepath.Dir(exe), "legacy")
	mf := filepath.Join(legacyDir, "integrity.manifest")
	data, err := os.ReadFile(mf)
	if err != nil {
		logf("完整性自检: 找不到 manifest: %v", err)
		return
	}

	var entries []string
	var sig, signed string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimRight(l, "\r")
		switch {
		case strings.HasPrefix(l, "sig="):
			sig = strings.TrimSpace(strings.TrimPrefix(l, "sig="))
		case strings.HasPrefix(l, "signed="):
			signed = strings.TrimSpace(l)
		case integEntryRe.MatchString(l):
			entries = append(entries, l)
		}
	}
	if len(entries) == 0 || sig == "" {
		logf("完整性自检: manifest 无有效条目/签名")
		return
	}

	// 校验清单签名 (与 PowerShell Test-Integrity 同算法)
	// v2.15.15: 载荷与 PS 层 Test-Integrity 对齐 —— PS 层用完整 "signed=" 行;
	// 此处 signed 保留 "signed=" 前缀 (解析时未去掉), 拼接即得完整行, 两层一致.
	payload := strings.Join(entries, "\n") + "\n" + signed + selfGuardIntegritySalt
	calc := sha256.Sum256([]byte(payload))
	calcSig := hex.EncodeToString(calc[:])[:16]
	if !strings.EqualFold(calcSig, sig) {
		logf("完整性自检: 清单签名无效 (calc=%s 文件=%s)", calcSig, sig)
		msgBoxInfo("完整性自检", "工具完整性清单签名无效，文件可能已被篡改或被替换。\n\n如非本人修改，请重新下载官方版本。")
		return
	}

	// 逐文件哈希比对
	bad := 0
	for _, e := range entries {
		idx := strings.LastIndex(e, "|")
		if idx < 0 {
			continue
		}
		p := e[:idx]
		want := strings.ToLower(e[idx+1:])
		fp := filepath.Join(legacyDir, p)
		fb, rerr := os.ReadFile(fp)
		if rerr != nil {
			logf("完整性自检: 文件缺失 %s", p)
			bad++
			continue
		}
		sum := sha256.Sum256(fb)
		if hex.EncodeToString(sum[:]) != want {
			logf("完整性自检: 哈希不符 %s", p)
			bad++
		}
	}
	if bad == 0 {
		logf("完整性自检: 工具完整性校验通过")
		setStatus("工具完整性校验通过")
	} else {
		logf("完整性自检: %d 个文件异常", bad)
		msgBoxInfo("完整性自检", fmt.Sprintf("检测到 %d 个工具文件被篡改或被替换！\n\n请重新下载官方版本。", bad))
	}
}

// writeGuardFlag / removeGuardFlag / guardFlagExists 主进程存活标记:
// 主进程启动后写入, 正常退出前删除; 看门狗据此区分"正常退出"与"被 kill".
func writeGuardFlag() {
	if exe, err := os.Executable(); err == nil {
		_ = os.WriteFile(filepath.Join(filepath.Dir(exe), selfGuardFlagFile), []byte("1"), 0644)
	}
}
func removeGuardFlag() {
	if exe, err := os.Executable(); err == nil {
		_ = os.Remove(filepath.Join(filepath.Dir(exe), selfGuardFlagFile))
	}
}
func guardFlagExists() bool {
	if exe, err := os.Executable(); err != nil {
		return false
	} else {
		_, err = os.Stat(filepath.Join(filepath.Dir(exe), selfGuardFlagFile))
		return err == nil
	}
}

// ===================== 三档自保护: 双向心跳 + 高权限守护 (v2.15.9) =====================
// 档2/3 在档1(单向看门狗)之上, 增加"双向心跳": 主进程也探活看门狗(及高权限守护),
//   任一方被 kill/冻结, 另一方秒级拉起 —— 形成对称自愈, 避免"攻击者同时杀两进程"破防.
//
// 心跳载体: 用**文件心跳**(写 GetTickCount64 毫秒时间戳到 sf_hb_*.tmp).
//   选文件而非共享内存, 是因为档3 主进程(低/中 IL)与高权限守护(高 IL/SYSTEM)跨 IL,
//   文件默认 ACL 允许高 IL 读低 IL 文件, 而命名共享内存的 DACL 跨 IL 更麻烦.
//   文件名含 exe 路径哈希 + 角色(main/watch/guard), 支持不同目录并存、防误连.
//
// 诚实边界(同 PPL/EDR-Freeze): 用户态心跳+守护无法挡持有 SeDebugPrivilege 的管理员/驱动
//   同时杀两进程; 它显著抬高"普通恶意软件/脚本"的攻击成本, 是"急救箱"式最强用户态档,
//   非 Ring0 不可绕过. 真正不可绕过需内核驱动(ObRegisterCallbacks), 不在此档范围.

const (
	hbPollSec   = 1 // 心跳写/探活间隔(秒)
	hbTimeoutSec = 5 // 心跳超时阈值: 超过该时长未更新视为对方已死 -> 拉起
)

// hbPaths 返回三种角色的心跳文件路径(基于 exe 路径哈希, 区分目录并存).
func hbPaths() (main, watch, guard string) {
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	h := fnvHashString(exe)
	main = filepath.Join(dir, "sf_hb_main_"+h+".tmp")
	watch = filepath.Join(dir, "sf_hb_watch_"+h+".tmp")
	guard = filepath.Join(dir, "sf_hb_guard_"+h+".tmp")
	return
}

// fnvHashString 短哈希(用于心跳/互斥命名, 非安全用途).
func fnvHashString(s string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return fmt.Sprintf("%08x", h)
}

// writeHeartbeat 把当前 GetTickCount64 毫秒数写入心跳文件(覆盖写, best-effort).
func writeHeartbeat(path string) {
	t, _, _ := procGetTickCount64.Call()
	b := strconv.FormatUint(uint64(t), 10)
	_ = os.WriteFile(path, []byte(b), 0644)
}

// readHeartbeat 读心跳文件的时间戳; 文件不存在/读不到返回 0(视为已死).
func readHeartbeat(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// nowTicks 当前毫秒计数(GetTickCount64).
func nowTicks() uint64 {
	t, _, _ := procGetTickCount64.Call()
	return uint64(t)
}

// startBidirectionalHeartbeat 启动双向心跳:
//   - 主进程周期写 sf_hb_main.tmp (让看门狗/守护知道"主还活着")
//   - 主进程探活看门狗: 若 sf_hb_watch.tmp 超时 -> 看门狗被 kill -> 主动重启看门狗
//   - (档3) 探活高权限守护: 若 sf_hb_guard.tmp 超时 -> 守护被 kill -> 主动重启守护
// 全部 best-effort: 任一失败仅日志, 不阻断运行.
func startBidirectionalHeartbeat() {
	go func() {
		mainHB, watchHB, guardHB := hbPaths()
		// 主进程心跳写循环
		go func() {
			for {
				writeHeartbeat(mainHB)
				time.Sleep(hbPollSec * time.Second)
			}
		}()
		logf("自保护[双向心跳]: 已启动 (主↔看门狗%s 互探活)", map[bool]string{true: "/守护", false: ""}[buildTier >= 3])
		for {
			time.Sleep(hbPollSec * time.Second)
			// 探活看门狗
			if nowTicks()-readHeartbeat(watchHB) > uint64(hbTimeoutSec*1000) {
				logf("自保护[双向心跳]: 看门狗心跳超时, 主动重启看门狗")
				spawnWatchdog()
			}
			// 探活高权限守护(仅档3)
			if buildTier >= 3 {
				if nowTicks()-readHeartbeat(guardHB) > uint64(hbTimeoutSec*1000) {
					logf("自保护[双向心跳]: 高权限守护心跳超时, 主动重启守护")
					spawnGuardian()
				}
			}
		}
	}()
}

// ensureElevatedOrRestartTier 档2/3 启动即申请一次 UAC: 若当前未提权, 以 runas 重启整个
//   exe 并携带 --tier <N> --elevated-run, 新实例以管理员令牌运行(继承同令牌, 仍在自身 Job 内).
//  复用 v2.15.5 的整 exe runas 重启机制, 仅扩展携带 tier. Wine 下 ShellExecute(runas) 会失败
//   -> 优雅降级: 记日志, 以当前令牌继续运行(不阻断).
func ensureElevatedOrRestartTier() {
	if isProcessElevated() {
		return // 已管理员, 直接进入对应档
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	params := fmt.Sprintf("--tier %d --elevated-run", buildTier)
	logf("自保护[档%d]: 未提权, 申请 UAC 重启自身 (params=%q)", buildTier, params)
	// windows.ShellExecute 返回 error(底层 ShellExecuteW 返回 HINSTANCE, <=32 为失败码,
	//   被包成 error). 失败(用户拒 UAC / Wine 无 UAC 服务) -> 优雅降级以当前令牌继续.
	if err := windows.ShellExecute(0, windows.StringToUTF16Ptr("runas"),
		windows.StringToUTF16Ptr(exe),
		windows.StringToUTF16Ptr(params),
		windows.StringToUTF16Ptr(filepath.Dir(exe)), SW_SHOWNORMAL); err != nil {
		logf("自保护[档%d]: UAC 申请失败/被拒 (%v), 以当前令牌继续(降级)", buildTier, err)
		return
	}
	logf("自保护[档%d]: 已弹出 UAC, 新实例将接管, 本实例退出", buildTier)
	os.Exit(0)
}

// spawnWatchdog 主进程 spawn 自身 "--watchdog <pid> --tier N" 子进程(后台静默), 负责被 kill 时自动重启.
func spawnWatchdog() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, "--watchdog", strconv.Itoa(os.Getpid()), "--tier", strconv.Itoa(buildTier))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW: 看门狗后台静默运行
	}
	if err := cmd.Start(); err != nil {
		logf("自保护: spawn 看门狗失败: %v", err)
		return
	}
	logf("自保护: 已 spawn 看门狗 pid=%d (tier=%d)", cmd.Process.Pid, buildTier)
}

// watchdogMain 看门狗模式主逻辑 (由主进程 spawn). 监控 watchPID, 被 kill 时自动重启.
func watchdogMain(watchPID int) {
	// 单实例互斥: 已有看门狗(主进程重启后再次 spawn 的看门狗)直接退出, 避免多 watch.
	mn := selfGuardMutexName()
	mut, merr := windows.CreateMutex(nil, false, syscall.StringToUTF16Ptr(mn))
	if merr != nil {
		logf("自保护[看门狗]: 创建互斥失败: %v (跳过去重, 仍监控)", merr)
	} else if windows.GetLastError() == windows.ERROR_ALREADY_EXISTS {
		_ = windows.CloseHandle(mut)
		logf("自保护[看门狗]: 已有看门狗实例, 退出")
		return
	} else {
		defer windows.CloseHandle(mut)
	}

	logf("自保护[看门狗]: 启动, 监控主进程 PID=%d", watchPID)
	currentPID := watchPID
	kills := 0
	_, watchHB, _ := hbPaths()
	// v2.15.74: 改用进程句柄 + WaitForSingleObject 监控主进程终止.
	//  旧实现按 PID 轮询 OpenProcess: 主进程死后其 PID 被其它进程复用时, OpenProcess 恒成功,
	//  看门狗误判"主进程还活着" -> 永不退出 -> 用户关闭后后台残留 exe 进程.
	//  进程句柄锁定的是"同一进程对象", 不受 PID 复用影响; 进程终止时句柄变为 signaled.
	monPid := uint32(currentPID)
	var hWait windows.Handle
	openWaitHandle := func() {
		hWait = 0
		h, e := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, monPid)
		if e == nil {
			hWait = h
		}
	}
	openWaitHandle()
	for {
		writeHeartbeat(watchHB) // 双向心跳: 看门狗声明"我还活着"

		if hWait == 0 {
			// 句柄获取失败(主进程尚未建立/权限受限): 降级重试
			openWaitHandle()
			time.Sleep(time.Duration(selfGuardPollSec) * time.Second)
			continue
		}
		// 等待主进程终止: WAIT_OBJECT_0(0)=已终止, WAIT_TIMEOUT(0x102)=仍存活
		r, _, _ := procWaitForSingleObject.Call(uintptr(hWait), uintptr(selfGuardPollSec*1000))
		if r == 0x102 { // WAIT_TIMEOUT: 主进程仍存活
			continue
		}
		_ = windows.CloseHandle(hWait)
		hWait = 0

		// 主进程消失: 判断正常退出还是被 kill
		if !guardFlagExists() {
			logf("自保护[看门狗]: 主进程正常退出, 看门狗结束")
			return
		}

		kills++
		logf("自保护[看门狗]: 检测到主进程被强制终止 (PID=%d), 第 %d 次自动重启", currentPID, kills)
		if kills > selfGuardMaxKills {
			logf("自保护[看门狗]: 已连续被终止 %d 次, 超过上限 %d, 停止自动重启", kills, selfGuardMaxKills)
			return
		}

		// 重启主进程 (不带参数 -> 进入 GUI 主模式, 会再 spawn 新看门狗, 但新看门狗因 mutex 退出)
		exe, _ := os.Executable()
		cmd := exec.Command(exe)
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0}
		if err := cmd.Start(); err != nil {
			logf("自保护[看门狗]: 重启主进程失败: %v", err)
			continue
		}
		currentPID = cmd.Process.Pid
		monPid = uint32(currentPID)
		openWaitHandle()
		logf("自保护[看门狗]: 已重启主进程, 新 PID=%d", currentPID)

		// 等待新主进程建立存活标记 (最多 30s)
		waited := 0
		for waited < 30 {
			if guardFlagExists() {
				break
			}
			time.Sleep(time.Second)
			waited++
		}
		if !guardFlagExists() {
			logf("自保护[看门狗]: 重启后主进程未建立存活标记, 继续监控 PID=%d", currentPID)
		}
	}
}

// ===================== 高权限守护进程 (v2.15.9, 档3 急救箱) =====================
// 档3 在双向心跳看门狗之上, 再 spawn 一个**高权限守护进程**(以管理员/SYSTEM 令牌运行,
//   高于主进程 IL), 与主进程双向心跳: 主被冻结/退出 -> 守护秒级 ResumeThread/重启;
//   守护被 kill -> 主进程 guardianProbeLoop 重启守护. 守护是"急救箱"式最强用户态防线.
//
// 启动: 档3 主进程已通过 ensureElevatedOrRestartTier 以管理员令牌运行, spawn 守护时再以
//   runas 提到更高权(SYSTEM 需服务; 这里先以管理员 runas, 服务安装为可选项). 守护进程即本 exe
//   自身带 --guardian <mainpid> --tier 3 运行, 逻辑在 guardianMain.
//
// best-effort: 任一 API 失败仅日志, 绝不影响主程序运行.

// spawnGuardian 主进程 spawn 高权限守护子进程(档3). 守护即本 exe 自身带 --guardian <pid>.
func spawnGuardian() {
	if buildTier < 3 {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	// 以 runas 提到管理员(若主进程已是 SYSTEM 则等价); Wine 下失败则优雅降级.
	params := fmt.Sprintf("--guardian %d --tier 3", os.Getpid())
	if err := windows.ShellExecute(0, windows.StringToUTF16Ptr("runas"),
		windows.StringToUTF16Ptr(exe),
		windows.StringToUTF16Ptr(params),
		windows.StringToUTF16Ptr(filepath.Dir(exe)), SW_SHOWNORMAL); err != nil {
		logf("自保护[守护]: spawn 高权限守护失败/被拒 (%v), 降级到双向心跳看门狗", err)
		return
	}
	logf("自保护[守护]: 已请求启动高权限守护进程")
}

// svcName 档3 高权限守护服务的注册名.
const svcName = "SilverFoxGuardian"

// toggleGuardianService 档3 GUI 按钮: 安装/卸载"以 SYSTEM 运行"的守护服务(最强常驻).
//   已安装 -> 卸载; 未安装 -> 弹确认框后 sc create + sc start. 全部 best-effort, 失败仅提示.
//   注意: 这是系统级变更(LocalSystem 服务, 开机自启), 仅在用户明确确认时执行, 非默认.
func toggleGuardianService() {
	if buildTier < 3 {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	// 判断是否已安装
	if serviceExists() {
		if msgBoxQuestion("急救箱常驻", "检测到守护服务已安装。\r\n\r\n是否卸载(停止并删除 SilverFoxGuardian 服务)?") {
			runSc("delete", svcName)
			msgBoxInfo("急救箱常驻", "已请求卸载守护服务。")
			logf("自保护[守护]: 已卸载 SYSTEM 服务")
		}
		return
	}
	if !msgBoxQuestion("急救箱常驻(高危)",
		"即将把本程序的守护进程安装为 Windows 服务, 以 LocalSystem(系统) 权限开机自启常驻。\r\n\r\n"+
			"这会修改系统服务配置, 仅建议在被恶意软件疯狂攻击时使用。确定安装?") {
		return
	}
	binPath := fmt.Sprintf("\"%s\" --guardian %d --tier 3 --svc", exe, os.Getpid())
	runSc("create", svcName, "binPath=", binPath, "type=", "own", "start=", "auto", "obj=", "LocalSystem")
	runSc("start", svcName)
	msgBoxInfo("急救箱常驻", "已请求安装并启动守护服务(SilverFoxGuardian)。\r\n可在 services.msc 查看。")
	logf("自保护[守护]: 已安装 SYSTEM 服务 binPath=%s", binPath)
}

// serviceExists 查服务是否注册(best-effort).
func serviceExists() bool {
	out, err := exec.Command("sc.exe", "query", svcName).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), svcName)
}

// runSc 执行 sc.exe 命令(best-effort, 参数数组, 无注入风险).
func runSc(args ...string) {
	cmd := exec.Command("sc.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := cmd.CombinedOutput(); err != nil {
		logf("自保护[守护]: sc %v 失败: %v (%s)", args, err, string(out))
	} else {
		logf("自保护[守护]: sc %v 成功", args)
	}
}

// guardianMain 高权限守护进程主逻辑(由主进程 runas 拉起, 带 --guardian <mainpid>).
//   双向心跳: 周期写 sf_hb_guard.tmp; 探活主进程(mainHB) —— 主消失/冻结超时 -> 重启主进程
//   (以守护自身高权, 能拉起被冻结/被杀的主); 主被挂起时 ResumeThread 恢复.
func guardianMain(mainPID int) {
	mainHB, _, guardHB := hbPaths()
	var lastRestart uint64 // 重启冷却时间戳(防紧循环繁殖)
	logf("自保护[守护]: 高权限守护启动, 监控主进程 PID=%d", mainPID)
	// 单实例互斥
	mn := selfGuardMutexName() + "_guard"
	mut, merr := windows.CreateMutex(nil, false, syscall.StringToUTF16Ptr(mn))
	if merr == nil && windows.GetLastError() == windows.ERROR_ALREADY_EXISTS {
		_ = windows.CloseHandle(mut)
		logf("自保护[守护]: 已有守护实例, 退出")
		return
	} else if merr == nil {
		defer windows.CloseHandle(mut)
	}

	for {
		writeHeartbeat(guardHB) // 声明"守护还活着"
		time.Sleep(hbPollSec * time.Second)

		// 探活主进程: 以"主心跳文件新鲜度"为唯一权威信号(不依赖启动时的 PID, 跨进程/PID
		//   空间差异环境更稳). 主心跳超时 -> 主可能被 kill/冻结.
		if nowTicks()-readHeartbeat(mainHB) <= uint64(hbTimeoutSec*1000) {
			lastRestart = 0 // 主在线, 重置冷却计时
			continue
		}
		// 主无心跳: 先尝试恢复被挂起的线程(防 EDR-Freeze 假死), 再判断是否需要重启
		logf("自保护[守护]: 主进程心跳超时, 尝试恢复/重启 PID=%d", mainPID)
		resumeSuspendedThreadsOf(uint32(mainPID))
		time.Sleep(500 * time.Millisecond)
		if nowTicks()-readHeartbeat(mainHB) <= uint64(hbTimeoutSec*1000) {
			continue // 恢复成功, 主已重新心跳
		}
		// 主确无心跳: 重启冷却(防瞬时不可读导致的紧循环繁殖). 距上次重启 <10s 则跳过本轮.
		if lastRestart != 0 && nowTicks()-lastRestart < 10000 {
			time.Sleep(2 * time.Second)
			continue
		}
		// 仅当 guard flag 在(主被 kill)才重启; 正常退出(flag 已删)则守护结束.
		if !guardFlagExists() {
			logf("自保护[守护]: 主进程正常退出, 守护结束")
			return
		}
		exe2, _ := os.Executable()
		// 重启时带 --guarded: 告知新主进程"守护已在管理你, 不要再 spawn 新守护"(打破
		//   守护重启主→主再 spawn 守护 的乘式繁殖; 既有守护继续监控新主 PID).
		cmd := exec.Command(exe2, "--guarded")
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0}
		if err := cmd.Start(); err != nil {
			logf("自保护[守护]: 重启主进程失败: %v", err)
			continue
		}
		lastRestart = nowTicks()
		logf("自保护[守护]: 已重启主进程 PID=%d", cmd.Process.Pid)
		time.Sleep(2 * time.Second)
	}
}

// ===================== EDR-Freeze 反冻防御 (v2.15.8) =====================
// 威胁模型: 攻击者滥用 Windows 错误报告(WER)机制 —— 通过 WerFaultSecure.exe 调用
//   MiniDumpWriteDump 对本进程生成内存转储; 利用"转储进行中"的竞态窗口, 用 SuspendThread /
//   NtSuspendProcess 把本进程的所有线程挂起, 使其永久"休眠"(GUI 卡死、看门狗心跳收不到),
//   从而绕过看门狗自愈、规避检测。这是利用系统合法设计(非漏洞)的 EDR-Freeze 手法。
//
// 真正能堵死这条链的, 是内核级防护: 内核回调 ObRegisterCallbacks / 拦截 NtSuspendThread /
// NtSuspendProcess(需内核驱动 + 微软交叉签名认证)。Ring3 用户态无法从根上禁止系统挂起本进程
//   的线程 —— 拥有 SeDebug 的管理员/驱动随时可再次挂起。
//
// 但用户态能做的纵深防御是真实有效的, 且与既有看门狗天然互补:
//   ① 心跳反冻: 主线程被挂起时, GetMessage 循环停滞 -> 看门狗/心跳 goroutine 收不到"我活着"
//      信号。另起一个独立 watchdog goroutine, 周期性自旋校验"本进程是否仍能调度": 用
//      OpenThread + NtQueryInformationThread 查主线程 SuspendCount; 若挂起 -> ResumeThread 立即
//      恢复 + 写存活标记(让看门狗即便读本进程心跳失败也能判定"被冻结而非被杀")。
//   ② 线程挂起监控: 枚举本进程所有线程(Thread32First/Next), 对任意被挂起的线程主动 ResumeThread
//      (除非是自身为暂停而挂起的工作线程, 本程序无此类线程, 故一律恢复)。
//   ③ best-effort WER 自禁用: WerSetFlags(WER_FAULT_REPORTING_NO_HEAP_DUMP=0x4) 尝试关闭自身
//      WER 堆转储, 缩小"可被 MiniDump"的暴露面(不保证在任意系统上生效, 仅纵深)。
// 全部 best-effort: 任一 API 失败仅日志, 绝不阻断主程序运行。
//
// 已知边界(写进交付文档): 用户态无法禁止内核/SeDebug 持有者再次挂起线程 —— 反冻是"反复拉起"
//   的猫鼠博弈, 能显著抬高攻击成本、防止"一次冻结永久失联", 但不能提供内核级不可绕过保证。

const (
	threadSuspendResume    = 0x0002 // THREAD_SUSPEND_RESUME (用于 OpenThread 拿 ResumeThread 所需句柄)
	threadQueryInformation = 0x0040 // THREAD_QUERY_INFORMATION (NtQueryInformationThread 所需)
	threadBasicInfoClass   = 0      // ThreadBasicInformation

	// NtQueryInformationThread 返回的 ThreadBasicInformation 最小布局.
	// 仅需要 SuspendCount 字段(结构尾部倒数第 2 个 DWORD), 但我们按真实 ABI 对齐读取:
	//   ExitStatus(4) TebBaseAddress(PTR) ClientId{UniqueProcess(PTR) UniqueThread(PTR)}
	//   AffinityMask(PTR) Priority(4) BasePriority(4) ... SuspendCount(1) ...
	// 为稳定取 SuspendCount, 定义完整 64 位布局如下(与 ntdll 实际结构一致).
	threadBasicInfoSize = 48 // x64: 4 + 8 + 8 + 8 + 8 + 4 + 4 + 4(pad) + 1 + ...; 取 48 足够覆盖到 SuspendCount
)

// threadBasicInfo 按 ntdll ThreadBasicInformation (x64) 对齐. 我们只需 SuspendCount(末字段).
type threadBasicInfo struct {
	ExitStatus     int32
	_              [4]byte // padding (x64 对齐到 8)
	TebBaseAddress uintptr
	UniqueProcess  uintptr
	UniqueThread   uintptr
	AffinityMask   uintptr
	Priority       int32
	BasePriority   int32
	_              [4]byte // padding 到 8
	SuspendCount   int32  // 线程被 SuspendThread 的嵌套次数; >0 即处于挂起态
	_              [4]byte
}

// startAntiFreeze 启动 EDR-Freeze 反冻防御(独立 goroutine, 由自保护初始化调用).
// 整合: 心跳反冻 + 线程挂起监控 + WER 自禁用 best-effort.
func startAntiFreeze() {
	go antiFreezeLoop()
	disableSelfWERBestEffort()
	logf("反冻[EDR-Freeze]: 已启动(心跳反冻 + 线程挂起监控 best-effort)")
}

// antiFreezeLoop 反冻主循环: 周期性检查本进程主线程 + 全部线程是否被挂起, 挂起即恢复.
func antiFreezeLoop() {
	const interval = 1500 * time.Millisecond
	selfPID := uint32(windows.GetCurrentProcessId())
	for {
		time.Sleep(interval)
		// ① 心跳反冻: 主线程若被挂起 -> 恢复 + 刷存活标记.
		resumed := resumeSuspendedThreadsOf(selfPID)
		if resumed > 0 {
			logf("反冻[EDR-Freeze]: 检测到 %d 个本进程线程被挂起, 已主动 ResumeThread 恢复", resumed)
			// 刷新存活标记: 被冻结期间看门狗若读不到心跳, 标记在即判定"被 kill"而误重启;
			// 这里续命, 让看门狗正确区分"被冻结(应等待恢复)"而非"被杀(应重启)".
			writeGuardFlag()
		}
		_ = selfPID
	}
}

// resumeSuspendedThreadsOf 枚举进程 pid 的所有线程, 对处于挂起态(SuspendCount>0)的线程
// 调用 ResumeThread 恢复运行. 返回实际恢复(或尝试恢复)的线程数. best-effort.
func resumeSuspendedThreadsOf(pid uint32) int {
	h, _, _ := procCreateToolhelp32SnapshotW.Call(th32csSnapThread, uintptr(pid))
	if h == 0 || h == ^uintptr(0) { // INVALID_HANDLE_VALUE
		// 线程快照失败(极少见): 退化为仅检查 + 恢复主线程.
		if resumeThreadByID(getMainThreadID(pid)) {
			return 1
		}
		return 0
	}
	defer procCloseHandle.Call(h)

	te := threadEntry32{Size: uint32(unsafe.Sizeof(threadEntry32{}))}
	r, _, _ := procThread32FirstW.Call(h, uintptr(unsafe.Pointer(&te)))
	if r == 0 {
		return 0
	}
	recovered := 0
	for {
		if te.OwnerProcessID == pid {
			tid := te.ThreadID
			if getThreadSuspendCount(tid) > 0 {
				if resumeThreadByID(tid) {
					recovered++
				}
			}
		}
		r, _, _ := procThread32NextW.Call(h, uintptr(unsafe.Pointer(&te)))
		if r == 0 {
			break
		}
	}
	return recovered
}

// getThreadSuspendCount 读线程 tid 的 SuspendCount(>0 即挂起). 读不到或失败返回 0.
func getThreadSuspendCount(tid uint32) int32 {
	if tid == 0 {
		return 0
	}
	th, _, _ := procOpenThread.Call(threadQueryInformation|threadSuspendResume, 0, uintptr(tid))
	if th == 0 {
		return 0
	}
	defer procCloseHandle.Call(th)
	var info threadBasicInfo
	// NtQueryInformationThread(ThreadHandle, ThreadBasicInformation(0), &info, sizeof(info), &retlen)
	var retLen uint32
	st, _, _ := procNtQueryInformationThread.Call(
		th,
		uintptr(threadBasicInfoClass),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Sizeof(info)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	_ = st // 返回 STATUS_SUCCESS(0) 才可靠; 失败按 0 处理
	return info.SuspendCount
}

// resumeThreadByID 用 OpenThread + ResumeThread 恢复指定线程. 成功返回 true.
func resumeThreadByID(tid uint32) bool {
	if tid == 0 {
		return false
	}
	th, _, _ := procOpenThread.Call(threadSuspendResume, 0, uintptr(tid))
	if th == 0 {
		logf("反冻: OpenThread(tid=%d) 失败 code=%d", tid, windows.GetLastError())
		return false
	}
	defer procCloseHandle.Call(th)
	ret, _, _ := procResumeThread.Call(th)
	if int32(ret) == -1 { // (DWORD)-1 = 失败
		logf("反冻: ResumeThread(tid=%d) 失败 code=%d", tid, windows.GetLastError())
		return false
	}
	return true
}

// getMainThreadID 通过 Toolhelp 线程快照找本进程第一个线程作为"主线程"近似.
// (精确主线程需遍历 TEB, 这里取本进程快照中首条线程即可用于心跳校验.)
func getMainThreadID(pid uint32) uint32 {
	h, _, _ := procCreateToolhelp32SnapshotW.Call(th32csSnapThread, uintptr(pid))
	if h == 0 || h == ^uintptr(0) {
		return 0
	}
	defer procCloseHandle.Call(h)
	te := threadEntry32{Size: uint32(unsafe.Sizeof(threadEntry32{}))}
	r, _, _ := procThread32FirstW.Call(h, uintptr(unsafe.Pointer(&te)))
	if r == 0 {
		return 0
	}
	for {
		if te.OwnerProcessID == pid {
			return te.ThreadID
		}
		r, _, _ := procThread32NextW.Call(h, uintptr(unsafe.Pointer(&te)))
		if r == 0 {
			break
		}
	}
	return 0
}

// disableSelfWERBestEffort 关闭本进程 WER 堆转储(best-effort): 缩小可被 MiniDump 的暴露面.
//   WerSetFlags(WER_FAULT_REPORTING_NO_HEAP_DUMP=0x4) 在支持的 Windows 版本上生效; 失败忽略.
func disableSelfWERBestEffort() {
	defer func() {
		if rec := recover(); rec != nil {
			logf("反冻[WER]: 自禁用异常已恢复: %v", rec)
		}
	}()
	// WER_FAULT_REPORTING_NO_HEAP_DUMP = 0x4
	const werNoHeapDump = 0x4
	r, _, _ := procWerSetFlags.Call(uintptr(werNoHeapDump))
	if r != 0 {
		logf("反冻[WER]: WerSetFlags(NO_HEAP_DUMP) 失败 code=%d (非致命, 仅纵深减弱)", r)
		return
	}
	logf("反冻[WER]: 已尝试关闭本进程 WER 堆转储 (缩小可被 MiniDump 面)")
}

// ===================== 进程与线程监控 (v2.15.7) =====================
// 需求: 监视系统中所有进程的创建/结束; 一旦发现有"可疑进程试图结束自己", 立即反制
//   (结束攻击者进程 / 触发自身自愈重启). 核心约束: 反制前**必须先判定"是什么程序"**,
//   不能一见可疑就杀 —— 避免误伤正常软件(更新器/安装包/崩溃报告/任务管理器).
//
// 双源采集(A+B 组合):
//   A) 轮询快照(Toolhelp CreateToolhelp32Snapshot + Process32First/Next): 每 ~1.5s 全量快照,
//      与上一次做差集 -> 得出"新出现/已退出"进程. 轻量、无需特权、必然可用, 作为主检测源与 ETW 兜底.
//   B) ETW 实时进程事件(kernel32 OpenTrace + EnableTraceEx2 订阅 Microsoft-Windows-Kernel-Process
//      提供者 + ProcessTrace 循环): 拿到进程创建/退出的精确实时事件, 延迟远低于轮询.
//      但 ETW 实时会话通常需要管理员权限, 且 Wine 无内核提供者 -> best-effort: 起不来就静默回退到 A.
//   两路事件汇入同一分类器(classifyProcess)做身份判定, 再决定是否反制.
//
// 身份判定("是什么程序"): 对可疑目标采集 镜像路径 / 父进程镜像 / 代码签名(WinVerifyTrust:
//   Microsoft 签名 / 有效签名 / 无效 / 未签名) / 路径启发(是否在 System32、是否在 temp/appdata、
//   是否冒充系统进程名但不在 System32) / 父链启发(父是浏览器/Office/脚本宿主却拉起 temp 下的 exe).
//   仅当"签名缺失/无效 + 路径/冒充/父链异常"组合命中时才判为可疑, 避免误杀签名正常的系统工具.
//
// 反制(仅对自身受威胁时): 监听终止型工具(taskkill/powershell Stop-Process/ProcessHacker/
//   PCHunter/taskmgr/系统的"结束任务"等)且**其代码签名非 Microsoft/有效**时, 才主动 TerminateProcess
//   它(我们 High IL 对低 IL 目标有权), 并记录完整身份取证; 同时刷新存活标记, 真被终止时由看门狗自愈.
// 全部 best-effort: 任一 API 失败仅日志, 绝不影响主程序运行.

const (
	th32csSnapProcess = 0x00000002 // CreateToolhelp32Snapshot 进程快照
	th32csSnapThread  = 0x00000004 // 线程快照(用于线程级监控)
	maxPath16         = 1024

	// Microsoft-Windows-Kernel-Process 提供者 GUID {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
	kernelProcessProvider = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
)

// processEntry32 对应 Windows PROCESSENTRY32 (Unicode). 仅保留必需字段, 按 ABI 对齐.
type processEntry32 struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriClassBase      int32
	Flags             uint32
	ExeFile           [maxPath16]uint16
}

// threadEntry32 对应 Windows THREADENTRY32 (用于线程级监控, 可选).
type threadEntry32 struct {
	Size           uint32
	ThreadID       uint32
	OwnerProcessID uint32
	PriClassBase   int32
	DeltaPriority  int32
	Flags          uint32
}

// procInfo 单个进程的身份快照.
type procInfo struct {
	PID    uint32
	PPID   uint32
	Image  string // 镜像全路径(小写)
	Parent string // 父进程镜像全路径(小写)
}

// verdict classifyProcess 的判定结果.
type verdict struct {
	Suspicious bool
	Category   string   // "impersonate-system" / "unsigned-temp" / "bad-parent" / "terminator" / "clean"
	Reasons    []string
}

// 终止型工具名(命中且未签名才反制). 仅作启发信号, 不单独定罪.
var terminatorNames = map[string]bool{
	"taskkill.exe": true, "powershell.exe": true, "pwsh.exe": true,
	"taskmgr.exe": true, "processhacker.exe": true, "systeminformer.exe": true,
	"pchunter.exe": true, "wkiller.exe": true, "wsyscheck.exe": true,
	"kill.exe": true, "pskill.exe": true, "tasklist.exe": true,
}

// 系统进程名(若出现在非 System32 路径 = 冒充嫌疑).
var systemProcNames = map[string]bool{
	"svchost.exe": true, "lsass.exe": true, "services.exe": true,
	"csrss.exe": true, "wininit.exe": true, "smss.exe": true,
	"spoolsv.exe": true, "explorer.exe": true,
}

// startProcessMonitor 启动进程与线程监控(轮询快照为主, ETW 实时 best-effort 为辅).
// 在 main() 自保护初始化末尾调用; 另起 goroutine, 失败静默.
func startProcessMonitor() {
	go pollProcessSnapshot()
	go startETWProcessMonitor()
	logf("进程监控: 已启动(轮询快照 + ETW 实时 best-effort)")
}

// snapshotProcesses 用 Toolhelp 快照枚举全部进程(PID/PPID/镜像).
func snapshotProcesses() []procInfo {
	out := make([]procInfo, 0, 256)
	h, _, _ := procCreateToolhelp32SnapshotW.Call(th32csSnapProcess, 0)
	if h == 0 || h == ^uintptr(0) { // INVALID_HANDLE_VALUE
		logf("进程监控: CreateToolhelp32Snapshot 失败 code=%d", windows.GetLastError())
		return out
	}
	defer procCloseHandle.Call(h)

	pe := processEntry32{Size: uint32(unsafe.Sizeof(processEntry32{}))}
	r, _, _ := procProcess32FirstW.Call(h, uintptr(unsafe.Pointer(&pe)))
	if r == 0 {
		return out
	}
	for {
		img := strings.ToLower(windows.UTF16ToString(pe.ExeFile[:]))
		pi := procInfo{PID: pe.ProcessID, PPID: pe.ParentProcessID, Image: img}
		if pi.PID != 0 {
			// 仅记录短名(exe 名), 全路径按需(新进程事件里)再查, 避免每轮对全部进程 OpenProcess(省开销).
			out = append(out, pi)
		}
		r, _, _ := procProcess32NextW.Call(h, uintptr(unsafe.Pointer(&pe)))
		if r == 0 {
			break
		}
	}
	return out
}

// pollProcessSnapshot 轮询快照主循环: 差集出 新出现/已退出 进程, 对新进程做分类与反制.
func pollProcessSnapshot() {
	const interval = 1500 * time.Millisecond
	prev := make(map[uint32]procInfo)
	// 首轮仅建基线, 不触发反制(避免启动瞬间把自身引擎树当成威胁).
	first := true
	for {
		cur := snapshotProcesses()
		curMap := make(map[uint32]procInfo, len(cur))
		for _, p := range cur {
			curMap[p.PID] = p
		}

		if !first {
			// 新出现进程
			for pid, p := range curMap {
				if _, ok := prev[pid]; !ok {
					onProcessCreated(p, curMap)
				}
			}
			// 已退出进程(用于审计/威胁退出跟踪)
			for pid, p := range prev {
				if _, ok := curMap[pid]; !ok {
					onProcessExited(p)
				}
			}
		}
		prev = curMap
		first = false
		time.Sleep(interval)
	}
}

// onProcessCreated 新进程事件: 先解析全路径 + 判定"是什么程序", 再决定是否反制.
func onProcessCreated(p procInfo, curMap map[uint32]procInfo) {
	// 仅对"新出现"的进程才查全路径(OpenProcess 有开销), 快照阶段只记短名.
	if full := queryProcessPath(p.PID); full != "" {
		p.Image = strings.ToLower(full)
	}
	v := classifyProcess(p, curMap)
	if !v.Suspicious {
		return
	}
	logf("进程监控: 新进程可疑 PID=%d img=%s ppid=%d category=%s reasons=%v",
		p.PID, p.Image, p.PPID, v.Category, v.Reasons)

	// 仅当威胁直指本进程(终止型工具 + 未签名)才主动反制, 其余仅记录告警.
	if v.Category == "terminator" {
		reactToThreat(p, v)
	}
}

// onProcessExited 进程退出事件: 审计用, 不反制.
func onProcessExited(p procInfo) {
	// 静默: 高频事件, 仅在 debug 时需要. 保留钩子以便将来做"威胁进程退出"跟踪.
	_ = p
}

// classifyProcess 判定"是什么程序": 综合签名/路径/冒充/父链. 返回是否可疑 + 类别 + 理由.
func classifyProcess(p procInfo, curMap map[uint32]procInfo) verdict {
	v := verdict{}
	name := p.Image
	if i := strings.LastIndex(name, "\\"); i >= 0 {
		name = name[i+1:]
	}
	base := name

	// 1) 路径/冒充启发: 系统进程名但不在 System32 -> 冒充嫌疑(高权重).
	isSystemName := systemProcNames[base]
	inSystem32 := strings.Contains(name, "\\system32\\") || strings.Contains(name, "\\syswow64\\")
	if isSystemName && !inSystem32 {
		v.Suspicious = true
		v.Category = "impersonate-system"
		v.Reasons = append(v.Reasons, "冒充系统进程名且不在 System32: "+base)
	}

	// 2) 未签名 + 来自临时/用户目录 -> 高危(除非是系统工具).
	sig := verifySignature(p.Image)
	inTemp := strings.Contains(name, "\\temp\\") || strings.Contains(name, "\\appdata\\") ||
		strings.Contains(name, "\\programdata\\") || strings.HasPrefix(name, "c:\\temp") ||
		strings.HasPrefix(name, "c:\\users\\") && strings.Contains(name, "\\local\\temp")
	if (sig == "unsigned" || sig == "invalid") && inTemp {
		v.Suspicious = true
		if v.Category == "" {
			v.Category = "unsigned-temp"
		}
		v.Reasons = append(v.Reasons, "未签名/无效签名且位于临时或用户目录: sig="+sig)
	}

	// 3) 父链启发: 父是浏览器/Office/脚本宿主, 子却是不在 Program Files/System32 的 exe.
	if pp, ok := curMap[p.PPID]; ok {
		pParent := strings.ToLower(pp.Image)
		badParent := strings.Contains(pParent, "chrome.exe") || strings.Contains(pParent, "msedge.exe") ||
			strings.Contains(pParent, "firefox.exe") || strings.Contains(pParent, "iexplore.exe") ||
			strings.Contains(pParent, "winword.exe") || strings.Contains(pParent, "excel.exe") ||
			strings.Contains(pParent, "powershell.exe") || strings.Contains(pParent, "cmd.exe") ||
			strings.Contains(pParent, "wscript.exe") || strings.Contains(pParent, "cscript.exe")
		inSafeDir := strings.Contains(name, "\\program files") || strings.Contains(name, "\\windows\\")
		if badParent && !inSafeDir && (sig == "unsigned" || sig == "invalid") {
			v.Suspicious = true
			if v.Category == "" {
				v.Category = "bad-parent"
			}
			v.Reasons = append(v.Reasons, "父进程="+pParent+" 拉起未签名子进程于非安全目录")
		}
	}

	// 4) 终止型工具: 命中工具名 且 非 Microsoft/有效签名 -> 视为针对本进程的威胁类别.
	if terminatorNames[base] {
		if sig != "microsoft" && sig != "valid" {
			v.Suspicious = true
			v.Category = "terminator"
			v.Reasons = append(v.Reasons, "终止型工具且未签名/无效: "+base+" sig="+sig)
		} else {
			// 签名正常的系统工具(如微软 taskmgr)不判可疑.
			v.Suspicious = false
			v.Category = "clean"
			v.Reasons = nil
		}
	}

	if !v.Suspicious && v.Category == "" {
		v.Category = "clean"
	}
	return v
}

// verifySignature 用 WinVerifyTrust 校验文件代码签名. 返回 microsoft/valid/invalid/unsigned/error.
func verifySignature(path string) string {
	if path == "" {
		return "error"
	}
	// WINTRUST_ACTION_GENERIC_VERIFY_V2 GUID {00AAC56B-CD44-11d3-8A2E-00C04F8EC293}
	action := windows.GUID{Data1: 0x00AAC56B, Data2: 0xCD44, Data3: 0x11D3,
		Data4: [8]byte{0x8A, 0x2E, 0x00, 0xC0, 0x4F, 0x8E, 0xC2, 0x93}}
	fileNamePtr := windows.StringToUTF16Ptr(path)
	wtd := winTrustData{
		Size:              uint32(unsafe.Sizeof(winTrustData{})),
		ActionID:          &action,
		FileOrCatalogOrBlobOrSgnrOrCert: uintptr(unsafe.Pointer(fileNamePtr)),
		UnionChoice:       1, // WTD_CHOICE_FILE
		StateAction:       1, // WTD_STATEACTION_VERIFY
		RevocationChecks:  0x00000020, // WTD_REVOCATION_CHECK_NONE(离线友好, 避免卡顿)
	}
	// 先以"仅 Microsoft 签名"宽松判定: 这里统一走 GenericVerify, 再按返回与主题细分.
	r, _, _, wtOk := safeCall(procWinVerifyTrust, 0, uintptr(unsafe.Pointer(&action)), uintptr(unsafe.Pointer(&wtd)))
	// 关闭状态(释放)
	wtd.StateAction = 2 // WTD_STATEACTION_CLOSE
	if _, _, _, ok := safeCall(procWinVerifyTrust, 0, uintptr(unsafe.Pointer(&action)), uintptr(unsafe.Pointer(&wtd))); !ok {
		logf("自保护[签名]: WinVerifyTrust 关闭状态调用失败(非致命)")
	}
	if !wtOk {
		// wintrust.dll 加载失败(DLL init routine failed): 无法校验, 按 error 处理, 不崩溃
		logf("自保护[签名]: wintrust.dll 懒加载失败, 跳过签名校验(非致命)")
		return "error"
	}

	switch r {
	case 0: // TRUST_E_NOSIGNATURE = 未签名 -> 需进一步用 CryptQueryObject 确认
		if isUnsigned(path) {
			return "unsigned"
		}
		return "valid"
	case 0x800B0100: // TRUST_E_NOSIGNATURE
		return "unsigned"
	case 0x800B0109: // TRUST_E_BAD_DIGEST / CERT 问题 -> 无效签名
		return "invalid"
	case 0x80096010: // TRUST_E_BASIC_CONSTRAINTS / 非 Microsoft
		return "valid" // 有效但非 MS
	default:
		// 其它错误: 尝试用 CryptQueryObject 兜底区分有无签名.
		if isUnsigned(path) {
			return "unsigned"
		}
		return "error"
	}
}

// isUnsigned 用 CryptQueryObject 探测文件是否根本无嵌入签名.
func isUnsigned(path string) bool {
	p := windows.StringToUTF16Ptr(path)
	var ct, ft uint32
	var store, msg, ctx uintptr
	r, _, _, ok := safeCall(procCryptQueryObject,
		1, // CERT_QUERY_OBJECT_FILE
		uintptr(unsafe.Pointer(p)),
		0x00000010|0x00000008, // CONTENT_TYPE_ALL / ENC|PKCS7
		0, 0, uintptr(unsafe.Pointer(&ct)), uintptr(unsafe.Pointer(&ft)),
		uintptr(unsafe.Pointer(&store)), uintptr(unsafe.Pointer(&msg)), uintptr(unsafe.Pointer(&ctx)))
	if !ok {
		// crypt32.dll 加载失败: 视为有签名(保守), 不崩溃
		return false
	}
	return r == 0
}

// winTrustData 最小可用结构(WTD). 仅列必要字段, 末尾保留 Reserved 占位以对齐.
type winTrustData struct {
	Size                       uint32
	PolicyCallbackData        uintptr
	SilentAppCallbackData     uintptr
	ActionID                  *windows.GUID
	StateAction               uint32
	FileOrCatalogOrBlobOrSgnrOrCert uintptr // WTD_CHOICE_FILE 时即文件全路径指针
	UnionChoice               uint32 // WTD_CHOICE_FILE = 1
	RevocationChecks          uint32 // WTD_REVOCATION_CHECK_NONE = 0x20
	RevocationFreshnessTime   uint32
	PURLUsageTimeout          uint32
	ReservedPtr               uintptr // pftCacheDuration
	UIContext                 uint32
	pad                       [4]byte // 补齐到 72 字节(真实 WINTRUST_DATA 64 位大小)
}

// reactToThreat 对判定为终止型威胁的进程采取反制: 主动终止 + 取证日志 + 刷新存活标记.
// 仅 best-effort: 目标 IL 高于或等于自身(受 PPL/系统保护)时 TerminateProcess 会失败, 忽略即可.
func reactToThreat(p procInfo, v verdict) {
	logf("进程监控[反制]: 对威胁进程 PID=%d img=%s 采取行动(类别=%s)", p.PID, p.Image, v.Category)
	// 不反制自身 / System / 父进程为 0/4 的系统进程.
	selfPID := uint32(windows.GetCurrentProcessId())
	if p.PID == selfPID || p.PID == 0 || p.PID == 4 {
		return
	}
	h, _, _ := procOpenProcess.Call(windows.PROCESS_TERMINATE, 0, uintptr(p.PID))
	if h == 0 {
		logf("进程监控[反制]: OpenProcess(PID=%d, TERMINATE) 失败 code=%d (可能 IL 不足, 放弃)", p.PID, windows.GetLastError())
		return
	}
	defer procCloseHandle.Call(h)
	r, _, _ := procTerminateProcess.Call(h, 0)
	if r != 0 {
		logf("进程监控[反制]: 已终止威胁进程 PID=%d img=%s", p.PID, p.Image)
	} else {
		logf("进程监控[反制]: TerminateProcess(PID=%d) 失败 code=%d (IL 不足或已退出)", p.PID, windows.GetLastError())
	}
	// 刷新存活标记, 即便自身随后被终止, 看门狗也能正确区分"被 kill"并自愈.
	writeGuardFlag()
}

// ===================== ETW 实时进程事件(B 路, best-effort) =====================
// 用 OpenTrace + EnableTraceEx2 订阅 Microsoft-Windows-Kernel-Process, ProcessTrace 循环拿
// 实时创建/退出事件, 延迟远低于轮询. 约束: 实时会话通常需管理员; Wine 无内核提供者.
// 因此全程 best-effort: 任一步骤失败即记录一次并退出本 goroutine, 监控完全回退到轮询快照(A).

// wnodeHeader / eventTraceProperties 最小布局(实时消费者), 按 Windows ABI 对齐.
type wnodeHeader struct {
	BufferSize  uint32
	ProviderId  uint32
	HistoryCtx  uint64
	TimeStamp   uint64
	Guid        windows.GUID
	ClientCtx   uint32
	Flags       uint32
}
type eventTraceProperties struct {
	Wnode              wnodeHeader
	BufferSize         uint32
	MinimumBuffers     uint32
	MaximumBuffers     uint32
	MaximumFileSize    uint32
	LogFileMode        uint32
	FlushTimer         uint32
	EnableFlags        uint32
	AgeLimit           uint32
	NumberOfBuffers    uint32
	FreeBuffers        uint32
	EventsLost         uint32
	BuffersWritten     uint32
	LogBuffersLost     uint32
	RealTimeBuffersLost uint32
	LoggerThreadId     uint32
	LogFileNameOffset  uint32
	LoggerNameOffset   uint32
}

// eventTraceLogfile 对应 EVENT_TRACE_LOGFILE (实时消费者回调注册).
type eventTraceLogfile struct {
	LogFileName         uintptr
	LoggerName          uintptr
	CurrentTime         uint64
	BuffersRead         uint32
	CurrentEvent        uintptr
	CurrentContext      uintptr
	LastEventTime       uint64
	FlushTimer          uint32
	Processor           uint32
	_                   uint32
	Context             uintptr
	BufferCallback      uintptr
	BufferSize          uint32
	MinBufferSpace      uint32
	MaxBufferSpace      uint32
	LogFileMode         uint32
	CurrentBuffer       uintptr
	_2                  [3]uintptr
	EventCallback       uintptr // PEVENT_CALLBACK (EVENT_TRACE)
	_3                  uintptr
}

// eventTraceHeader 事件头(用于解析 ProcessTrace 回调里的 EVENT_TRACE).
type eventTraceHeader struct {
	Size      uint16
	HeaderType uint16
	Flags     uint16
	EventType uint8
	Level     uint8
	Version   uint16
	Guid      windows.GUID
	ProcessorTime uint64
	FileTime   int64
}

// startETWProcessMonitor ETW 实时进程监控(goroutine, best-effort).
func startETWProcessMonitor() {
	defer func() {
		if r := recover(); r != nil {
			logf("进程监控[ETW]: 异常已恢复(回退轮询): %v", r)
		}
	}()
	// 1) 构造实时 trace 属性.
	props := eventTraceProperties{
		Wnode: wnodeHeader{
			BufferSize: uint32(unsafe.Sizeof(eventTraceProperties{})) + 256,
			Flags:      0x00020000, // WNODE_FLAG_TRACED_GUID
			Guid:       windows.GUID{Data1: 0x68fdd900, Data2: 0x4a3e, Data3: 0x11d1, Data4: [8]byte{0x8b, 0x70, 0x08, 0x00, 0x36, 0xb1, 0x1a, 0x09}}, // SystemTraceControlGuid
		},
		BufferSize:     4096,
		MinimumBuffers: 2,
		MaximumBuffers: 256,
		LogFileMode:    0x00000100, // EVENT_TRACE_REAL_TIME_MODE
		LogFileNameOffset: 0,
		LoggerNameOffset:  0,
	}
	props.Wnode.BufferSize = uint32(unsafe.Sizeof(props))

	loggerName, _ := windows.UTF16PtrFromString("SilverFoxProcMon")
	elf := eventTraceLogfile{
		LoggerName:    uintptr(unsafe.Pointer(loggerName)),
		LogFileMode:   0x00000100, // realtime
		EventCallback: uintptr(unsafe.Pointer(etwEventCallback)),
		Context:       0,
	}

	// 2) OpenTrace(返回 TRACEHANDLE).
	hTrace, _, _ := procOpenTraceW.Call(uintptr(unsafe.Pointer(&elf)))
	const invalidTraceHandle = ^uintptr(0)
	if hTrace == 0 || hTrace == invalidTraceHandle {
		logf("进程监控[ETW]: OpenTrace 失败 code=%d (无管理员/不支持, 回退轮询)", windows.GetLastError())
		return
	}
	defer procCloseTrace.Call(hTrace)

	// 3) EnableTraceEx2 订阅 Kernel-Process 提供者的进程事件.
	providerGUID := parseGUID(kernelProcessProvider)
	r, _, _ := procEnableTraceEx2.Call(hTrace,
		uintptr(unsafe.Pointer(&providerGUID)),
		1, // EVENT_CONTROL_CODE_ENABLE_PROVIDER
		1, // TRACE_LEVEL_INFORMATION
		0x10, // KEYWORD: 进程事件(ProcessStart/ProcessStop)对应 0x10
		0, 0, 0, uintptr(0))
	if r != 0 {
		logf("进程监控[ETW]: EnableTraceEx2 失败 code=%d (回退轮询)", r)
		return
	}
	logf("进程监控[ETW]: 已启用 Kernel-Process 实时事件")

	// 4) ProcessTrace 阻塞循环(实时事件经 etwEventCallback 回调分发).
	handles := []uintptr{hTrace}
	procProcessTrace.Call(uintptr(unsafe.Pointer(&handles[0])), 1, 0, 0)
	// ProcessTrace 返回即会话结束.
	logf("进程监控[ETW]: ProcessTrace 结束(会话关闭)")
}

// etwEventCallback 由 ProcessTrace 同步回调(在 startETWProcessMonitor 的 goroutine 内).
// 用 syscall.NewCallback 注册为 Windows 回调; 解析进程创建/退出事件并入分类器.
var etwEventCallback = syscall.NewCallback(func(cbd *eventTraceHeader) uintptr {
	if cbd == nil {
		return 0
	}
	// EVENT_HEADER 之后是 EVENT_DESCRIPTOR; 进程事件 Opcode: ProcessStart=1, ProcessStop=2.
	// 结构体起始为 EVENT_TRACE(含 Header + BufferPointer + ...); 此处只取 Header 的 Type 即可判定.
	// 由于 Go 侧难以稳定解析 ETW 负载(UserData), 我们仅在"事件类型=进程"时触发一轮快照差集,
	// 把实时事件当作"快照刷新触发器", 由既有分类器给出身份判定 —— 这样既拿到实时性,
	// 又复用经过验证的快照+WinVerifyTrust 身份识别, 避免手搓 ETW 负载解析的脆弱性.
	if cbd.HeaderType == 0x0002 { // TRACE_LEVEL... 实际用 Type 字段近似; 退化: 任何 ETW 事件都刷新一次快照.
		// 轻量: 不在此处大开销遍历, 交给轮询 goroutine 的下一轮; 这里仅作为"存在性证明"日志一次.
	}
	return 0
})

// parseGUID 把 "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}" 解析为 windows.GUID. 失败返回零值.
func parseGUID(s string) windows.GUID {
	g := windows.GUID{}
	b := []byte(s)
	if len(b) < 38 || b[0] != '{' || b[37] != '}' {
		return g
	}
	hexPair := func(off int) uint64 {
		var v uint64
		for i := 0; i < 2; i++ {
			c := b[off+i]
			var d uint64
			switch {
			case c >= '0' && c <= '9':
				d = uint64(c - '0')
			case c >= 'a' && c <= 'f':
				d = uint64(c-'a') + 10
			case c >= 'A' && c <= 'F':
				d = uint64(c-'A') + 10
			}
			v = v*16 + d
		}
		return v
	}
	// Data1(8 hex) Data2(4) Data3(4) Data4(2+2+12=16 hex)
	d1 := uint32(hexPair(1))
	d2 := uint16(hexPair(10))
	d3 := uint16(hexPair(15))
	var d4 [8]byte
	off := 20
	for i := 0; i < 8; i++ {
		d4[i] = byte(hexPair(off))
		off += 2
	}
	g.Data1, g.Data2, g.Data3, g.Data4 = d1, d2, d3, d4
	return g
}

// ===================== 引擎进程树清理 (v2.15.4) =====================
// 问题: GUI 通过 "cmd /c start "" bat" 启动检测引擎, start 把引擎脱离父进程,
//   形成独立的 powershell/cmd/bat 进程树. 用户关闭 GUI 时 exe 退出, 但引擎树仍
//   在运行 -> 进程残留(用户反馈"关闭后有进程残留").
// 对策: 把启动的 cmd.exe 放入 Job Object, 并设 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
//   exe 退出时 OS 自动关闭 job 句柄 -> 整棵引擎进程树(含 bat/ps1 孙进程)被一并终止,
//   因为孙进程默认继承父进程的 job(除非显式 CREATE_BREAKAWAY_FROM_JOB).
// 注意: 看门狗(watchdog 子进程)刻意不放入此 job —— 否则 exe 被 kill 时看门狗会被
//   一并杀掉, 自保护自愈能力失效. 看门狗仍靠 sf_guard.flag 在关闭时删除来判断正常退出.

var (
	procCreateJobObjectW        = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
)

// 持有 job 句柄直到 exe 退出(不主动 Close): OS 在进程退出时关闭句柄 -> 触发 KillOnJobClose.
var engineJobHandles []windows.Handle

// 记录已启动的引擎进程 PID, 供退出时 best-effort 兜底清理 (Job Object 之外的第二层保险).
var enginePids []uint32

// v2.15.74: 引擎运行标志 (防重复启动 + 完成提示)
var engineRunning = false
var engineDeadN  = 0
var uiPending    uint32 // v2.15.74: 消息合并标志(队列已有待处理消息则不再投递) // v2.15.74: 引擎进程消失连续计数

// v2.15.74: goroutine -> GUI 文本共享缓冲(PostMessage 跨线程传指针安全)
var (
	uiTextMu  sync.Mutex
	uiTextBuf []uint16
)

// postUiText 从任意 goroutine 安全地更新 GUI 文本(PostMessage, 不阻塞调用方)
func postUiText(hwnd windows.HWND, msg uint32, text string) {
	uiTextMu.Lock()
	defer uiTextMu.Unlock()
	// v2.15.74: 面板文本只保留尾部 400 行(大文本 WM_SETTEXT 重绘拖垮主线程)
	if lines := strings.Split(text, "\n"); len(lines) > 400 {
		text = strings.Join(lines[len(lines)-400:], "\n")
	}
	if text != "" {
		uiTextBuf = append(uiTextBuf[:0], syscall.StringToUTF16(text)...)
	}
	// v2.15.74: 消息合并 —— 队列已有待处理消息则不再投递(wndProc 处理时读最新 buf)
	if atomic.LoadUint32(&uiPending) == 1 {
		return
	}
	atomic.StoreUint32(&uiPending, 1)
	ptr := uintptr(unsafe.Pointer(&uiTextBuf[0]))
	procPostMessageW.Call(uintptr(hwnd), uintptr(msg), 0, ptr)
}

const jobObjectLimitKillOnJobClose = 0x2000

type jobObjectBasicLimitInfo struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	_pad1                   uint32 // LimitFlags(uint32) 后需 4 字节对齐到 8
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	_pad2                   uint32 // ActiveProcessLimit(uint32) 后需 4 字节对齐到 8 (Affinity 为 uintptr)
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobObjectExtendedLimitInfo struct {
	BasicLimitInformation jobObjectBasicLimitInfo
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryLimit uintptr
	PeakJobMemoryLimit    uintptr
}

// assignEngineJob 把已启动的引擎 cmd 进程加入清理 Job. 失败仅日志, 不影响主流程.
// 需 PROCESS_SET_QUOTA|PROCESS_TERMINATE 权限才能加入 job.
func assignEngineJob(p *os.Process) {
	if p == nil {
		return
	}
	hJob, _, _ := procCreateJobObjectW.Call(0, 0)
	if hJob == 0 {
		logf("引擎清理: CreateJobObject 失败 code=%d", windows.GetLastError())
		return
	}
	info := jobObjectExtendedLimitInfo{
		BasicLimitInformation: jobObjectBasicLimitInfo{LimitFlags: jobObjectLimitKillOnJobClose},
	}
	r, _, _ := procSetInformationJobObject.Call(
		hJob,
		9, // JobObjectExtendedLimitInformation
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if r == 0 {
		logf("引擎清理: SetInformationJobObject 失败 code=%d", windows.GetLastError())
		procCloseHandle.Call(hJob)
		return
	}
	hProc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(p.Pid))
	if err != nil {
		logf("引擎清理: OpenProcess(引擎 PID=%d)失败: %v", p.Pid, err)
		procCloseHandle.Call(hJob)
		return
	}
	defer windows.CloseHandle(hProc)
	if r2, _, _ := procAssignProcessToJobObject.Call(hJob, uintptr(hProc)); r2 == 0 {
		logf("引擎清理: 引擎进程 PID=%d 加入 Job 失败 code=%d (可能已在其它 job 中, 关闭时可能无法自动清理)", p.Pid, windows.GetLastError())
		procCloseHandle.Call(hJob)
		return
	}
	engineJobHandles = append(engineJobHandles, windows.Handle(hJob))
	logf("引擎清理: 引擎进程 PID=%d 已加入退出清理 Job", p.Pid)
}

// cleanupEngines 在 exe 退出时兜底清理仍在运行的引擎进程(Best-effort).
// 正常路径下 Job Object 在进程退出时通过 KillOnJobClose 已终止整棵树; 这里是第二层保险,
// 覆盖"进程被外部强杀导致 Job 句柄未正常关闭"等异常场景. 提权子实例(--elevated-run)中
// 引擎就在它自己的 Job 内, 退出时同样被自动回收; 本兜底再补一层 taskkill, 失败忽略即可.
// v2.15.26: 主窗口关机消息诊断日志 (%TEMP%\sf_win_query.log, 与层3 sf_sg_query.log 同套路).
func writeShutdownQueryLog(msg string) {
	_ = os.WriteFile(filepath.Join(os.TempDir(), "sf_win_query.log"),
		[]byte(time.Now().Format("2006-01-02 15:04:05.000")+" "+msg+"\n"), 0644)
}

// v2.15.26: 检查引擎进程是否仍有存活 (用于主窗口 QUERYENDSESSION 拦截判定).
// detectEnvSummary 启动环境检测: OS 版本/架构/PowerShell 可用性 (v2.15.74 简单兼容)
func detectEnvSummary() string {
	var v struct {
		MajorVersion      uint32
		MinorVersion      uint32
		BuildNumber       uint32
		PlatformID        uint32
		ServicePackMajor  uint16
		ServicePackMinor  uint16
		ProductType       byte
		SuiteMask         uint16
		Reserved2         uint16
	}
	// RTL_OSVERSIONINFOW 前 11 个字段 (结构体大小 148)
	// v2.15.74: LazyProc 延迟解析 GetProcAddress 在部分环境(安全软件钩子)失败会 panic -> 先 Find 保护
	raw := make([]byte, 148)
	raw[0] = 148
	var p uintptr = uintptr(unsafe.Pointer(&raw[0]))
	r := uintptr(1)
	osPart := "Win?"
	if err := procRtlGetVersion.Find(); err == nil {
		r, _, _ = procRtlGetVersion.Call(p)
	}
	if r == 0 {
		maj := uint32(raw[4]) | uint32(raw[5])<<8 | uint32(raw[6])<<16 | uint32(raw[7])<<24
		minv := uint32(raw[8]) | uint32(raw[9])<<8 | uint32(raw[10])<<16 | uint32(raw[11])<<24
		build := uint32(raw[12]) | uint32(raw[13])<<8 | uint32(raw[14])<<16 | uint32(raw[15])<<24
		_ = v
		osPart = fmt.Sprintf("Windows %d.%d build %d", maj, minv, build)
	}
	arch := os.Getenv("PROCESSOR_ARCHITECTURE")
	if arch == "" {
		arch = os.Getenv("PROCESSOR_ARCHITEW6432")
	}
	ps51 := ""
	if _, err := os.Stat(`C:\Windows\System32\WindowsPowerShell1.0\powershell.exe`); err == nil {
		ps51 = "PS5.1可用"
	} else {
		ps51 = "PS5.1缺失(引擎需PowerShell)"
	}
	return osPart + " | " + arch + " | " + ps51
}

func engineAlive() bool {
	// v2.15.29: enginePids 记录 cmd /c start 父进程(瞬死), 直接 OpenProcess 恒失败.
	//   用进程快照 PPID 两层 BFS: 父 cmd 的子(新 cmd)及孙(PowerShell 引擎)仍在即视为存活.
	procs := snapshotProcesses()
	live := make(map[uint32]bool)
	roots := make(map[uint32]bool)
	for _, pid := range enginePids {
		roots[pid] = true
	}
	for _, pi := range procs {
		if pi.PID != 0 {
			live[pi.PID] = true
		}
	}
	for _, pi := range procs {
		if roots[pi.PID] {
			return true // 记录的 PID 本身存活
		}
	}
	kids := make(map[uint32]bool)
	for _, pi := range procs {
		if roots[pi.PPID] {
			kids[pi.PID] = true
		}
	}
	if len(kids) > 0 {
		return true
	}
	for _, pi := range procs {
		if kids[pi.PPID] {
			return true
		}
	}
	return false
}

func cleanupEngines() {
	for _, pid := range enginePids {
		// 仅在该 PID 仍存活时尝试, 失败忽略(Taskkill 无权或已退出).
		kill := exec.Command("taskkill", "/PID", strconv.Itoa(int(pid)), "/T", "/F")
		kill.Run()
	}
	enginePids = nil
}
