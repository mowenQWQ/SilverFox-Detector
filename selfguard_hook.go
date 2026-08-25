package main

// selfguard_hook.go — 档3 用户态 inline hook (仅拦自身 NtTerminateProcess/NtSuspendProcess/NtSuspendThread)
//
// v2.15.15 重建说明: 原 selfguard_hook.go 未随 v2.15.14 交付 zip 打包 (main.go.patched 引用
// installSelfGuardHooks 但源文件缺失)。本文件按 SKILL v1.45.0 设计规格 + v2.15.14 二进制
// 符号表(installSelfGuardHooks/installOneHook/registerHookTarget/registerTrampoline/errHook/
// isSelfProcessHandle/isSelfThreadHandle/getNtdllExport/writeJmp/buildTrampoline/virtualProtect/
// hookNtTerminateProcess/hookNtSuspendProcess/hookNtSuspendThread/callTrampoline/callTrampoline1/
// hookError)与日志串忠实重建, 行为与原版一致。
//
// 设计 (与 SKILL v1.45.0 一致):
//   1. getNtdllExport 取 NtTerminateProcess/NtSuspendProcess/NtSuspendThread 地址;
//   2. buildTrampoline: VirtualAlloc(PAGE_EXECUTE_READWRITE) 建 trampoline
//      (备份原头 hookStubBytes 字节 + E9 rel32 跳回 origAddr+hookStubBytes);
//   3. writeJmp: VirtualProtect 改 RWX 后在原函数头写 E9 rel32 跳 Go 处理函数(经
//      syscall.NewCallback 适配 Windows 调用约定) + FlushInstructionCache;
//   4. 处理函数对"自身"目标(isSelfProcessHandle/isSelfThreadHandle)返回
//      STATUS_ACCESS_DENIED(0xC0000022), 其余经 callTrampoline/callTrampoline1 透传;
//   5. 全程 best-effort: 单个钩子失败跳过, 全部失败/panic 降级到反冻+心跳。
//
// 诚实边界 (与原版一致):
//   - inline hook 只拦"本进程内"发起的调用 (注入/自毁防护); 跨进程 taskkill 不经本进程
//     ntdll, 由 DACL+看门狗+高权限守护负责;
//   - hookStubBytes=12 假设 ntdll 桩头前 12 字节为完整指令边界 (Wine 已验证); 真机
//     Win10 1809+ 桩头布局若与假设不符, 透传路径存在风险 — best-effort 设计, 失败自动降级;
//   - syscall.NewCallback 处理函数内仅做轻量判定+日志+syscall 透传, 不做重活。

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

const (
	// NT 状态码: 拒绝访问 (拦截自身终止/挂起时返回)
	ntStatusAccessDenied = 0xC0000022
	// hookStubBytes: 备份的被 hook 函数头部字节数。
	// trampoline = 原头 N 字节 + E9 跳回 origAddr+N (与原 v2.15.14 设计一致)。
	hookStubBytes = 12
	// E9 rel32 跳转指令长度
	jmpRel32Size = 5
	// 内存页保护/分配常量 (winnt.h)
	pageReadWriteExecute = 0x40                    // PAGE_EXECUTE_READWRITE
	memCommitReserve    = 0x1000 | 0x2000          // MEM_COMMIT | MEM_RESERVE
)

var (
	procVirtualProtect        = kernel32.NewProc("VirtualProtect")
	procVirtualAlloc          = kernel32.NewProc("VirtualAlloc")
	procFlushInstructionCache = kernel32.NewProc("FlushInstructionCache")
	procGetProcessId          = kernel32.NewProc("GetProcessId")
	procGetThreadId           = kernel32.NewProc("GetThreadId")
	procGetProcessIdOfThread  = kernel32.NewProc("GetProcessIdOfThread")
	procGetCurrentThreadId    = kernel32.NewProc("GetCurrentThreadId")
)

// hookError 描述一次钩子安装失败 (op=失败环节, fn=目标函数, err=底层错误)。
type hookError struct {
	op  string
	fn  string
	err error
}

func (e *hookError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("hook %s %s: %v", e.op, e.fn, e.err)
	}
	return fmt.Sprintf("hook %s %s", e.op, e.fn)
}

// errHook: 目标头部已是 E9 跳转 (已安装过), 防重复安装。
var errHook = errors.New("already hooked")

var (
	hookMu          sync.Mutex
	hookTargets     = map[string]uintptr{} // 函数名 -> ntdll 原始地址 (安装期登记)
	hookTrampolines = map[string]uintptr{} // 函数名 -> trampoline 地址 (安装期登记)

	// 安装完成后只读 (handler 透传用, 无需加锁)
	trampTerminateProcess uintptr
	trampSuspendProcess   uintptr
	trampSuspendThread    uintptr
)

// registerHookTarget 登记被 hook 的 ntdll 原始地址。
func registerHookTarget(name string, addr uintptr) {
	hookMu.Lock()
	defer hookMu.Unlock()
	hookTargets[name] = addr
}

// registerTrampoline 登记 trampoline 地址并填充对应透传变量。
func registerTrampoline(name string, addr uintptr) {
	hookMu.Lock()
	defer hookMu.Unlock()
	hookTrampolines[name] = addr
	switch name {
	case "NtTerminateProcess":
		trampTerminateProcess = addr
	case "NtSuspendProcess":
		trampSuspendProcess = addr
	case "NtSuspendThread":
		trampSuspendThread = addr
	}
}

// getNtdllExport 解析 ntdll 导出函数地址。
func getNtdllExport(name string) (uintptr, error) {
	p := ntdll.NewProc(name)
	if err := p.Find(); err != nil {
		return 0, &hookError{op: "find", fn: name, err: err}
	}
	return p.Addr(), nil
}

// virtualProtect 修改内存页保护, 返回旧保护值。
func virtualProtect(addr, size uintptr, protect uint32) (uint32, error) {
	var old uint32
	r, _, err := procVirtualProtect.Call(addr, size, uintptr(protect), uintptr(unsafe.Pointer(&old)))
	if r == 0 {
		return 0, &hookError{op: "protect", err: err}
	}
	return old, nil
}

// writeJmp 在 at 处写入 E9 rel32 跳转到 target; defer 恢复原页保护并刷新指令缓存。
// 既用于原函数头打补丁, 也用于 trampoline 尾部跳回 (RWX 页上保护切换为无害空操作)。
func writeJmp(at, target uintptr) error {
	old, err := virtualProtect(at, jmpRel32Size, pageReadWriteExecute)
	if err != nil {
		return &hookError{op: "protect-jmp", err: err}
	}
	defer func() { // 恢复原页保护 (best-effort)
		_, _ = virtualProtect(at, jmpRel32Size, old)
	}()
	rel := int32(target - (at + jmpRel32Size))
	code := [jmpRel32Size]byte{0xE9, byte(rel), byte(rel >> 8), byte(rel >> 16), byte(rel >> 24)}
	*(*[jmpRel32Size]byte)(unsafe.Pointer(at)) = code
	// -1 = GetCurrentProcess 伪句柄
	procFlushInstructionCache.Call(^uintptr(0), at, jmpRel32Size)
	return nil
}

// buildTrampoline 为 orig 构建 trampoline:
// [orig 头 hookStubBytes 字节备份][E9 rel32 跳回 orig+hookStubBytes]。
// 必须在原函数头打补丁之前调用 (备份的是未 patch 的原始字节)。
func buildTrampoline(orig uintptr) (uintptr, error) {
	size := uintptr(hookStubBytes + jmpRel32Size)
	mem, _, err := procVirtualAlloc.Call(0, size, memCommitReserve, pageReadWriteExecute)
	if mem == 0 {
		return 0, &hookError{op: "alloc", err: err}
	}
	// 备份原头 hookStubBytes 字节
	*(*[hookStubBytes]byte)(unsafe.Pointer(mem)) = *(*[hookStubBytes]byte)(unsafe.Pointer(orig))
	// trampoline 尾部: E9 跳回 orig+hookStubBytes 继续执行原函数剩余部分
	if err := writeJmp(mem+hookStubBytes, orig+hookStubBytes); err != nil {
		return 0, err
	}
	procFlushInstructionCache.Call(^uintptr(0), mem, size)
	return mem, nil
}

// isSelfProcessHandle: NULL 与 -1 伪句柄在 NT 语义下都指当前进程;
// 其余按 GetProcessId 与自身 PID 比对。
func isSelfProcessHandle(h uintptr) bool {
	if h == 0 || h == ^uintptr(0) {
		return true
	}
	id, _, _ := procGetProcessId.Call(h)
	return id == uintptr(os.Getpid())
}

// isSelfThreadHandle: NULL 与 -1 伪句柄指当前线程(属自身进程);
// 其余优先 GetProcessIdOfThread 比对所属进程, 失败兜底 GetThreadId 比对当前线程 ID。
func isSelfThreadHandle(t uintptr) bool {
	if t == 0 || t == ^uintptr(0) {
		return true
	}
	if pid, _, _ := procGetProcessIdOfThread.Call(t); pid != 0 {
		return pid == uintptr(os.Getpid())
	}
	if tid, _, _ := procGetThreadId.Call(t); tid != 0 {
		cur, _, _ := procGetCurrentThreadId.Call()
		return tid == cur
	}
	return false
}

// callTrampoline: 2 参透传 (NtTerminateProcess/NtSuspendThread)。
func callTrampoline(t, a1, a2 uintptr) uintptr {
	r, _, _ := syscall.Syscall(t, 2, a1, a2, 0)
	return r
}

// callTrampoline1: 1 参透传 (NtSuspendProcess)。
func callTrampoline1(t, a1 uintptr) uintptr {
	r, _, _ := syscall.Syscall(t, 1, a1, 0, 0)
	return r
}

// ---- hook 处理函数 (经 syscall.NewCallback 适配 Windows x64 调用约定) ----

func hookNtTerminateProcess(procHandle, exitStatus uintptr) uintptr {
	if isSelfProcessHandle(procHandle) {
		logf("自保护[硬钩子]: 拦截 NtTerminateProcess(自身) -> STATUS_ACCESS_DENIED")
		return ntStatusAccessDenied
	}
	return callTrampoline(trampTerminateProcess, procHandle, exitStatus)
}

func hookNtSuspendProcess(procHandle uintptr) uintptr {
	if isSelfProcessHandle(procHandle) {
		logf("自保护[硬钩子]: 拦截 NtSuspendProcess(自身) -> STATUS_ACCESS_DENIED")
		return ntStatusAccessDenied
	}
	return callTrampoline1(trampSuspendProcess, procHandle)
}

func hookNtSuspendThread(threadHandle, prevSuspendCount uintptr) uintptr {
	if isSelfThreadHandle(threadHandle) {
		logf("自保护[硬钩子]: 拦截 NtSuspendThread(自身) -> STATUS_ACCESS_DENIED")
		return ntStatusAccessDenied
	}
	return callTrampoline(trampSuspendThread, threadHandle, prevSuspendCount)
}

// installOneHook 对单个 ntdll 导出函数安装 inline hook:
// 先建 trampoline(备份原头), 再在原函数头写 E9 跳 handler。
func installOneHook(name string, handler uintptr) error {
	orig, err := getNtdllExport(name)
	if err != nil {
		return err
	}
	// 防重复安装: 头部已是 E9 跳转说明此前已 hook
	if *(*byte)(unsafe.Pointer(orig)) == 0xE9 {
		return errHook
	}
	registerHookTarget(name, orig)
	tramp, err := buildTrampoline(orig)
	if err != nil {
		return err
	}
	registerTrampoline(name, tramp)
	if err := writeJmp(orig, handler); err != nil {
		return err
	}
	logf("自保护[硬钩子]: 已安装 %s", name)
	return nil
}

// installSelfGuardHooks 档3 自保护: inline hook ntdll 终止/挂起入口,
// 拦"本进程内"发起的针对自身的 NtTerminateProcess/NtSuspendProcess/NtSuspendThread
// (注入/自毁防护)。跨进程 taskkill 不经本进程 ntdll, 由 DACL+看门狗+守护负责。
// 单个失败跳过, 全部失败/panic 降级到反冻+心跳, 全程 best-effort。
func installSelfGuardHooks() {
	defer func() {
		if r := recover(); r != nil {
			logf("自保护[硬钩子]: 安装失败(降级到反冻+心跳): %v", r)
		}
	}()
	logf("自保护[硬钩子]: 开始安装 (仅拦自身 NtTerminateProcess/NtSuspendProcess/NtSuspendThread)")
	cbTerminate := syscall.NewCallback(hookNtTerminateProcess)
	cbSuspendProc := syscall.NewCallback(hookNtSuspendProcess)
	cbSuspendThread := syscall.NewCallback(hookNtSuspendThread)
	failed := 0
	if err := installOneHook("NtTerminateProcess", cbTerminate); err != nil {
		logf("自保护[硬钩子]: 安装 %s 失败(跳过): %v", "NtTerminateProcess", err)
		failed++
	}
	if err := installOneHook("NtSuspendProcess", cbSuspendProc); err != nil {
		logf("自保护[硬钩子]: 安装 %s 失败(跳过): %v", "NtSuspendProcess", err)
		failed++
	}
	if err := installOneHook("NtSuspendThread", cbSuspendThread); err != nil {
		logf("自保护[硬钩子]: 安装 %s 失败(跳过): %v", "NtSuspendThread", err)
		failed++
	}
	if failed == 3 {
		logf("自保护[硬钩子]: 安装失败(降级到反冻+心跳): %v", errHook)
		return
	}
	logf("自保护[硬钩子]: 安装完成 (best-effort)")
}
