//go:build windows

package jvm

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ScanJVMs — Windows에서 실행 중인 JVM을 열거한다(리눅스 `/proc` 정찰과 대칭).
//
// **외부 도구를 부르지 않는다** — WMI도 PowerShell도 tasklist도 아니고 Toolhelp32다.
// cng-collector와 같은 이유다(§2.3): 스크립트 실행이 정책으로 막힌 서버에서 관측 실패가
// 환경 탓으로 흩어지면 무엇을 못 봤는지조차 불분명해진다.
//
// **남의 프로세스 메모리를 읽지 않는다.** 그래서 명령줄(=앱 이름)이 비고, 그 사실은
// [JVMScanStats.CmdlineUnavailable]로 남는다. 리눅스는 `/proc/<pid>/cmdline`이 파일이라
// 그냥 읽지만 Windows는 PEB를 들여다봐야 한다 — 관측하자고 넘을 선이 아니다.
func ScanJVMs() ([]JVMProc, JVMScanStats) {
	st := JVMScanStats{CmdlineUnavailable: true}

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		st.ProcUnavailable = true // 프로세스 목록을 못 얻었다 — "JVM 0개"가 아니다(§2.6)
		return nil, st
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		st.ProcUnavailable = true
		return nil, st
	}

	var out []JVMProc
	for {
		if pid := int(pe.ProcessID); pid > 0 {
			if p, ok := inspectProcess(pid, &st); ok {
				out = append(out, p)
			}
		}
		if err := windows.Process32Next(snap, &pe); err != nil {
			break // ERROR_NO_MORE_FILES — 끝
		}
	}
	return out, st
}

// inspectProcess — 프로세스 하나가 JVM인지 보고, 맞으면 정찰 결과를 만든다.
func inspectProcess(pid int, st *JVMScanStats) (JVMProc, bool) {
	exe, err := imagePath(pid)
	if err != nil {
		st.Denied++ // 열지 못했다(권한·종료) — 갭이지 부재가 아니다
		return JVMProc{}, false
	}
	st.Accessible++

	// java.exe면 그것으로 끝. 아니면 모듈 목록에서 jvm.dll을 찾는다 — 네이티브 런처가
	// JVM을 포함해 도는 경우(리눅스의 libjvm.so 판별과 같은 자리)를 놓치지 않기 위해서다.
	jvmDLL := ""
	if !isJavaExeWindows(exe) {
		if jvmDLL = findJVMDLL(pid); jvmDLL == "" {
			return JVMProc{}, false
		}
	}
	st.WithJVM++

	home := deriveJavaHomeWindows(exe, jvmDLL)
	return JVMProc{
		PID:      pid,
		Exe:      exe,
		App:      "", // 명령줄을 안 읽는다 — CmdlineUnavailable이 그 사실을 진다
		JavaHome: home,
		JavaBin:  javaBinForWindows(home, exe),
		Version:  readReleaseVersion(home),

		ViaLibjvm:     jvmDLL != "",
		AttachCapable: attachCapableAt(home, AttachLibRelWindows, fileExists),
	}, true
}

// imagePath — 프로세스의 실행 파일 전체 경로. QUERY_LIMITED_INFORMATION만 요구한다 —
// 경로를 알자고 메모리를 읽을 권한까지 받지 않는다.
func imagePath(pid int) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// findJVMDLL — 그 프로세스가 로드한 jvm.dll 경로(없거나 못 보면 ""). 못 본 것을 없는 것으로
// 적지 않기 위해, 이 자리에서 실패하면 그 프로세스는 **JVM이 아닌 것이 아니라 판별 못 한 것**이다
// — 리눅스가 maps를 못 읽을 때와 같은 취급이다.
func findJVMDLL(pid int) string {
	snap, err := windows.CreateToolhelp32Snapshot(
		windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, uint32(pid))
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(snap)

	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))
	if err := windows.Module32First(snap, &me); err != nil {
		return ""
	}
	for {
		p := windows.UTF16ToString(me.ExePath[:])
		if parts := winParts(p); strings.EqualFold(parts[len(parts)-1], "jvm.dll") {
			return p
		}
		if err := windows.Module32Next(snap, &me); err != nil {
			return ""
		}
	}
}
