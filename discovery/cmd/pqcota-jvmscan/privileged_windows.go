//go:build windows

package main

import "golang.org/x/sys/windows"

// elevateAs — 시야를 넓히려면 무엇으로 돌려야 하는가.
const elevateAs = "an Administrator"

// privileged — 이미 상승된 토큰으로 돌고 있나. 이미 관리자인데 "관리자로 돌리세요"라고
// 하면 안내가 아니라 잡음이다 — 못 연 프로세스가 남아도 그것은 더 올릴 데가 없는 바닥값이다.
func privileged() bool { return windows.GetCurrentProcessToken().IsElevated() }
