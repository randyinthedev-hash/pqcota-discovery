//go:build !windows

package cng

// Enumerate — Windows가 아닌 곳의 거부 스텁.
//
// **표시 없이 빈 결과를 돌려주지 않는다.** 빈 관측과 "CNG가 없다"가 같은 모양이 되면 리눅스에서
// 돌린 결과가 "이 노드엔 CNG provider가 없다"로 읽힌다(§2.6 갭 ≠ 부재).
func Enumerate() (Observation, error) { return Observation{}, ErrNotWindows }
