//go:build !windows

package main

import "os"

const elevateAs = "root"

func privileged() bool { return os.Geteuid() == 0 }
