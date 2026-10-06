// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import "os"

const elevateAs = "root"

func privileged() bool { return os.Geteuid() == 0 }
