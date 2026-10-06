#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# 호스트: 순수 Java collector 빌드(컨테이너 내 javac) + attach 통합 검증.
#   bash collectors/jvm/collector/run.sh
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
IMG="pqcota-test/jvm-collector:latest"
echo "[build] $IMG (javac — no Kotlin, no Gradle)"
docker build -t "$IMG" "$DIR"
echo "[run]"
docker run --rm --label pqcota-test "$IMG"
