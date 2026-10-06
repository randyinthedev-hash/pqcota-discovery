#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 randyinthedev
# SPDX-License-Identifier: Apache-2.0
# 호스트: 정적 바이너리 빌드 + 이미지 빌드 + 격리 실행. `source ~/pqcota-sandbox/env.sh` 선행.
#   bash collectors/openssl/integration/run.sh
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"   # integration → openssl → collectors → repo 루트
IMG="pqcota-test/openssl-collector-it:latest"

echo "[build] static binary (no CGO)"
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$DIR/openssl-collector" ./collectors/openssl/integration/probe )

echo "[build] image $IMG"
docker build -t "$IMG" "$DIR"

echo "[run]"
docker run --rm --label pqcota-test "$IMG"
