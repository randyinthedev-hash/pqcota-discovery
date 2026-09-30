#!/usr/bin/env bash
# 호스트에서 실행: PoC 이미지 빌드 + 격리 실행 (pqcota-test 라벨).
#   bash collectors/jvm/attach-poc/run.sh
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
IMG="pqcota-test/jvm-attach-poc:latest"
echo "[build] $IMG"
docker build -t "$IMG" "$DIR"
echo "[run]"
docker run --rm --label pqcota-test "$IMG"
