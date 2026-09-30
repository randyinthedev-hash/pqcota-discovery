#!/usr/bin/env bash
# 컨테이너 내부: libssl 로드한 장수 프로세스 기동 → collector가 /proc·ELF로 탐지 → 검증.
set -e

python3 -c "import ssl, time; print('[app] ssl loaded:', ssl.OPENSSL_VERSION); time.sleep(999)" &
PID=$!
sleep 2
echo "[test] target pid=$PID (python3 + libssl)"

echo "=== openssl-collector output ==="
OUT=$(/usr/local/bin/openssl-collector "$PID")
echo "$OUT"

echo "=== assertion (SD-1 + SD-3, on real software) ==="
if echo "$OUT" | grep -q "lib=libssl" && echo "$OUT" | grep -q "fork=OpenSSL"; then
  echo "PASS: detected libssl loaded by a running process, and identified fork=OpenSSL from ELF strings"
  RC=0
else
  echo "FAIL: detection or identification failed"
  RC=1
fi
kill "$PID" 2>/dev/null || true
exit $RC
