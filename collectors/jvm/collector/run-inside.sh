#!/usr/bin/env bash
# 컨테이너 내부: (1) attach 성공 경로, (2) attach 차단 시 정적 폴백 경로 검증.
set -e
cd /poc
RC=0

echo "########## Phase 1: attach succeeds (S2) ##########"
java -cp .:bcprov.jar ProviderApp &
P1=$!
sleep 2
echo "[test] target pid=$P1"
java --add-modules jdk.attach -cp collector.jar pqcota.jvm.Attacher "$P1" /poc/collector.jar /tmp/p1.txt
sleep 1
cat /tmp/p1.txt
if grep -q '|BC|' /tmp/p1.txt; then
  echo "PASS: attach captured the dynamic BouncyCastle (confirmed)"
else
  echo "FAIL: BC not captured"; RC=1
fi
kill "$P1" 2>/dev/null || true

echo
echo "########## Phase 2: attach blocked → static fallback (TD-JVM-4) ##########"
# DisableAttachMechanism: 대상은 BC를 동적 등록하지만 attach가 차단됨.
java -XX:+DisableAttachMechanism -cp .:bcprov.jar ProviderApp &
P2=$!
sleep 2
echo "[test] target pid=$P2 (DisableAttachMechanism)"
java --add-modules jdk.attach -cp collector.jar pqcota.jvm.Attacher "$P2" /poc/collector.jar /tmp/p2.txt || true
sleep 1
cat /tmp/p2.txt
echo "--- assertion (TD-JVM-4: honest degradation) ---"
if grep -q 'gap=runtime-introspection' /tmp/p2.txt \
   && grep -q 'evidence_strength=inferred' /tmp/p2.txt \
   && ! grep -q '|BC|' /tmp/p2.txt; then
  echo "PASS: with attach blocked it falls back to static — static providers only, the dynamic BC stated as a gap (never mistaken for absence)"
else
  echo "FAIL: the degradation path is wrong"; RC=1
fi
kill "$P2" 2>/dev/null || true

exit $RC
