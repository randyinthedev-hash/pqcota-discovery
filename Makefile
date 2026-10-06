# SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# pqcota-discovery — 디스커버리(collector·CLI·Java 사이드카)의 빌드·테스트
# 전제: go(go.mod의 toolchain 이상). 이 리포는 형제 모듈을 go.mod의 replace로 ../ 에서 읽는다(작업 공간 배치).

.PHONY: all build-jar fmt-check vet build test

all: build-jar fmt-check vet build test

# 전체 빌드 — Go(호스트 + **리눅스 타깃**) + Java 사이드카.
#
# ★ 리눅스 타깃을 따로 빌드하는 이유: collector의 핵심(`/proc`·AF_PACKET·attach)은 `//go:build linux`라
# **macOS에서는 컴파일 대상에서 빠진다.** 호스트 빌드만 하면 Mac 기여자가 그 코드를 깨도 통과한다.
# 교차 컴파일이 공짜(CGO_ENABLED=0)라 늘 함께 확인한다.
build:
	go build ./...
	@echo "→ 리눅스 타깃 교차 확인(리눅스 전용 파일 포함)"
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /dev/null ./... 2>&1 | head -20; \
	 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /dev/null ./... >/dev/null
	@# Windows 타깃도 함께 본다 — CNG collector가 여기서 자란다. 리눅스 전용 코드가
	@# 빌드 태그 밖으로 새면 **Windows에서만** 깨지므로, 그 코드를 쓰기 전에 게이트를 세운다.
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o /dev/null ./... 2>&1 | head -20; \
	 CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o /dev/null ./... >/dev/null
	@echo "✓ Go 빌드(호스트 + linux/amd64 + windows/amd64) 통과"

# Java attach 사이드카 — JDK가 없으면 **건너뛰되 알리지 않고 넘기지 않는다**(§2.6 결).
# 산출물은 build/collector.jar. 데모는 컨테이너 안에서 같은 걸 빌드한다.
#
# ★ 두 번 컴파일하는 이유 — **대상 JVM의 하한이 곧 관측 커버리지**다. 관측 대상 안으로 들어가는 것은
# 에이전트(IntrospectAgent)뿐이고 그것은 Java 8 API만 쓰므로 `--release 8`로 낮춘다. Attacher는
# `com.sun.tools.attach`(JDK 9+ 모듈)를 써서 8로 못 낮추지만, 대상 JVM 안에서 로드되지 않으므로
# 상관없다. 한 번에 컴파일하면 전부 빌드 JDK의 클래스 버전이 되어 **낡은 JVM에서 로드조차 안 된다**
# (실측: JDK 21로 만든 jar은 17·11·8에서 LinkageError).
JVM_COLLECTOR := collectors/jvm/collector
build-jar:
	@if ! command -v javac >/dev/null; then \
	  echo "⚠ javac 없음 — Java 사이드카 빌드 건너뜀(JDK 11+ 필요). collector.jar가 없으면 attach 경로를 쓸 수 없다."; \
	  exit 0; \
	fi; \
	rm -rf build/jvmcls && mkdir -p build/jvmcls && \
	javac --release 8 -nowarn -d build/jvmcls \
	  $(JVM_COLLECTOR)/src/main/java/pqcota/jvm/IntrospectAgent.java && \
	javac --release 11 -nowarn -d build/jvmcls \
	  $(JVM_COLLECTOR)/src/main/java/pqcota/jvm/Attacher.java && \
	jar cfm build/collector.jar $(JVM_COLLECTOR)/manifest.mf -C build/jvmcls . && \
	rm -rf build/jvmcls && \
	echo "✓ Java 사이드카: build/collector.jar"

# gofmt 게이트 — CONTRIBUTING이 gofmt를 규정하는데 검사가 없어 미포맷이 8건까지 쌓인 적이 있다.
# gen/(생성 코드)은 제외. 실패 시 어떤 파일인지 보여준다.
fmt-check:
	@files=$$(gofmt -l $$(git ls-files '*.go' | grep -v '^gen/') 2>/dev/null); \
	if [ -n "$$files" ]; then \
	  echo "✗ gofmt 필요:"; echo "$$files"; echo "  고치기: gofmt -w <파일>"; exit 1; \
	fi; \
	echo "✓ gofmt 통과"

vet:
	go vet ./...

test:
	go test ./...
