// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package pqcota.jvm;

import java.io.FileWriter;
import java.lang.instrument.Instrumentation;
import java.security.Provider;
import java.security.Security;
import java.util.Locale;
import java.util.TreeSet;

/**
 * 인트로스펙션 에이전트 (S2). 대상 JVM에 주입되므로 **의존성 없이 JDK 클래스만** 쓴다.
 * 사이드카 전체가 순수 Java(Attacher·IntrospectAgent) — Kotlin·Gradle 없음.
 * 대상 JVM에 남의 런타임(kotlin-stdlib 등)을 끌고 들어가지 않는다.
 *
 * <p>★ 이 클래스만 {@code --release 8}로 컴파일한다 — <b>대상 JVM의 하한이 곧 관측 커버리지</b>이고,
 * 관측 대상은 대개 레거시다. 클래스 파일 버전이 대상보다 높으면 로드 자체가 안 된다. 그래서 여기서는
 * Java 9+ API를 직접 부르지 않는다(아래 provider 버전 읽기 참고).
 */
public final class IntrospectAgent {
    public static void agentmain(String args, Instrumentation inst) {
        StringBuilder sb = new StringBuilder("PQCOTA_PROVIDERS_BEGIN\n");
        int order = 0;
        for (Provider p : Security.getProviders()) {
            sb.append(order++).append('|')
              .append(p.getName()).append('|')
              .append(versionOf(p)).append('|')
              .append(p.getClass().getName()).append('|')
              .append(pqcServices(p)).append('\n');
        }
        sb.append("PQCOTA_PROVIDERS_END\n");
        String out = (args != null && !args.isEmpty()) ? args : "/tmp/pqcota-providers.txt";
        try (FileWriter w = new FileWriter(out)) {
            w.write(sb.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * provider가 서비스하는 표준 PQC 알고리즘 이름(ML-KEM·ML-DSA·SLH-DSA 계열)을 쉼표로 잇는다. 없으면 빈 칸.
     *
     * <p>빈 칸은 「서비스를 봤는데 없었다」이고, 다섯째 칸이 아예 없는 옛 출력은 「보지 않았다」다 — 둘을
     * 가르려고 칸을 늘 쓴다. provider 이름이나 판으로는 알 수 없다: Temurin 21.0.13은 백포트로 둘을 등록하지만
     * provider 판은 21.0.12와 같은 "21"이다(2026-10-30 실측). 보는 것은 등록된 서비스 목록까지다 — 연산이 되는지는
     * 재지 않는다. 여기서는 이름의 모양으로 고르기만 하고, 무엇인지는 코어가 정한다.
     */
    private static String pqcServices(Provider p) {
        TreeSet<String> names = new TreeSet<String>();
        for (Provider.Service s : p.getServices()) {
            String n = s.getAlgorithm().toUpperCase(Locale.ROOT).replace("-", "").replace("_", "");
            if (n.contains("MLKEM") || n.contains("MLDSA") || n.contains("SLHDSA")) {
                names.add(s.getAlgorithm());
            }
        }
        StringBuilder sb = new StringBuilder();
        for (String n : names) {
            if (sb.length() > 0) sb.append(',');
            sb.append(n);
        }
        return sb.toString();
    }

    /**
     * provider 버전 문자열. {@code getVersionStr()}는 Java 9+에만 있어 리플렉션으로 먼저 찾고,
     * 없으면 Java 8의 {@code getVersion()}(double)로 떨어진다 — 낡은 대상에서도 로드되게.
     */
    private static String versionOf(Provider p) {
        try {
            Object v = Provider.class.getMethod("getVersionStr").invoke(p);
            if (v != null) return v.toString();
        } catch (Throwable ignored) {
            // Java 8 — 아래로.
        }
        return String.valueOf(p.getVersion());
    }
}
