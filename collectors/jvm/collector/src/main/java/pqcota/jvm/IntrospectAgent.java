package pqcota.jvm;

import java.io.FileWriter;
import java.lang.instrument.Instrumentation;
import java.security.Provider;
import java.security.Security;

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
              .append(p.getClass().getName()).append('\n');
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
