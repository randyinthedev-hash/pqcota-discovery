import java.io.FileWriter;
import java.lang.instrument.Instrumentation;
import java.security.Provider;
import java.security.Security;

/**
 * 인트로스펙션 에이전트 (jvm-collector 핵심). attach로 대상 JVM에 주입되어
 * agentmain 안에서 Security.getProviders() **실체**를 조회하고 결과를 파일로 반환한다.
 * 등록 순서 보존(§1.2 우선순위 협상 판정 근거).
 */
public class IntrospectAgent {
    public static void agentmain(String args, Instrumentation inst) {
        StringBuilder sb = new StringBuilder("PQCOTA_PROVIDERS_BEGIN\n");
        int order = 0;
        for (Provider p : Security.getProviders()) {
            sb.append(order++).append('|')
              .append(p.getName()).append('|')
              .append(p.getVersionStr()).append('|')
              .append(p.getClass().getName()).append('\n');
        }
        sb.append("PQCOTA_PROVIDERS_END\n");
        String out = args != null && !args.isEmpty() ? args : "/tmp/pqcota-providers.txt";
        try (FileWriter w = new FileWriter(out)) {
            w.write(sb.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
