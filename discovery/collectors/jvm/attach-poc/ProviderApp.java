import java.security.Provider;
import java.security.Security;

/**
 * 테스트 대상 JVM (S2). BouncyCastle을 **런타임에 동적 등록**한 뒤 대기한다.
 * 동적 등록(addProvider)은 java.security 파일·정적 스캔으로는 보이지 않으므로(§1.2),
 * attach로만 잡아야 하는 "실체"의 대표 케이스다.
 */
public class ProviderApp {
    public static void main(String[] args) throws Exception {
        try {
            Class<?> bc = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            Security.addProvider((Provider) bc.getDeclaredConstructor().newInstance());
            System.out.println("[app] BouncyCastle registered dynamically (invisible to a static scan)");
        } catch (Throwable t) {
            System.out.println("[app] BC not on the classpath — default providers only");
        }
        System.out.println("[app] running pid=" + ProcessHandle.current().pid());
        Thread.sleep(Long.MAX_VALUE);
    }
}
