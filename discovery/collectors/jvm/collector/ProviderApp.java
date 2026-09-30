import java.security.Provider;
import java.security.Security;

/** 테스트 대상 JVM. BouncyCastle을 런타임 동적 등록(정적 스캔 불가)한 뒤 대기. */
public class ProviderApp {
    public static void main(String[] args) throws Exception {
        try {
            Class<?> bc = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            Security.addProvider((Provider) bc.getDeclaredConstructor().newInstance());
            System.out.println("[app] BouncyCastle registered dynamically");
        } catch (Throwable t) {
            System.out.println("[app] no BC — default providers only");
        }
        System.out.println("[app] running pid=" + ProcessHandle.current().pid());
        Thread.sleep(Long.MAX_VALUE);
    }
}
