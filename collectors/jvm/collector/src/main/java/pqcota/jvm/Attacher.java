package pqcota.jvm;

import com.sun.tools.attach.VirtualMachine;

/**
 * attach 클라이언트 (jvm-collector). 실행 중 대상 JVM(pid)에 붙어 에이전트 JAR를 loadAgent.
 * jdk.attach 모듈 필요. 전제: 동일 UID(또는 root), attach 미차단(JEP 451 대응은 설계 §2.2).
 *
 * 사용: java --add-modules jdk.attach -cp collector.jar pqcota.jvm.Attacher &lt;pid&gt; &lt;agent.jar&gt; [out]
 *
 * 순수 Java — 이 사이드카에 Kotlin·Gradle이 필요 없다. 불가피한 제약은 "JVM 안에서 실행"뿐이고
 * 플랫폼 자신의 언어(Java)로 충분하다. 빌드는 javac + jar(run.sh).
 */
public final class Attacher {
    public static void main(String[] args) {
        String pid = args[0];
        String agentJar = args[1];
        String out = args.length > 2 ? args[2] : "/tmp/pqcota-providers.txt";
        try {
            VirtualMachine vm = VirtualMachine.attach(pid);
            try {
                vm.loadAgent(agentJar, out);
            } finally {
                vm.detach();
            }
            System.out.println("[attacher] attach succeeded → the real getProviders() (confirmed)");
        } catch (Exception e) {
            // JEP 451 / DisableAttachMechanism / 권한 → **여기서 끝낸다.**
            //
            // 예전에는 이 자리에서 `System.getProperty("java.home")`으로 java.security를 읽어
            // 결과를 냈다. 그 java.home은 **대상이 아니라 이 클라이언트의 것**이다 — 대상이
            // 자기 JDK가 아닐 때(순수 JRE·런처 심) 남의 provider 목록이 그 자산에 붙는다.
            // 강등 표시가 함께 붙어도 값이 틀린 것은 그대로다. 빈 결과보다 나쁘다.
            // 실측(Windows 11): javapath 런처 심에 클라이언트 JDK의 provider 13개가 달렸다.
            //
            // 정적 폴백은 Go 쪽(StaticFallbackGo)이 **대상의** JAVA_HOME으로 하고, 모르면
            // 갭을 낸다. 실패를 실패로 돌려줘야 그 경로로 넘어간다.
            System.err.println("[attacher] attach unavailable (" + e.getClass().getSimpleName()
                    + "): " + e.getMessage());
            System.exit(2);
        }
    }

    private Attacher() {}
}
