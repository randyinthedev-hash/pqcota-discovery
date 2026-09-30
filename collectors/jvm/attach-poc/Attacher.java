import com.sun.tools.attach.VirtualMachine;

/**
 * attach 클라이언트 (jvm-collector). 별도 JVM에서 실행 중 대상 JVM(pid)에 붙어
 * 인트로스펙션 에이전트 JAR를 loadAgent 한다. jdk.attach 모듈 필요(순수 JRE 불가).
 * 전제: 대상과 동일 UID(또는 root), DisableAttachMechanism 아님.
 *
 * 사용: java --add-modules jdk.attach Attacher <pid> <agent.jar> [out파일]
 */
public class Attacher {
    public static void main(String[] args) throws Exception {
        String pid = args[0];
        String agentJar = args[1];
        String out = args.length > 2 ? args[2] : "";
        VirtualMachine vm = VirtualMachine.attach(pid);
        try {
            vm.loadAgent(agentJar, out);
        } finally {
            vm.detach();
        }
        System.out.println("[attacher] attached and injected the agent (pid=" + pid + ")");
    }
}
