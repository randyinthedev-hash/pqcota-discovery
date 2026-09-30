# jvm-collector attach PoC (S2). 격리 실행 — teardown이 라벨로 정리.
FROM eclipse-temurin:21-jdk
WORKDIR /poc
# BouncyCastle provider — 동적 등록 테스트용.
ADD https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.79/bcprov-jdk18on-1.79.jar /poc/bcprov.jar
COPY ProviderApp.java IntrospectAgent.java Attacher.java manifest.mf run-inside.sh /poc/
RUN javac -cp /poc/bcprov.jar ProviderApp.java \
 && javac IntrospectAgent.java \
 && jar cfm agent.jar manifest.mf IntrospectAgent.class \
 && javac Attacher.java
CMD ["bash", "/poc/run-inside.sh"]
