# jvm-collector (순수 Java) 빌드 + attach 통합 검증. Kotlin·Gradle 불필요 — javac + jar.
FROM eclipse-temurin:21-jdk
WORKDIR /poc
ADD https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.79/bcprov-jdk18on-1.79.jar /poc/bcprov.jar
# 사이드카 소스(Attacher·StaticFallback·IntrospectAgent) → collector.jar (Agent-Class 매니페스트 포함).
COPY src/main/java /poc/src
COPY manifest.mf ProviderApp.java run-inside.sh /poc/
RUN javac -d /poc/classes $(find /poc/src -name '*.java') \
 && jar cfm /poc/collector.jar /poc/manifest.mf -C /poc/classes . \
 && javac -cp /poc/bcprov.jar ProviderApp.java
CMD ["bash", "/poc/run-inside.sh"]
