FROM --platform=$BUILDPLATFORM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY sdk/java/ sdk/java/
COPY agents/examples/java-spring-ai/ agents/examples/java-spring-ai/
COPY examples/java-tickets/ examples/java-tickets/
# Docker bridge networks may have DNS AAAA records without an IPv6 route.
# This applies only to dependency resolution in the build JVM.
RUN MAVEN_OPTS=-Djava.net.preferIPv4Stack=true mvn --batch-mode --no-transfer-progress -f sdk/java/pom.xml -pl :example-java-tickets -am -Dmaven.test.skip=true package

# Select the supported Ubuntu LTS runtime explicitly instead of inheriting
# unrelated service-manager binaries from the upstream default distro.
FROM eclipse-temurin:21-jre-jammy
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /workspace/examples/java-tickets/target/example-java-tickets-0.3.0.jar /app/agent.jar
COPY --from=build /workspace/examples/java-tickets/target/lib/ /app/lib/
USER 65532:65532
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=70", "-cp", "/app/agent.jar:/app/lib/*", "com.lexagent.examples.tickets.TicketAgent"]
