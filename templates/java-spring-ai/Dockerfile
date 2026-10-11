# syntax=docker/dockerfile:1
# The release pipeline pins the base images by digest before publishing.
FROM maven:3.9.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY pom.xml ./
COPY platform_entry ./platform_entry
RUN mvn --batch-mode --no-transfer-progress -DskipTests package

FROM eclipse-temurin:17-jre
RUN useradd --system --uid 10001 --create-home agent
USER 10001:10001
WORKDIR /app
COPY --from=build /src/target/agent-0.1.0.jar /app/agent.jar
# The SDK ExecutionServer serves /health/ready and the five execution entries.
# / SDK ExecutionServer 提供 /health/ready 与五个执行入口。
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/agent.jar"]
