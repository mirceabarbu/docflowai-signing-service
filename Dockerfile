FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /app
# CACHE BUST: b239 — forteaza rebuild complet
LABEL build.version="b244" build.date="2026-03-31"
COPY pom.xml .
COPY src ./src
RUN mvn -q -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR /app
LABEL build.version="b244"
COPY --from=build /app/target/docflowai-sts-pades-service-0.0.6.jar /app/app.jar
ENV PORT=8085
EXPOSE 8085
ENTRYPOINT ["sh", "-c", "java -Dserver.port=${PORT} -jar /app/app.jar"]
