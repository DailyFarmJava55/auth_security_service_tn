# Dockerfile

FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

COPY target/dailyFarm_auth_security_service-0.0.1-SNAPSHOT.jar ./app.jar

ENTRYPOINT ["java","-jar","app.jar"]