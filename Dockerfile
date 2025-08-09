FROM maven:3.9.10-eclipse-temurin-21-alpine

# Install curl for health check
# RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN mvn clean package -DskipTests

EXPOSE 8080

# HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
#     CMD curl --fail http://localhost:8080/health || exit 1

ENTRYPOINT ["java","-jar","target/auth-micro-0.0.1-SNAPSHOT.jar"]
