# docker/Dockerfile.java — Java Compiler Microservice Container
# ==============================================================
# Multi-stage build:
#   Stage 1 (builder): uses Maven + JDK to compile the fat JAR
#   Stage 2 (runtime): uses JDK (not JRE) since we need javac at runtime
#
# Note: We need a JDK image (not JRE) at runtime because the service
# uses javax.tools.JavaCompiler to compile user-submitted code snippets.
# The javac binary and the tools.jar are only present in JDK images.
#
# Build (from project root):
#   docker build -f docker/Dockerfile.java -t codelens-java .
#
# Run standalone:
#   docker run -p 9090:9090 codelens-java

# ── Stage 1: Build with Maven ─────────────────────────────────────────────────
FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /build

# Copy pom.xml first — caches Maven dependencies across builds
COPY java_service/pom.xml .
RUN mvn dependency:go-offline -q

# Copy source and build the fat JAR
COPY java_service/src ./src
RUN mvn clean package -DskipTests -q

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# Must be JDK (not JRE) — we need javac to compile user-submitted snippets
FROM eclipse-temurin:17-jdk-jammy AS runtime

LABEL maintainer="Capstone Team"
LABEL description="CodeLens — Java Code Compiler Microservice"
LABEL version="1.0"

# Install curl for health checks
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --gid 1001 appgroup && \
    useradd  --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser

WORKDIR /app

# Copy the fat JAR from the builder stage
COPY --from=builder /build/target/code-review-service-1.0.jar app.jar
RUN chown appuser:appgroup app.jar

USER appuser

# Temp directory for compilation (JAR writes here; must be writable by appuser)
RUN mkdir -p /tmp/codelens-compile

ENV JAVA_SERVICE_PORT=9090
ENV JAVA_OPTS="-Xmx256m -Xms64m -XX:+UseContainerSupport"

EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:${PORT:-9090}/health || exit 1

# $PORT takes precedence (Render assigns a dynamic port); falls back to
# JAVA_SERVICE_PORT for Docker Compose and plain `docker run`.
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar ${PORT:-$JAVA_SERVICE_PORT}"]
