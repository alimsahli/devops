# ===== Stage 1: Build the application =====
FROM maven:3.9.6-eclipse-temurin-17 AS builder

# Set working directory inside the container
WORKDIR /app

# Copy the pom.xml and download dependencies first (for better caching)
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy the rest of the source code
COPY src ./src

# Build the application (skip tests for faster builds)
RUN mvn clean package -DskipTests

# ===== Stage 2: Create the runtime image =====
FROM eclipse-temurin:17-jdk-jammy

# Set working directory
WORKDIR /app

# Copy the jar file from the builder stage
COPY --from=builder /app/target/*.jar app.jar

# Expose the application port (change if needed)
EXPOSE 8080

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]
