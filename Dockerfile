FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app
COPY NetSentry/pom.xml .
COPY NetSentry/src ./src
RUN mvn -B clean package -DskipTests

FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /app/target/netsentry.jar app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar", "web"]