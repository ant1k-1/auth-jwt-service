# build stage
FROM gradle:8.7 AS builder
WORKDIR /usr/app/
COPY . .
RUN gradle build -x test

# package build
FROM openjdk:17
ENV JAR_NAME=auth-0.0.1-SNAPSHOT.jar
ENV APP_HOME=/usr/app/
# should be env file here
WORKDIR $APP_HOME
COPY --from=builder $APP_HOME .
EXPOSE 8081
ENTRYPOINT exec java -jar $APP_HOME/build/libs/$JAR_NAME