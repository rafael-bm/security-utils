plugins {
    java
    idea
    id("io.freefair.lombok") version "5.0.0-rc6"
}

group = "uk.co.mulecode"
version = "1.0.0-SNAPSHOT"

repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    annotationProcessor("org.projectlombok:lombok:1.18.10")
    testAnnotationProcessor("org.projectlombok:lombok:1.18.10")

    implementation("commons-io:commons-io:2.6")
    implementation("org.bouncycastle:bcpg-jdk15on:1.64")

    testImplementation("org.assertj:assertj-core:3.15.0")
    testImplementation("junit:junit:4.12")
}

tasks.wrapper {
    gradleVersion = "6.2.2"
    distributionType = Wrapper.DistributionType.ALL
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}
