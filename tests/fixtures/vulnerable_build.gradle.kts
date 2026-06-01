plugins {
    java
}

group = "com.example"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    // GHSA-jjjh-jjxp-wpff / CVE-2022-42003: affected < 2.13.4.2
    implementation("com.fasterxml.jackson.core:jackson-databind:2.13.0")
    implementation("org.slf4j:slf4j-api:1.7.36")
    testImplementation("junit:junit:4.13.2")
}
