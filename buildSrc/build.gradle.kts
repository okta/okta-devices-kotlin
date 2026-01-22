plugins {
    `kotlin-dsl`
    `java-gradle-plugin`
    `kotlin-dsl-precompiled-script-plugins`
}

repositories {
    // The org.jetbrains.kotlin.jvm plugin requires a repository
    // where to download the Kotlin compiler dependencies from.
    google()
    gradlePluginPortal()
    mavenCentral()
}

dependencies {
    //noinspection UseTomlInstead
    implementation("com.diffplug.spotless:spotless-plugin-gradle:8.1.0")
    implementation("org.owasp:dependency-check-gradle:12.2.0")
}
