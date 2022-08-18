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
    maven(url= "https://oss.sonatype.org/content/repositories/snapshots/")
}

dependencies {
    implementation("com.diffplug.spotless:spotless-plugin-gradle:6.8.0")
    implementation("org.owasp:dependency-check-gradle:7.1.1")
}
