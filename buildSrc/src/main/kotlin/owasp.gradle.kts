plugins {
    id("org.owasp.dependencycheck")
}

dependencyCheck {
    failOnError = true
    failBuildOnCVSS = 0F
    scanConfigurations = listOf(
        "api",
        "archives",
        "compile",
        "implementation",
        "releaseCompileClasspath",
        "releaseRuntimeClasspath",
        "androidTest",
        "runtimeOnly",
        "testImplementation"
    )
    suppressionFile = File("${rootDir}/config/owasp-suppression.xml").toString()
}
