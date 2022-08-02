plugins {
    id("com.diffplug.spotless")
}

spotless {
    format("misc") {
        target("**/*.gradle", "**/*.md", "**/.gitignore")
        trimTrailingWhitespace()
        indentWithSpaces(4)
        endWithNewline()
    }
    cpp {
        target("**/*.CPP")
        licenseHeaderFile("${rootDir}/config/license", "#")
        eclipseCdt() // Use default CDT formatter
        endWithNewline()
    }
    kotlin {
        target("**/*.kt")
        ktlint("0.46.1")
        licenseHeaderFile("${rootDir}/config/license")
        endWithNewline()
    }
    kotlinGradle {
        // same as kotlin, but for .gradle.kts files (defaults to "*.gradle.kts")
        target("*.gradle.kts", "additionalScripts/*.gradle.kts", "buildSrc/*.gradle.kts")
        ktlint("0.46.1")
        endWithNewline()
    }
    format("xml") {
        target("**/*.xml")
        targetExclude("**/build/**/*.xml")
        licenseHeaderFile("${rootDir}/config/license.xml", "(<[^!?])")
    }
}
