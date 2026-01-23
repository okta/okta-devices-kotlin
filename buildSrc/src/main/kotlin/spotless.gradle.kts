plugins {
    id("com.diffplug.spotless")
}

spotless {
    format("misc") {
        target("**/*.gradle", "**/*.md", "**/.gitignore")
        trimTrailingWhitespace()
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
        // Disable the naming rules for composable functions.
        ktlint("1.5.0").editorConfigOverride(mapOf("disabled_rules" to "standard:function-naming"))
        licenseHeaderFile("${rootDir}/config/license")
        endWithNewline()
    }
    kotlinGradle {
        // same as kotlin, but for .gradle.kts files (defaults to "*.gradle.kts")
        target("*.gradle.kts", "additionalScripts/*.gradle.kts", "buildSrc/*.gradle.kts")
        ktlint("1.5.0")
        endWithNewline()
    }
    format("xml") {
        target("**/*.xml")
        targetExclude("**/build/**/*.xml")
        licenseHeaderFile("${rootDir}/config/license.xml", "(<[^!?])")
    }
}
