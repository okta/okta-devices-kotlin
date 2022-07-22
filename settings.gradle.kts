pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven(url = "https://oss.sonatype.org/content/repositories/snapshots/") // remove once we release
        maven(url = "https://jitpack.io")
    }
}
rootProject.name = "okta-devices-kotlin"
include(":push-sample-app")
include(":devices-push")
