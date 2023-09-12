import org.gradle.api.Project
import java.util.Properties

/**
 * Configuration for push-sample-app, devices-push, devices-authenticator
 */
object DevicesConfig {
    const val minSdkVersion = 24
    const val compileSdkVersion = 34
    const val targetSdkVersion = 34
    const val buildToolsVersion = "34.0.0"

    const val pushSampleAppVersionCode = 1
    const val pushSampleAppVersionName = "1.0.0"

    const val devicesPushVersion = "1.1.0"

    data class OssrhCredentials(
        val ossrhUsername: String,
        val ossrhPassword: String,
        val signingKeyId: String,
        val signingPassword: String,
        val signingKey: String,
    )

    fun ossrhCredentials(project: Project): OssrhCredentials {
        val properties = Properties()
        val propFile = project.rootProject.file("local.properties")
        if (propFile.exists()) propFile.inputStream().use { properties.load(it) }
        return OssrhCredentials(
            properties.getProperty("ossrh.username") ?: System.getenv("OSSRH_USERNAME") ?: "",
            properties.getProperty("ossrh.password") ?: System.getenv("OSSRH_PASSWORD") ?: "",
            properties.getProperty("signing.keyId") ?: System.getenv("SIGNING_KEY_ID") ?: "",
            properties.getProperty("signing.password") ?: System.getenv("SIGNING_PASSWORD") ?: "",
            properties.getProperty("signing.key") ?: System.getenv("SIGNING_KEY") ?: "",
        )
    }

    fun releaseVersion(project: Project): String = with(project.gradle.startParameter.taskNames) {
        val version = getVersion(project)
        when {
            any { it.contains("publishAllPublicationsToSonatypeRepository") }
                || any { it.contains("publishReleasePublicationToSonatypeRepository") } -> version

            any { it.contains("publishReleasePublicationToSnapshotRepository") }
                || any { it.contains("publishAllPublicationsToSnapshotRepository") } -> "$version-SNAPSHOT"

            // Add sha and git count for internal and local repo
            else -> "$version-${gitCountAndSha(project)}"
        }
    }

    private fun gitCountAndSha(project: Project): String {
        fun shell(cmd: String): String {
            val output = java.io.ByteArrayOutputStream()
            project.exec {
                commandLine = cmd.split(" ")
                standardOutput = output
            }
            return String(output.toByteArray()).replace(System.lineSeparator(), "")
        }
        return shell("git rev-list HEAD --count") + "-" + shell("git rev-parse --short=8 HEAD")
    }

    private fun getVersion(project: Project): String = when (project.name) {
        Modules.DEVICES_PUSH.moduleName -> Modules.DEVICES_PUSH.version
        else -> throw IllegalArgumentException("Unknown module ${project.name}")
    }

    private enum class Modules(val moduleName: String, val version: String) {
        DEVICES_PUSH("devices-push", devicesPushVersion),
    }
}
