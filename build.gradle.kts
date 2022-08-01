// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    id("com.android.application") version "7.2.1" apply false
    id("com.android.library") version "7.2.1" apply false
    id("org.jetbrains.kotlin.android") version Version.kotlin apply false
    id("org.jetbrains.dokka") version "1.6.10" apply false
    id("com.google.gms.google-services") version "4.3.13" apply false
    id("org.jetbrains.kotlinx.kover") version "0.5.1" apply false
    id("org.sonarqube") version "3.4.0.2513" apply true
    id("io.gitlab.arturbosch.detekt") version "1.21.0" apply false
}

task<Delete>("clean") {
    delete(rootProject.buildDir)
}

sonarqube {
    val properties = java.util.Properties()
    project.rootProject.file("local.properties").takeIf { it.exists() }?.inputStream()?.use { properties.load(it) }
    properties {
        property("sonar.host.url", properties.getProperty("sonar.host.url") ?: System.getenv("SONAR_HOST_URL") ?: "")
        property("sonar.projectKey", properties.getProperty("sonar.project.key") ?: System.getenv("SONAR_PROJECT_KEY") ?: "")
        property("sonar.coverage.jacoco.xmlReportPaths", properties.getProperty("sonar.report.paths") ?: System.getenv("SONAR_REPORT_PATHS") ?: "")
        property("sonar.kotlin.detekt.reportPaths", properties.getProperty("sonar.report.detekt.paths") ?: System.getenv("SONAR_REPORT_DETEKT_PATHS") ?: "")
    }
}

val reportMerge by tasks.registering(io.gitlab.arturbosch.detekt.report.ReportMergeTask::class) {
    output.set(rootProject.buildDir.resolve("reports/detekt/merge.xml"))
}
subprojects {
    plugins.withType(io.gitlab.arturbosch.detekt.DetektPlugin::class) {
        tasks.withType(io.gitlab.arturbosch.detekt.Detekt::class) detekt@{
            finalizedBy(reportMerge)
            reportMerge.configure {
                input.from(this@detekt.xmlReportFile)
            }
        }
    }
}