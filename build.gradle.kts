// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    id("com.android.application") version "8.5.2" apply false
    id("com.android.library") version "8.5.2" apply false
    id("org.jetbrains.kotlin.android") version Version.kotlin apply false
    id("org.jetbrains.dokka") version "1.9.20" apply false
    id("com.google.gms.google-services") version "4.4.2" apply false
    id("org.jetbrains.kotlinx.kover") version "0.8.3" apply false
    id("org.sonarqube") version "5.1.0.4882" apply true
    id("io.gitlab.arturbosch.detekt") version "1.23.6" apply false
}

buildscript {
    configurations.all {
        resolutionStrategy {
            force("com.fasterxml.woodstox:woodstox-core:6.6.1")
            force("com.fasterxml.jackson.core:jackson-core:2.17.2")
            // https://issuetracker.google.com/issues/340202290
            // AGP introduced incompatible bc versions. Forces the version that AGP uses.
            // 1.7.1 has vulns, but these vulns are not included in the binary since this is used by buildscript
            force("org.bouncycastle:bcprov-jdk18on:1.71")
            force("org.bouncycastle:bcpkix-jdk18on:1.71")
        }
    }
}

allprojects {
    configurations.all {
        resolutionStrategy {
            force("com.squareup.okio:okio:3.9.0")
            force("org.bouncycastle:bcprov-jdk18on:1.78.1")
            force("org.json:json:20240303")
            force("com.google.guava:guava:33.3.0-jre")
            force("androidx.room:room-runtime:${Version.room}")
        }
    }
}

task<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
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
    output.set(rootProject.layout.buildDirectory.file("reports/detekt/merge.xml"))
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