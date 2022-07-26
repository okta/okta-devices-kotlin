// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    id("com.android.application") version ("7.2.1") apply false
    id("com.android.library") version ("7.2.1") apply false
    id("org.jetbrains.kotlin.android") version (Version.kotlin) apply false
    id("org.jetbrains.dokka") version ("1.6.10") apply false
    id("com.google.gms.google-services") version ("4.3.13") apply false
    id("org.jetbrains.kotlinx.kover") version "0.5.1" apply false
}

task<Delete>("clean") {
    delete(rootProject.buildDir)
}
