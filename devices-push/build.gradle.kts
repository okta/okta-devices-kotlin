import com.android.build.api.dsl.LibraryExtension
import org.gradle.kotlin.dsl.configure
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library")
    id("owasp")
    id("spotless")
    id("publish")
    id("org.jetbrains.dokka")
    id("org.jetbrains.kotlinx.kover")
    id("io.gitlab.arturbosch.detekt")
    kotlin("plugin.serialization") version libs.versions.kotlin.get()
}

detekt {
    config.setFrom(files("${project.rootDir}/config/devices-detekt.yml"))
    buildUponDefaultConfig = true
    parallel = true
}

extensions.configure<LibraryExtension> {
    compileSdk = DevicesConfig.compileSdkVersion
    namespace = "com.okta.devices.push"

    defaultConfig {
        minSdk = DevicesConfig.minSdkVersion
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("proguard-rules.pro")
    }

    compileOptions {
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
            withJavadocJar()
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.fromTarget(JavaVersion.VERSION_17.toString())
    }
}

dependencies {
    coreLibraryDesugaring(libs.desugar.jdk.libs)
    api(libs.devices.authenticator)
    implementation(libs.devices.core) {
        exclude(group = "com.google.android.gms", module = "play-services-safetynet")
    }
    implementation(libs.devices.storage)

    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.biometric)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.core.ktx)
    implementation(libs.jjwt.api)
    runtimeOnly(libs.jjwt.impl)
    runtimeOnly(libs.jjwt.orgjson) {
        exclude(group = "org.json", module = "json") // provided by Android natively
    }
    implementation(libs.okhttp)
    implementation(libs.sqlcipher)

    testImplementation(libs.logging.interceptor)
    testImplementation(libs.devices.fake.server) {
        exclude(group = "com.google.android.gms", module = "play-services-safetynet")
    }
    testImplementation(libs.androidx.core.testing)
    testImplementation(libs.androidx.room.testing)
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.junit)
    testImplementation(libs.androidx.junit.ktx)
    testImplementation(libs.robolectric)
    testImplementation(libs.mockwebserver)
    testImplementation(libs.mockk)
    testImplementation(libs.hamcrest.library)
    testImplementation(libs.kotlinx.serialization.json)
    testImplementation(libs.kotlinx.serialization.properties)
}
