plugins {
    id("com.android.library")
    id("owasp")
    id("spotless")
    id("publish")
    id("org.jetbrains.dokka")
    id("org.jetbrains.kotlinx.kover")
    id("io.gitlab.arturbosch.detekt")
    kotlin("android")
    kotlin("plugin.serialization") version Version.kotlin
}

detekt {
    config.setFrom(files("${project.rootDir}/config/devices-detekt.yml"))
    buildUponDefaultConfig = true
    parallel = true
}

android {
    compileSdk = DevicesConfig.compileSdkVersion
    buildToolsVersion = DevicesConfig.buildToolsVersion
    namespace = "com.okta.devices.push"

    defaultConfig {
        minSdk = DevicesConfig.minSdkVersion
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            consumerProguardFiles("proguard-rules.pro")
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

dependencies {
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.2")
    api("com.okta.devices:devices-authenticator:${Version.devicesAuthenticator}")
    implementation("com.okta.devices:devices-core:${Version.devicesCore}") {
        exclude(group = "com.google.android.gms", module = "play-services-safetynet")
    }
    implementation("com.okta.devices:devices-storage:${Version.devicesStorage}")

    implementation("androidx.lifecycle:lifecycle-runtime-ktx:${Version.archLifecycleVersion}")
    implementation("androidx.biometric:biometric:1.2.0-alpha05")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:${Version.coroutine}")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("io.jsonwebtoken:jjwt-api:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-orgjson:0.12.6") {
        exclude(group = "org.json", module = "json") // provided by Android natively
    }
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    testImplementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
    testImplementation("com.okta.devices:devices-fake-server:${Version.devicesFakeServer}") {
        exclude(group = "com.google.android.gms", module = "play-services-safetynet")
    }
    testImplementation("androidx.arch.core:core-testing:2.2.0")
    testImplementation("androidx.room:room-testing:${Version.room}")
    testImplementation("org.jetbrains.kotlin:kotlin-test:${Version.kotlin}")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:${Version.coroutine}")
    testImplementation("junit:junit:4.13.2")
    testImplementation("androidx.test.ext:junit-ktx:${Version.extJunit}")
    testImplementation("org.robolectric:robolectric:4.13")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("io.mockk:mockk:1.13.12")
    testImplementation("org.hamcrest:hamcrest-library:3.0")
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:${Version.kotlinSerialization}")
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-properties:${Version.kotlinSerialization}")
}
