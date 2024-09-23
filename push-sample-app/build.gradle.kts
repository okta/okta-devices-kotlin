import java.util.Properties

plugins {
    id("com.android.application")
    id("owasp")
    id("spotless")
    id("com.google.gms.google-services")
    id("io.gitlab.arturbosch.detekt")
    id("org.jetbrains.kotlin.plugin.compose") version Version.kotlin
    kotlin("android")
}

detekt {
    config.setFrom(files("${project.rootDir}/config/devices-detekt.yml", "${project.rootDir}/config/compose-detekt.yml"))
    buildUponDefaultConfig = true
    parallel = true
}

android {
    compileSdk = DevicesConfig.compileSdkVersion
    buildToolsVersion = DevicesConfig.buildToolsVersion
    namespace = "example.okta.android.sample"

    defaultConfig {
        signingConfig = signingConfigs.getByName("debug")
        applicationId = "example.okta.android.push_sample_app"
        minSdk = DevicesConfig.minSdkVersion
        targetSdk = DevicesConfig.targetSdkVersion
        versionCode = DevicesConfig.pushSampleAppVersionCode
        versionName = DevicesConfig.pushSampleAppVersionName

        val properties = Properties()
        val propFile = rootProject.file("local.properties")
        if (propFile.exists()) propFile.inputStream().use { properties.load(it) }

        buildConfigField("String", "ORG_URL", properties.getProperty("org.url") ?: "\"\"")
        buildConfigField("String", "OIDC_CLIENT_ID", properties.getProperty("oidc.client.id") ?: "\"\"")
        buildConfigField("String", "OIDC_SCOPE", properties.getProperty("oidc.scope") ?: "\"\"")
        buildConfigField("String", "OIDC_REDIRECT_URI", properties.getProperty("oidc.redirect.uri") ?: "\"\"")
        manifestPlaceholders["webAuthenticationRedirectScheme"] = properties.getProperty("oidc.scheme") ?: ""
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }
}

dependencies {
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.2")
    implementation(project(":devices-push"))

    implementation(platform("com.okta.kotlin:bom:1.2.0"))
    implementation("com.okta.kotlin:auth-foundation")
    implementation("com.okta.kotlin:oauth2")
    implementation("com.okta.kotlin:web-authentication-ui")

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.biometric:biometric:1.2.0-alpha05")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:${Version.archLifecycleVersion}")
    implementation("androidx.compose.material:material:${Version.compose}")
    implementation("androidx.compose.ui:ui:${Version.compose}")
    implementation("androidx.compose.ui:ui-tooling:${Version.compose}")
    implementation("androidx.compose.ui:ui-tooling-preview:${Version.compose}")
    implementation("androidx.compose.runtime:runtime:${Version.compose}")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-play-services:1.8.1")

    implementation("com.jakewharton.timber:timber:5.0.1")

    // Firebase BoM
    implementation(platform("com.google.firebase:firebase-bom:33.3.0"))
    implementation("com.google.firebase:firebase-messaging-ktx")
    implementation("androidx.security:security-crypto-ktx:1.1.0-alpha06")
}
