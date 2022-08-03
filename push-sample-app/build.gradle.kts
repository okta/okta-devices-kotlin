import java.util.Properties

plugins {
    id("com.android.application")
    id("owasp")
    id("spotless")
    id("com.google.gms.google-services")
    id("io.gitlab.arturbosch.detekt")
    kotlin("android")
}

detekt {
    config = files("${project.rootDir}/config/devices-detekt.yml", "${project.rootDir}/config/compose-detekt.yml")
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
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_11.toString()
    }

    buildFeatures {
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = Version.composeCompiler
    }
}

dependencies {
    implementation(project(":devices-push"))

    implementation(platform("com.okta.kotlin:bom:1.0.0"))
    implementation("com.okta.kotlin:auth-foundation")
    implementation("com.okta.kotlin:oauth2")
    implementation("com.okta.kotlin:web-authentication-ui")

    implementation("androidx.core:core-ktx:1.8.0")
    implementation("androidx.appcompat:appcompat:1.4.2")
    implementation("androidx.biometric:biometric:1.2.0-alpha04")
    implementation("androidx.activity:activity-compose:1.5.1")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:${Version.archLifecycleVersion}")
    implementation("androidx.compose.material:material:${Version.compose}")
    implementation("androidx.compose.ui:ui:${Version.compose}")
    implementation("androidx.compose.ui:ui-tooling:${Version.compose}")
    implementation("androidx.compose.ui:ui-tooling-preview:${Version.compose}")
    implementation("androidx.compose.runtime:runtime:${Version.compose}")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-play-services:1.6.4")

    implementation("com.jakewharton.timber:timber:5.0.1")

    // Firebase BoM
    implementation(platform("com.google.firebase:firebase-bom:30.3.1"))
    implementation("com.google.firebase:firebase-messaging-ktx")
    implementation("androidx.security:security-crypto-ktx:1.1.0-alpha03")
}
