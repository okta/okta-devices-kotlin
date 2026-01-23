import com.android.build.api.dsl.ApplicationExtension
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.util.Properties

plugins {
    id("com.android.application")
    id("owasp")
    id("spotless")
    id("com.google.gms.google-services")
    id("io.gitlab.arturbosch.detekt")
    id("org.jetbrains.kotlin.plugin.compose") version libs.versions.kotlin.get()
}

detekt {
    config.setFrom(files("${project.rootDir}/config/devices-detekt.yml", "${project.rootDir}/config/compose-detekt.yml"))
    buildUponDefaultConfig = true
    parallel = true
}

extensions.configure<ApplicationExtension> {
    compileSdk = DevicesConfig.compileSdkVersion
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

    buildFeatures {
        compose = true
        buildConfig = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.fromTarget(JavaVersion.VERSION_17.toString())
    }
}

dependencies {
    coreLibraryDesugaring(libs.desugar.jdk.libs)
    implementation(project(":devices-push"))

    implementation(platform(libs.okta.bom))
    implementation(libs.auth.foundation)
    implementation(libs.oauth2)
    implementation(libs.web.authentication.ui)

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.compose.material)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.runtime)

    implementation(libs.kotlinx.coroutines.play.services)

    implementation(libs.timber)

    // Firebase BoM
    implementation(platform(libs.firebase.bom))
    implementation(libs.google.firebase.messaging)
    implementation(libs.androidx.security.crypto)
}
