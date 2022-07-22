plugins {
    id("maven-publish")
    id("signing")
}

val ossrhCredentials = DevicesConfig.ossrhCredentials(project)

publishing {
    publications {
        register<MavenPublication>("release") {
            pom {
                name.set("Okta Devices Kotlin")
                description.set("Okta's multi-factor push authentication service that provides a way for you to implement MFA in your Android application.")
                url.set("https://github.com/okta/okta-devices-kotlin")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("FeiChen-okta")
                        name.set("Fei Chen")
                        email.set("fei.chen@okta.com")
                    }
                    developer {
                        id.set("tommywong-okta")
                        name.set("Tommy Wong")
                        email.set("tommy.wong@okta.com")
                    }
                    developer {
                        id.set("buntyjoshi-okta")
                        name.set("Bunty Joshi")
                        email.set("bunty.joshi@okta.com")
                    }
                    developer {
                        id.set("hansreichenbach-okta")
                        name.set("Hans Reichenbach")
                        email.set("hans.reichenbach@okta.com")
                    }
                    developer {
                        id.set("IldarAbdullin-okta")
                        name.set("Ildar Abdullin")
                        email.set("ildar.abdullin@okta.com")
                    }
                    developer {
                        id.set("mingxiajiang-okta")
                        name.set("Mingxia Jiang")
                        email.set("mingxia.jiang@okta.com")
                    }
                }
                scm {
                    connection.set("scm:git@github.com:okta/okta-devices-kotlin.git")
                    developerConnection.set("scm:git@github.com:okta/okta-devices-kotlin.git")
                    url.set("https://github.com/okta/okta-devices-kotlin.git")
                }
            }

            groupId = "com.okta.devices"
            artifactId = project.name
            version = DevicesConfig.releaseVersion(project)
            if (artifactId == "devices-core") {
                artifact(tasks.getByName("emptySourceJar"))
                artifact(tasks.getByName("emptyJavadocJar"))
            }
            afterEvaluate {
                from(components["release"])
            }
        }
    }

    repositories {
        maven(url = "$buildDir/repo") {
            name = "internal"
        }
    }

    repositories {
        maven(url = "https://oss.sonatype.org/service/local/staging/deploy/maven2/") {
            name = "sonatype"
            credentials {
                username = ossrhCredentials.ossrhUsername
                password = ossrhCredentials.ossrhPassword
            }
            authentication {
                create<BasicAuthentication>("basic")
            }
        }
        maven(url = "https://oss.sonatype.org/content/repositories/snapshots/") {
            name = "snapshot"
            credentials {
                username = ossrhCredentials.ossrhUsername
                password = ossrhCredentials.ossrhPassword
            }
            authentication {
                create<BasicAuthentication>("basic")
            }
        }
    }
}

tasks.withType<Sign>().configureEach {
    onlyIf {
        (gradle.taskGraph.hasTask(":${project.name}:publishAllPublicationsToSonatypeRepository")
            || gradle.taskGraph.hasTask(":${project.name}:publishReleasePublicationToSonatypeRepository"))
    }
}

signing {
    useInMemoryPgpKeys(ossrhCredentials.signingKeyId, ossrhCredentials.signingKey, ossrhCredentials.signingPassword)
    sign(publishing.publications.getByName("release"))
}
