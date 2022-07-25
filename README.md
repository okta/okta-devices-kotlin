[![Support](https://img.shields.io/badge/support-Developer%20Forum-blue.svg)][devforum]
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# Okta Devices SDK

This library is Okta's multi-factor push authentication service that provides a way for you to implement MFA in your Android application.

**Table of Contents**

- [Okta Authenticator SDK](#okta-authenticator-sdk)
    - [Release status](#release-status)
    - [Need help?](#need-help)
    - [Getting started](#getting-started)
    - [Installation](#Installation)
    - [Usage](#Usage)
        - [Creation](#Creation)
        - [Enrollment](#Enrollment)
            - [Retrieve existing enrollments](#Retrieve-existing-enrollments)
            - [Update registration token](#Update-registration-token)
            - [Update user verification](#Update-user-verification)
            - [Delete enrollment](#Delete-enrollment)
            - [Delete enrollment from device](#Delete-enrollment-from-device)
        - [Verification](#Verification)
            - [Retrieve pending challenges](#Retrieve-pending-challenges)
            - [Resolve the challenge](#Resolve-the-challenge)

## Release status

This library uses semantic versioning and follows Okta's [Library Version Policy][okta-library-versioning].

| Version | Status                             |
| ------- | ---------------------------------- |
| 0.0.1   | ⚠ Beta                             |

⚠ Beta version is currently in development and isn't ready for production use

The latest release can always be found on the [releases page][github-releases].

## Need help?

If you run into problems using the SDK, you can:

* Ask questions on the [Okta Developer Forums][devforum]
* Post [issues][github-issues] here on GitHub (for code errors)

## Getting started

// TODO link to setup custom authenticator // TODO link to setup push provider // TODO list and explain why [OIDC SDK](https://github.com/okta/okta-oidc-android)
or [IDX SDK](https://github.com/okta/okta-idx-android) is required. Firebase messaging SDK is required

See the [Push Sample App] for a complete implementation.

- **Kotlin Coroutines**: The following sample code assumes that suspend functions are called in a coroutine scope. See [Kotlin Coroutines] for more information.

### Installation

Add the Okta Authenticator SDK dependency to your build.gradle file:

```kotlin
implementation("com.okta.devices:devices-push:0.0.1")
```

## Usage

A complete integration requires your app to implement the following:

- **Creation:** Create the SDK object to work with your Okta authenticator configuration.
- **Enrollment:** Register a device and optional biometrics with an account for use with push MFA.
- **Verification:** Resolve an MFA challenge step for a sign-in attempt against an enrolled account, prompting the user to approve or reject it (with optional biometrics).
- **Update:** Refresh the FCM device registration token, remediate changed biometrics, deregister the account on the device.

### Creation

Create the SDK object to work with your Okta authenticator configuration. Use the PushAuthenticatorBuilder to create an authenticator with your application configuration:

```kotlin
val authenticator: PushAuthenticator = PushAuthenticatorBuilder.create(
    ApplicationConfig(context, appName = "MyApp", appVersion = BuildConfig.VERSION_NAME)
) {
    passphrase = "SecretPassphrase".toByteArray() // Secret must be stored securely 
}.getOrThrow()
```

If a passphrase isn't provided, then the Devices SDK data will not be encrypted. It is up to you to secure the passphrase.

### Enrollment

Once an authenticator and oidc application has been created, you will also need a Firebase device registration token. After we have met all the requirements, we can start enrolling the user by doing the
following:

```kotlin
val authConfig = DeviceAuthenticatorConfig(URL(orgUrl), "oidcClientId")
val result = authenticator.enroll(AuthToken.Bearer("accessToken"), authConfig, EnrollmentParameters.Push(FcmToken("registrationToken")), enableUserVerification = false)
if (result.isSuccess) {
    val pushEnrollment: PushEnrollment = result.value
}
```

#### Retrieve existing enrollments

In order to retrieve information about existing enrollments, use `allEnrollments()`. This can be used to display attributes for a list of accounts or find a specific account in order to update or
delete it.

```kotlin
val enrollments: List<PushEnrollment> = authenticator.allEnrollments().getOrThrow()
```

#### Update registration token

Whenever the FCM SDK sends your application a new token with FirebaseMessagingService.onNewToken, you can update existing enrollments with the new token by doing the following:

```kotlin
val enrollments: List<PushEnrollment> = authenticator.allEnrollments().getOrThrow()

// Find the enrollment associated with the current user
enrollments.find { it.user.username == "myUser" }?.let { pushEnrollment ->
    pushEnrollment.updateRegistrationToken(AuthToken.Bearer("accessToken"), FcmToken("newToken"))
        .onSuccess { println("success") }
        .onFailure { println("failure") }
}
```

#### Update user verification

User verification is for checking that a user is the one claimed, this can be achieved by asking the user for biometrics. You can enable or disable user verification by doing the following:

```kotlin
val enrollments: List<PushEnrollment> = authenticator.allEnrollments().getOrThrow()

// Find the enrollment associated with the current user
enrollments.find { it.user.username == "myUser" }?.let { pushEnrollment ->
    pushEnrollment.setUserVerification(AuthToken.Bearer("accessToken"), true)
        .onSuccess { println("success") }
        .onFailure { println("failure") }
}
```

### Delete enrollment

Deleting an enrollment will unenroll push verification. This will result in the SDK deleting enrollment from the device when a successful response is received from the Okta server.

```kotlin
val enrollments: List<PushEnrollment> = authenticator.allEnrollments().getOrThrow()

// Find the enrollment associated with the current user and delete it
enrollments.find { it.userInformation().username == "myUser" }?.let { pushEnrollment ->
    authenticator.delete(AuthToken.Bearer("accessToken"), pushEnrollment)
        .onSuccess { println("success") }
        .onFailure { println("failure") }
}
```

### Delete enrollment from device

The difference between calling `deleteFromDevice` and `delete` is that `deleteFromDevice` does not make a server call to unenroll push verification, therefore it does not require any authorization. Use this with caution as the
user will be unable to meet MFA requirements for any sign-in attempt.

```kotlin
val enrollments: List<PushEnrollment> = authenticator.allEnrollments().getOrThrow()

// Find the enrollment associated with the current user
enrollments.find { it.userInformation().username == "myUser" }?.let { pushEnrollment ->
    pushEnrollment.deleteFromDevice()
        .onSuccess { println("success") }
        .onFailure { println("failure") }
}
```

### Verification

When a user attempts to sign in to the enrolled account (e.g. via an app or a web browser), Okta's backend will create a push challenge and send this challenge to enrolled devices via your push
provider.

#### Retrieve pending challenges

Sometimes Firebase messaging service fails to deliver a notification to the user, we can check the server to see if we have any pending challenges by doing the following:

```kotlin
val enrollments: List<PushEnrollment> = authenticator.allEnrollments().getOrThrow()

// Find the enrollment associated with the current user
enrollments.find { it.user.username == "myUser" }?.let { pushEnrollment ->
    pushEnrollment.retrievePushChallenges(AuthToken.Bearer("accessToken"))
        .onSuccess { println("success") }
        .onFailure { println("failure") }
}
```

### Resolve the challenge

Once you have received a challenge via one of the channels above, your app should `resolve` them in order to proceed with login. The SDK may request remediation steps in order to complete resolution,
such as `UserConsent` (to request the user to approve/deny the challenge) or `UserVerification` to notify the app that a biometric verification is required to proceed.

```kotlin

val fcmRemoteMessage = "PushChallengeString" // fcm challenge

authenticator.parseChallenge(fcmRemoteMessage)
    .onSuccess { challenge ->
        challenge.resolve().onSuccess { remediation ->
            remediate(remediation) // call method to handle remediation
        }.onFailure { println("failure") }
    }.onFailure { println("failure") }

private fun remediate(remediation: PushRemediation) = runCatching {
    when (remediation) {
        is Completed -> println("Successfully handled. sign in success")
        is UserConsent -> println("Show a UX to accept or deny")
        is UserVerification -> println("Show a biometric prompt")
        is UserVerificationError -> println("Biometric failure")
    }
}.getOrElse { updateError(it) }
```

See the [Push Sample App] for a complete implementation on resolving a push challenge.

## Contributing

We are happy to accept contributions and PRs! Please see the [contribution guide](CONTRIBUTING.md) to understand how to structure a contribution.

[Push Sample App]: https://github.com/okta-tardis/okta-devices-android/tree/master/push-sample-app

[devforum]: https://devforum.okta.com/

[lang-landing]: https://developer.okta.com/code/android/#android-libraries

[github-releases]: https://github.com/okta-tardis/okta-devices-android/releases

[Rate Limiting at Okta]: https://developer.okta.com/docs/api/getting_started/rate-limits

[okta-library-versioning]: https://developer.okta.com/code/library-versions

[Kotlin coroutines]: https://kotlinlang.org/docs/coroutines-overview.html
