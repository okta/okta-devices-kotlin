# Push Example

This example shows you how to use the [Okta Devices SDK](https://github.com/okta/okta-devices-kotlin).

**Table of contents**
- [Push Example](#push-example)
  - [Prerequisites](#prerequisites)
  - [Configuration](#configuration)
  - [Dependencies](#dependencies)
  - [Run this example](#run-this-example)
  - [Enroll this app as a custom authenticator](#enroll-this-app-as-a-custom-authenticator)
  - [Verify it works](#verify-it-works)

## Prerequisites

In order to use this project, your org's admin needs to:
1. Add an OIDC app with the proper Okta API scopes ('okta.myAccount.appAuthenticator.manage', 'okta.myAccount.appAuthenticator.read') along with any OIDC scopes ('openid', 'profile', 'email').
2. Create an FCM config.
3. Create a custom authenticator using the FCM config created above.

### Configuration

#### Update configuration file
1. Add the following properties to local.properties in the root directory

```
oidc.scheme={yourOidcScheme}
org.url="{yourOrgUrl}"
oidc.client.id="{yourOrgClientId}"
oidc.redirect.uri="{yourRedirectUri}"
oidc.scope="openid profile email offline_access okta.myAccount.appAuthenticator.manage okta.myAccount.appAuthenticator.read"
```

2. Download google-services.json from your organization's Firebase and add to your project directory, to obtain the file, you can follow the instruction [here](https://firebase.google.com/docs/android/setup)

**Notes:**
- To receive a **refresh_token**, you must include the `offline_access` scope.
- Make sure **oidc.redirect.uri** is consistent with **oidc.scheme**. For example, if your **oidc.redirect.uri** is `com.okta.example:/callback`, the **oidc.scheme** should be
  `com.okta.example`.

## Dependencies

This sample uses the [Okta OIDC Library] as a dependency in its `build.gradle.kts` file:

```groovy
    implementation(platform("com.okta.kotlin:bom:1.0.0"))
    implementation("com.okta.kotlin:auth-foundation")
    implementation("com.okta.kotlin:oauth2")
    implementation("com.okta.kotlin:web-authentication-ui")
```

## Run this example

You can open this sample into Android Studio or build it using gradle.
```bash
./gradlew push-sample-app:assembleRelease
```

[Okta Devices SDK]: https://github.com/okta/okta-devices-kotlin
[Okta OIDC Library]: https://github.com/okta/okta-mobile-kotlin

## Enroll this app as a custom authenticator
In order to try the SDK capabilities, you need to Sign In on the app with your org's credentials.

Once signed in, enable the `Sign in with push notification` checkbox. This will call the SDK and initiate the enrollment in order to set up your device as push authenticator.

You can also sign in by biometrics like touch ID or face ID by enabling the `Enable biometrics` option. You have to ensure that `Sign in with push notification` option is enabled and you have enabled biometrics on your device

## Verify it works
On a browser, try to log in on your org's website and select `Get a push notification` as the login method. You should receive a push notification on your device

Once tapping the notification, you can tap the `Yes,it's me` option on the pop up window to sign in, or provide your biometrics if you enabled `Enable biometrics` option

### Push delivery issues
If for some reason there's an issue receiving push notifications, you can press the `Check notification` button in the app, the SDK will pull all the pending challenges and you should be able to receive the notification after that.
