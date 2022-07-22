/*
 * Copyright (c) 2021-2022, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License,
 * Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the
 * License.
 */
package example.okta.android.sample.client

import android.app.Application
import com.okta.devices.api.log.DeviceLog
import com.okta.devices.api.model.ApplicationConfig
import com.okta.devices.api.model.DeviceAuthenticatorConfig
import com.okta.devices.api.model.EnrollmentParameters
import com.okta.devices.api.model.RegistrationToken
import com.okta.devices.push.PushAuthenticatorBuilder
import com.okta.devices.push.api.PushAuthenticator
import com.okta.devices.push.api.PushChallenge
import com.okta.devices.push.api.PushEnrollment
import example.okta.android.sample.BuildConfig
import example.okta.android.sample.errors.AuthenticatorError
import timber.log.Timber
import java.net.URL

/**
 * PushAuthenticator use cases: enable or disable push MFA, list existing push enrollment, enable or disable biometric,
 * update FCM devices registration tokens, parsing push notification challenges and checking the server for push challenges.
 *
 * @property oidcClient Used to get access tokens to authorize the user for the above use cases.
 * @constructor
 * Creates a AuthenticatorClient that is composed of the oidcClient and PushAuthenticator
 *
 * @param app
 */
class AuthenticatorClient(app: Application, private val oidcClient: OktaOidcClient) {
    // Create the PushAuthenticator and customize the DeviceLog to use timber
    private val pushAuthenticator: PushAuthenticator = PushAuthenticatorBuilder.create(
        ApplicationConfig(app, appName = BuildConfig.APPLICATION_ID, appVersion = BuildConfig.VERSION_NAME)
    ) {
        // Override the default log with Timber
        deviceLog = object : DeviceLog {
            override fun println(priority: Int, tag: String, log: String, tr: Throwable?) {
                Timber.log(priority, tag, log, tr)
            }
        }
        // Enable encryption
        passphrase = "Do not do this in your app".toByteArray()
    }.getOrThrow()

    suspend fun getEnrollment(userId: String): Result<PushEnrollment> = runCatching {
        return pushAuthenticator.allEnrollments().getOrThrow().let { authenticators ->
            authenticators.find { it.user().id == userId }?.run { Result.success(this) }
        } ?: Result.failure(AuthenticatorError.NoEnrollment)
    }.getOrElse { Result.failure(it) }

    suspend fun enroll(userId: String, params: EnrollmentParameters): Result<PushEnrollment> = runCatching {
        val config = DeviceAuthenticatorConfig(URL(BuildConfig.ORG_URL), BuildConfig.OIDC_CLIENT_ID)
        val authToken = oidcClient.authToken(userId).getOrThrow()
        return pushAuthenticator.enroll(authToken, config, params).fold({ Result.success(it) }, { Result.failure(it) })
    }.getOrElse { Result.failure(it) }

    suspend fun updateRegistrationTokenForAll(registrationToken: String): Result<String> = runCatching {
        pushAuthenticator.allEnrollments().getOrThrow().forEach {
            val authToken = oidcClient.authToken(it.user().id).getOrThrow()
            it.updateRegistrationToken(authToken, RegistrationToken.FcmToken(registrationToken))
        }
        Result.success(registrationToken)
    }.getOrElse { Result.failure(it) }

    suspend fun delete(userId: String): Result<Boolean> = runCatching {
        getEnrollment(userId).getOrNull()?.run {
            val authToken = oidcClient.authToken(userId).getOrThrow()
            pushAuthenticator.delete(authToken, this)
        } ?: Result.success(true)
    }.getOrElse { Result.failure(it) }

    suspend fun handlePushChallenge(challengeJws: String): Result<PushChallenge> = runCatching {
        val remediation = pushAuthenticator.parseChallenge(challengeJws).getOrThrow()
        Result.success(remediation)
    }.getOrElse { Result.failure(it) }

    suspend fun updateUserVerification(enableUv: Boolean, userId: String): Result<Boolean> = runCatching {
        getEnrollment(userId).getOrNull()?.run {
            val authToken = oidcClient.authToken(userId).getOrThrow()
            setUserVerification(authToken, enableUv)
        } ?: Result.failure(AuthenticatorError.NoEnrollment)
    }.getOrElse { Result.failure(it) }

    suspend fun retrievePendingChallenges(): Result<List<PushChallenge>> = runCatching {
        pushAuthenticator.allEnrollments().getOrThrow().firstOrNull()?.let {
            val authToken = oidcClient.authToken(it.user().id).getOrThrow()
            val challenges = it.retrievePushChallenges(authToken).getOrThrow()
            Result.success(challenges)
        } ?: Result.failure(AuthenticatorError.NoEnrollment)
    }.getOrElse { Result.failure(it) }
}
