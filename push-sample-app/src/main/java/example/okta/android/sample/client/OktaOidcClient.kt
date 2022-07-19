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
import com.okta.authfoundation.claims.name
import com.okta.authfoundation.claims.subject
import com.okta.authfoundation.client.OidcClient
import com.okta.authfoundation.client.OidcClientResult
import com.okta.authfoundation.client.OidcConfiguration
import com.okta.authfoundation.credential.Credential
import com.okta.authfoundation.credential.CredentialDataSource.Companion.createCredentialDataSource
import com.okta.authfoundation.credential.RevokeTokenType
import com.okta.authfoundation.jwt.JwtParser
import com.okta.devices.api.model.AuthToken
import com.okta.webauthenticationui.WebAuthenticationClient.Companion.createWebAuthenticationClient
import example.okta.android.sample.BuildConfig
import example.okta.android.sample.app.MainActivity
import example.okta.android.sample.errors.OidcError
import example.okta.android.sample.model.UserStatus
import okhttp3.HttpUrl.Companion.toHttpUrl

/**
 * A oidc client is required to authenticate and authorize the user to use the devices-push SDK.
 * The OIDC client for this example is from: https://github.com/okta/okta-mobile-kotlin
 */
class OktaOidcClient(app: Application) {

    private val jwtParser = JwtParser.create()

    private val oidcClient = OidcClient.createFromDiscoveryUrl(
        OidcConfiguration(
            clientId = BuildConfig.OIDC_CLIENT_ID,
            defaultScope = BuildConfig.OIDC_SCOPE
        ),
        "${BuildConfig.ORG_URL}/.well-known/openid-configuration?client_id=${BuildConfig.OIDC_CLIENT_ID}".toHttpUrl()
    )

    private val credentialDataSource = oidcClient.createCredentialDataSource(app)

    suspend fun oidcAuthenticate(activity: MainActivity, payload: Map<String, String> = emptyMap()): Result<UserStatus> {
        val webAuthenticationClient = oidcClient.createWebAuthenticationClient()

        return when (val result = webAuthenticationClient.login(activity, BuildConfig.OIDC_REDIRECT_URI, payload)) {
            is OidcClientResult.Error -> Result.failure(OidcError.Error("oidc login failed", result.exception))
            is OidcClientResult.Success -> result.result.idToken?.run {
                runCatching {
                    jwtParser.parse(this).let { jwt ->
                        val credential = jwt.subject?.run { getCredential(this) } ?: credentialDataSource.createCredential()
                        credential.storeToken(result.result)
                        Result.success(UserStatus(checkNotNull(jwt.subject), checkNotNull(jwt.name), pushEnabled = false, userVerification = false))
                    }
                }.getOrElse { Result.failure(it) }
            } ?: Result.failure(OidcError.InvalidState)
        }
    }

    private suspend fun getCredential(userId: String): Credential? =
        credentialDataSource.listCredentials().find { it.idToken()?.subject == userId }

    suspend fun getSignedInUser(): Result<UserStatus> = runCatching {
        val jwt = jwtParser.parse(checkNotNull(credentialDataSource.listCredentials().first().token?.idToken))
        Result.success(UserStatus(checkNotNull(jwt.subject), checkNotNull(jwt.name), pushEnabled = false, userVerification = false))
    }.getOrElse { Result.failure(it) }

    suspend fun authToken(userId: String): Result<AuthToken.Bearer> = runCatching {
        getCredential(userId)?.run {
            getValidAccessToken()?.run {
                Result.success(AuthToken.Bearer(this))
            } ?: Result.failure(OidcError.Error("Invalid access token"))
        } ?: Result.failure(OidcError.NoSession)
    }.getOrElse { Result.failure(it) }

    suspend fun revokeToken(userId: String): Result<Boolean> {
        return getCredential(userId)?.run {
            // revoking refresh token will also revoke access token.
            when (val result = revokeToken(RevokeTokenType.REFRESH_TOKEN)) {
                is OidcClientResult.Error -> Result.failure(OidcError.Error(cause = result.exception))
                is OidcClientResult.Success -> Result.success(true)
            }
        } ?: Result.failure(OidcError.NoSession)
    }

    suspend fun deleteSession(userId: String): Result<Boolean> = runCatching {
        getCredential(userId)?.run { delete() }
        Result.success(true)
    }.getOrElse { Result.failure(it) }
}
