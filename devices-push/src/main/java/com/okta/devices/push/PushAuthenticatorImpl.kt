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
package com.okta.devices.push

import com.okta.devices.DeviceAuthenticatorCore
import com.okta.devices.api.DeviceAuthenticator
import com.okta.devices.api.model.AuthToken
import com.okta.devices.api.model.DeviceAuthenticatorConfig
import com.okta.devices.api.model.EnrollmentParameters
import com.okta.devices.authenticator.DeviceAuthenticatorImpl
import com.okta.devices.authenticator.exceptions.toResult
import com.okta.devices.authenticator.model.ChallengeContext
import com.okta.devices.data.repository.MethodType.PUSH
import com.okta.devices.model.AuthorizationToken
import com.okta.devices.model.EnrollmentCoreParameters
import com.okta.devices.model.deviceError
import com.okta.devices.push.api.PushAuthenticator
import com.okta.devices.push.api.PushChallenge
import com.okta.devices.push.api.PushEnrollment
import com.okta.devices.util.baseUrl

internal class PushAuthenticatorImpl(
    private val core: DeviceAuthenticatorCore,
    private val myAccount: Boolean = false
) : PushAuthenticator, DeviceAuthenticator by DeviceAuthenticatorImpl(core, myAccount) {

    override suspend fun parseChallenge(challenge: String, allowedClockSkewInSeconds: Long): Result<PushChallenge> = runCatching {
        val challengeInfo = core.parseJws(challenge, allowedClockSkewInSeconds).getOrElse { return Result.failure(it) }
        core.getAuthenticatorEnrollmentById(challengeInfo.authenticatorEnrollmentId).fold(
            {
                if (challengeInfo.method == PUSH) {
                    Result.success(PushChallengeImpl(ChallengeContext(challengeInfo, it), allowedClockSkewInSeconds))
                } else Result.failure(IllegalArgumentException("Challenge is not of type push"))
            },
            { Result.failure(it) }
        )
    }.getOrElse { it.deviceError().toResult() }

    override suspend fun enroll(authToken: AuthToken, config: DeviceAuthenticatorConfig, params: EnrollmentParameters): Result<PushEnrollment> {
        if (params !is EnrollmentParameters.Push) return Result.failure(IllegalArgumentException("EnrollmentParameters must be of type Push"))
        val coreParameters = EnrollmentCoreParameters(
            methodTypes = listOf(PUSH),
            authToken = AuthorizationToken.Bearer(authToken.token),
            pushToken = params.registrationToken.get(),
            userVerificationEnabled = params.enableUserVerification,
            cibaEnabled = params.enableCiba
        )
        return if (myAccount) core.enrollMyAccount(config.baseUrl(), config.oidcClientId, coreParameters, null).fold(
            { Result.success(PushEnrollmentImpl(it, myAccount)) },
            { Result.failure(it) }
        ) else core.enroll(config.baseUrl(), config.oidcClientId, coreParameters, null).fold(
            { Result.success(PushEnrollmentImpl(it, myAccount)) },
            { Result.failure(it) }
        )
    }

    override suspend fun allEnrollments(): Result<List<PushEnrollment>> = core.getAllEnrollments().fold(
        { Result.success(it.map { core -> PushEnrollmentImpl(core, myAccount) }) },
        { Result.failure(it) }
    )
}
