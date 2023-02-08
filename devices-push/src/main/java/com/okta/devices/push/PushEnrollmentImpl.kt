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

import com.okta.devices.AuthenticatorEnrollmentCore
import com.okta.devices.api.AuthenticatorEnrollment
import com.okta.devices.api.errors.DeviceAuthenticatorError.InternalDeviceError
import com.okta.devices.api.model.AuthToken
import com.okta.devices.api.model.RegistrationToken
import com.okta.devices.authenticator.AuthenticatorEnrollmentImpl
import com.okta.devices.authenticator.model.ChallengeContext
import com.okta.devices.model.AuthorizationToken
import com.okta.devices.model.ErrorCode.EXCEPTION
import com.okta.devices.push.api.PushChallenge
import com.okta.devices.push.api.PushEnrollment

internal class PushEnrollmentImpl(
    private val enrollmentCore: AuthenticatorEnrollmentCore,
    private val myAccount: Boolean = false,
) : PushEnrollment, AuthenticatorEnrollment by AuthenticatorEnrollmentImpl(enrollmentCore, myAccount) {

    override suspend fun updateRegistrationToken(authToken: AuthToken, registrationToken: RegistrationToken): Result<String> {
        return if (myAccount) enrollmentCore.patchRegistrationToken(AuthorizationToken.Bearer(authToken.token), registrationToken.get())
        else enrollmentCore.updateRegistrationToken(AuthorizationToken.Bearer(authToken.token), registrationToken.get())
    }

    override suspend fun retrievePushChallenges(authToken: AuthToken, allowedClockSkewInSeconds: Long): Result<List<PushChallenge>> =
        enrollmentCore.retrievePushChallenges(AuthorizationToken.Bearer(authToken.token), allowedClockSkewInSeconds).fold(
            { Result.success(it.map { info -> PushChallengeImpl(ChallengeContext(info, enrollmentCore), allowedClockSkewInSeconds) }) },
            { Result.failure(it) }
        )

    override suspend fun retrieveMaintenanceToken(scope: List<String>, authorizationServerId: String?): Result<AuthToken> {
        if (scope.isEmpty()) return Result.failure(InternalDeviceError(EXCEPTION.value, "Empty scope", IllegalArgumentException("No scope specified")))
        return enrollmentCore.getToken(scope.joinToString(separator = " "), authorizationServerId?.takeIf { it.isNotBlank() })
            .fold({ Result.success(AuthToken.Bearer(it.accessToken)) }, { Result.failure(it) })
    }
}
