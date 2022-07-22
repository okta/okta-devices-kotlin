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
package com.okta.devices.push.utils

import androidx.biometric.BiometricPrompt.AuthenticationResult
import com.okta.devices.api.errors.DeviceAuthenticatorError.SecurityError
import com.okta.devices.api.model.Challenge
import com.okta.devices.push.PushRemediation

class RemediationHandler(private val userInteraction: UserInteraction) {
    // Mock the user interaction
    interface UserInteraction {
        fun confirm(challenge: Challenge): Boolean
        fun userVerification(challenge: Challenge): AuthenticationResult?
        fun fixUserVerificationError(securityError: SecurityError): Boolean
    }

    tailrec suspend fun handleRemediation(remediate: PushRemediation): Result<PushRemediation> {
        val result = when (remediate) {
            is PushRemediation.Completed -> Result.success(remediate)
            is PushRemediation.UserConsent -> if (userInteraction.confirm(remediate.challenge)) remediate.accept() else remediate.deny()
            is PushRemediation.UserVerification -> userInteraction.userVerification(remediate.challenge)?.run { remediate.resolve(this) } ?: remediate.deny()
            is PushRemediation.UserVerificationError -> if (userInteraction.fixUserVerificationError(remediate.securityError)) remediate.resolve() else remediate.deny()
        }
        val latestRemediation = result.getOrThrow()
        return if (latestRemediation is PushRemediation.Completed) result else handleRemediation(latestRemediation)
    }
}
