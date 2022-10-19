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
package example.okta.android.sample.challenge

import androidx.biometric.BiometricPrompt
import com.okta.devices.push.PushRemediation
import com.okta.devices.push.PushRemediation.CibaConsent
import com.okta.devices.push.PushRemediation.UserConsent
import com.okta.devices.push.PushRemediation.UserVerification
import example.okta.android.sample.errors.BiometricError
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Wrap the PushRemediation as a ViewModel state. The state can then be passed to the UI layer
 *
 * @return ChallengeState
 */
fun PushRemediation.remediationAsState(): RemediationState = when (this) {
    is PushRemediation.Completed -> RemediationState.CompletedState(this)
    is UserConsent -> RemediationState.UserConsentState(this)
    is PushRemediation.CibaConsent -> RemediationState.CibaConsentState(this)
    is UserVerification -> RemediationState.UserVerificationState(this)
    is PushRemediation.UserVerificationError -> RemediationState.UserVerificationErrorState(this)
}

suspend fun UserConsent.handleAcceptOrDeny(accept: Boolean): Result<RemediationState> {
    val result = if (accept) accept() else deny()
    return result.fold({ Result.success(it.remediationAsState()) }, { Result.failure(it) })
}

suspend fun CibaConsent.handleAcceptOrDeny(accept: Boolean): Result<RemediationState> {
    val result = if (accept) accept() else deny()
    return result.fold({ Result.success(it.remediationAsState()) }, { Result.failure(it) })
}

suspend fun UserVerification.handleUserVerification(
    result: BiometricPrompt.AuthenticationResult?,
    dispatcher: CoroutineDispatcher = Dispatchers.IO,
    biometricError: BiometricError? = null
): Result<RemediationState> {
    return result?.let { authenticationResult ->
        resolve(authenticationResult)
            .fold({ pushRemediation ->
                // Accept since user already confirmed, we can also ask for approval.
                if (pushRemediation is UserConsent) {
                    withContext(dispatcher) { pushRemediation.accept().fold({ Result.success(it.remediationAsState()) }, { Result.failure(it) }) }
                } else Result.success(pushRemediation.remediationAsState())
            }, { Result.failure(it) })
    } ?: when (biometricError) {
        is BiometricError.TemporaryUnavailable -> temporarilyUnavailable().fold({ Result.success(it.remediationAsState()) }, { Result.failure(it) })
        is BiometricError.PermanentlyUnavailable -> permanentlyUnavailable().fold({ Result.success(it.remediationAsState()) }, { Result.failure(it) })
        else -> cancel().fold({ Result.success(it.remediationAsState()) }, { Result.failure(it) })
    }
}
