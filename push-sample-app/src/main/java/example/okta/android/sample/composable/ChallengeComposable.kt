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
package example.okta.android.sample.composable

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.core.app.NotificationManagerCompat
import example.okta.android.sample.R
import example.okta.android.sample.app.ChallengeActivity
import example.okta.android.sample.app.ChallengeViewModel
import example.okta.android.sample.app.ChallengeViewModel.State.Error
import example.okta.android.sample.app.ChallengeViewModel.State.IncomingChallenge
import example.okta.android.sample.app.ChallengeViewModel.State.ProcessChallenge
import example.okta.android.sample.app.handleBiometric
import example.okta.android.sample.challenge.RemediationState
import example.okta.android.sample.errors.BiometricError
import example.okta.android.sample.model.UserResponse

@Composable
fun ChallengeComposable(finishAction: () -> Unit, viewModel: ChallengeViewModel) {
    val state by viewModel.uiState.collectAsState()

    with(state) {
        when (this) {
            ProcessChallenge -> Unit // Initial state no need to show UI
            is Error -> ErrorState(stringResource(id = R.string.unknown), throwable, finishAction)
            is IncomingChallenge -> {
                HandleIncomingChallenge(this, viewModel, finishAction)
            }
        }
    }
}

@Composable
fun HandleIncomingChallenge(incomingChallenge: IncomingChallenge, viewModel: ChallengeViewModel, finishAction: () -> Unit) {
    with(incomingChallenge) {
        val activity = LocalContext.current as ChallengeActivity
        NotificationManagerCompat.from(activity).cancel(previousChallengeId)
        when (remediationState) {
            is RemediationState.CompletedState -> ChallengeCompleted(finishAction)
            is RemediationState.UserConsentState -> {
                if (response == UserResponse.NONE) {
                    AcceptPushScreen(
                        remediationState.userConsent,
                        { viewModel.acceptOrDeny(true, remediationState.userConsent) },
                        { viewModel.acceptOrDeny(false, remediationState.userConsent) }
                    )
                } else viewModel.acceptOrDeny(response == UserResponse.ACCEPTED, remediationState.userConsent)
            }
            is RemediationState.UserVerificationState -> LaunchedEffect(remediationState) {
                runCatching {
                    val result = activity.handleBiometric(remediationState.userVerification.signature)
                    viewModel.userVerification(remediationState.userVerification, result)
                }.onFailure {
                    when (it) {
                        is BiometricError -> viewModel.userVerification(remediationState.userVerification, null, it)
                        else -> viewModel.onError(it)
                    }
                }
            }
            is RemediationState.UserVerificationErrorState -> viewModel.onError(remediationState.userVerificationError.securityError)
        }
    }
}
