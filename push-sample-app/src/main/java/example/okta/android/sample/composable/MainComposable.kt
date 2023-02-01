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
import example.okta.android.sample.R
import example.okta.android.sample.app.MainActivity
import example.okta.android.sample.app.MainViewModel
import example.okta.android.sample.app.handleBiometric
import example.okta.android.sample.challenge.RemediationState
import example.okta.android.sample.errors.BiometricError

@Composable
fun MainComposable(viewModel: MainViewModel) {
    val state by viewModel.uiState.collectAsState()
    val activity = LocalContext.current as MainActivity

    with(state) {
        when (this) {
            MainViewModel.State.Loading -> LoadingState()
            MainViewModel.State.SignIn, MainViewModel.State.SignedOut -> SignInScreen { viewModel.signIn(activity) }
            is MainViewModel.State.SetupPush -> SetupPushScreen({ viewModel.refresh(false) }, { enableUv -> viewModel.enablePush(userStatus, enableUv) })
            is MainViewModel.State.Error -> ErrorState(throwable = throwable) { viewModel.refresh(false) }
            is MainViewModel.State.StatusUpdate -> HomeScreen(
                userStatus,
                { viewModel.enablePush(userStatus, false) },
                { enableUv -> viewModel.updateUserVerification(userStatus, enableUv) },
                { viewModel.disablePush(userStatus) },
                updateCibaAction = { enableCiba -> viewModel.updateCibaTransaction(userStatus, enableCiba) },
                { viewModel.signOut(userStatus.userId) },
                { viewModel.refresh(true) }
            )
            is MainViewModel.State.RemediationStatus -> HandleRemediate(remediationState, viewModel, activity)
        }
    }
}

@Composable
private fun HandleRemediate(remediationState: RemediationState, viewModel: MainViewModel, activity: MainActivity) = when (remediationState) {
    is RemediationState.CompletedState -> ChallengeCompleted { viewModel.refresh(false) }
    is RemediationState.UserConsentState ->
        AcceptPushScreen(
            remediationState.userConsent,
            { viewModel.acceptOrDeny(true, remediationState.userConsent) },
            { viewModel.acceptOrDeny(false, remediationState.userConsent) }
        )
    is RemediationState.CibaConsentState ->
        AcceptCibaPushScreen(
            remediationState.cibaConsent,
            { viewModel.acceptOrDeny(true, remediationState.cibaConsent) },
            { viewModel.acceptOrDeny(false, remediationState.cibaConsent) }
        )
    is RemediationState.UserVerificationErrorState -> ErrorState(stringResource(R.string.unknown_error), remediationState.userVerificationError.securityError.cause) {
        viewModel.refresh(false)
    }
    is RemediationState.UserVerificationState -> LaunchedEffect(remediationState) {
        runCatching {
            val result = activity.handleBiometric(remediationState.userVerification.signature)
            viewModel.userVerification(remediationState.userVerification, result)
        }.onFailure {
            if (it is BiometricError.UserCancel || it is BiometricError.Error) viewModel.userVerification(remediationState.userVerification, null)
            else viewModel.onError(it)
        }
    }
}
