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
package example.okta.android.sample.app

import androidx.biometric.BiometricPrompt
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.google.firebase.messaging.FirebaseMessaging
import com.okta.devices.api.model.EnrollmentParameters
import com.okta.devices.api.model.RegistrationToken
import com.okta.devices.push.PushRemediation
import example.okta.android.sample.challenge.RemediationState
import example.okta.android.sample.challenge.handleAcceptOrDeny
import example.okta.android.sample.challenge.handleUserVerification
import example.okta.android.sample.challenge.remediationAsState
import example.okta.android.sample.client.AuthenticatorClient
import example.okta.android.sample.client.OktaOidcClient
import example.okta.android.sample.model.UserStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.asDeferred
import timber.log.Timber

class MainViewModel(
    private val authenticatorClient: AuthenticatorClient,
    private val oidcClient: OktaOidcClient
) : ViewModel() {

    class Factory(private val authenticatorClient: AuthenticatorClient, private val oidcClient: OktaOidcClient) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T = MainViewModel(authenticatorClient, oidcClient) as T
    }

    sealed class State {
        object Loading : State()
        object SignIn : State()
        object SignedOut : State()
        class SetupPush(val userStatus: UserStatus) : State()
        class StatusUpdate(val userStatus: UserStatus) : State()
        class Error(val throwable: Throwable) : State()
        class RemediationStatus(val remediationState: RemediationState) : State()
    }

    private val uiStateFlow: MutableStateFlow<State> = MutableStateFlow(State.Loading)

    val uiState = uiStateFlow.stateIn(viewModelScope, SharingStarted.Eagerly, uiStateFlow.value)

    init {
        // check for pending challenges on app start
        refresh(true)
    }

    fun refresh(checkPending: Boolean) {
        uiStateFlow.update { State.Loading }
        viewModelScope.launch(Dispatchers.IO) {
            oidcClient.getSignedInUser().onSuccess { userStatus ->
                authenticatorClient.getEnrollment(userStatus.userId)
                    .onSuccess { enrollment ->
                        uiStateFlow.update { State.StatusUpdate(userStatus.copy(pushEnabled = true, userVerification = enrollment.userVerificationEnabled())) }
                        if (checkPending) {
                            authenticatorClient.retrievePendingChallenges()
                                .onSuccess {
                                    // If the user initiates multiple MFA attempts, retrievePushChallenges may contain multiple challenges.
                                    // This sample is only handling the first.
                                    it.firstOrNull()?.let { challenge ->
                                        challenge.resolve()
                                            .onSuccess { remediation -> uiStateFlow.update { State.RemediationStatus(remediation.remediationAsState()) } }
                                            .onFailure { throwable -> Timber.i(throwable, "resolve pending challenge failed") }
                                    }
                                }.onFailure { Timber.i(it, "retrievePendingChallenges failed") }
                        }
                    }.onFailure { uiStateFlow.update { State.StatusUpdate(userStatus) } }
            }.onFailure { uiStateFlow.update { State.SignIn } }
        }
    }

    fun signIn(activity: MainActivity) = viewModelScope.launch(Dispatchers.IO) {
        uiStateFlow.update { State.Loading }
        oidcClient.oidcAuthenticate(activity)
            .onSuccess { userStatus -> uiStateFlow.update { State.SetupPush(userStatus) } }
            .onFailure { onError(it) }
    }

    fun enablePush(userStatus: UserStatus, enableUv: Boolean) = viewModelScope.launch(Dispatchers.IO) {
        uiStateFlow.update { State.Loading }
        runCatching {
            val token = FirebaseMessaging.getInstance().token.asDeferred().await()
            authenticatorClient.enroll(userStatus.userId, EnrollmentParameters.Push(RegistrationToken.FcmToken(token), enableUv))
                .onSuccess { uiStateFlow.update { State.StatusUpdate(userStatus.copy(pushEnabled = true, userVerification = enableUv)) } }
                .onFailure { onError(it) }
        }.getOrElse { onError(it) }
    }

    fun disablePush(userStatus: UserStatus) = viewModelScope.launch(Dispatchers.IO) {
        uiStateFlow.update { State.Loading }
        runCatching {
            authenticatorClient.delete(userStatus.userId)
                .onSuccess { uiStateFlow.update { State.StatusUpdate(userStatus.copy(pushEnabled = false, userVerification = false)) } }
                .onFailure { onError(it) }
        }
    }

    fun updateUserVerification(userStatus: UserStatus, enableUv: Boolean) = viewModelScope.launch(Dispatchers.IO) {
        uiStateFlow.update { State.Loading }
        runCatching {
            authenticatorClient.updateUserVerification(enableUv, userStatus.userId)
                .onSuccess { uiStateFlow.update { State.StatusUpdate(userStatus.copy(userVerification = enableUv)) } }
                .onFailure { onError(it) }
        }.getOrElse { onError(it) }
    }

    fun acceptOrDeny(accept: Boolean, userConsent: PushRemediation.UserConsent) = viewModelScope.launch(Dispatchers.IO) {
        userConsent.handleAcceptOrDeny(accept)
            .onSuccess { remediationState -> uiStateFlow.update { State.RemediationStatus(remediationState) } }
            .onFailure { onError(it) }
    }

    fun userVerification(userVerification: PushRemediation.UserVerification, result: BiometricPrompt.AuthenticationResult?) = viewModelScope.launch(Dispatchers.IO) {
        userVerification.handleUserVerification(result)
            .onSuccess { remediationState -> uiStateFlow.update { State.RemediationStatus(remediationState) } }
            .onFailure { onError(it) }
    }

    fun signOut(userId: String) = viewModelScope.launch(Dispatchers.IO) {
        authenticatorClient.delete(userId).onSuccess {
            oidcClient.revokeToken(userId)
                .onSuccess {
                    oidcClient.deleteSession(userId)
                    uiStateFlow.update { State.SignedOut }
                }
                .onFailure { onError(it) }
        }.onFailure { onError(it) }
    }

    fun onError(throwable: Throwable) {
        Timber.e(throwable)
        uiStateFlow.update { State.Error(throwable) }
    }
}
