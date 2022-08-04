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
import com.okta.devices.push.PushRemediation
import example.okta.android.sample.Constants
import example.okta.android.sample.challenge.RemediationState
import example.okta.android.sample.challenge.handleAcceptOrDeny
import example.okta.android.sample.challenge.handleUserVerification
import example.okta.android.sample.challenge.remediationAsState
import example.okta.android.sample.client.AuthenticatorClient
import example.okta.android.sample.model.UserResponse
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import timber.log.Timber

/**
 * View model used by ChallengeComposable. ChallengeActivity is the owner of this viewmodel and pass this to ChallengeComposable.
 *
 * @property authenticatorClient
 * @property notificationId
 * @property challengeJws
 * @property response
 */
class ChallengeViewModel(
    private val authenticatorClient: AuthenticatorClient,
    private val notificationId: Int,
    private val challengeJws: String,
    private val response: UserResponse,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO
) : ViewModel() {

    class Factory(
        private val authenticatorClient: AuthenticatorClient,
        private val notificationId: Int,
        private val challengeJws: String,
        private val response: UserResponse
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T = ChallengeViewModel(authenticatorClient, notificationId, challengeJws, response) as T
    }

    sealed class State(val response: UserResponse = UserResponse.NONE) {
        object ProcessChallenge : State()
        class Error(val throwable: Throwable) : State()
        class IncomingChallenge(val remediationState: RemediationState, response: UserResponse, val previousChallengeId: Int = -1) : State(response)
    }

    private val uiStateFlow: MutableStateFlow<State> = MutableStateFlow(State.ProcessChallenge)

    val uiState = uiStateFlow.stateIn(viewModelScope, SharingStarted.Eagerly, uiStateFlow.value)

    init {
        start()
    }

    private fun start() = viewModelScope.launch(dispatcher) {
        runCatching {
            viewModelScope.launch {
                try {
                    withTimeout(Constants.TIME_OUT_MS) {
                        val challenge = authenticatorClient.handlePushChallenge(challengeJws).getOrThrow()
                        uiStateFlow.update {
                            State.IncomingChallenge(challenge.resolve().getOrThrow().remediationAsState(), response, notificationId)
                        }
                    }
                } catch (ex: TimeoutCancellationException) {
                    Timber.e(ex)
                }
            }
        }.getOrElse { onError(it) }
    }

    fun acceptOrDeny(accept: Boolean, userConsent: PushRemediation.UserConsent) = viewModelScope.launch(dispatcher) {
        userConsent.handleAcceptOrDeny(accept)
            .onSuccess { challengeState -> uiStateFlow.update { State.IncomingChallenge(challengeState, response) } }
            .onFailure { onError(it) }
    }

    fun userVerification(userVerification: PushRemediation.UserVerification, result: BiometricPrompt.AuthenticationResult?) = viewModelScope.launch(dispatcher) {
        userVerification.handleUserVerification(result)
            .onSuccess { challengeState -> uiStateFlow.update { State.IncomingChallenge(challengeState, response) } }
            .onFailure { onError(it) }
    }

    fun onError(throwable: Throwable) {
        Timber.e(throwable)
        uiStateFlow.update { State.Error(throwable) }
    }
}
