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

import com.okta.devices.push.PushRemediation

sealed interface RemediationState {
    class CompletedState(val completed: PushRemediation.Completed) : RemediationState
    class UserConsentState(val userConsent: PushRemediation.UserConsent) : RemediationState
    class UserVerificationState(val userVerification: PushRemediation.UserVerification) : RemediationState
    class UserVerificationErrorState(val userVerificationError: PushRemediation.UserVerificationError) : RemediationState
}
