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
package com.okta.devices.push.api

import com.okta.devices.api.AuthenticatorEnrollment
import com.okta.devices.api.model.AuthToken
import com.okta.devices.api.model.RegistrationToken

/**
 * In addition to [AuthenticatorEnrollment] methods, this adds push specific enrollment options such as checking the server for
 * existing challenges and updating the device registration token.
 */
interface PushEnrollment : AuthenticatorEnrollment {

    /**
     * update push token for this enrollment
     *
     * @param authToken
     * @param registrationToken type of token see [RegistrationToken] for possible values
     * @return [Result] if successful the value with be the registration token
     */
    suspend fun updateRegistrationToken(authToken: AuthToken, registrationToken: RegistrationToken): Result<String>

    /**
     * Check for pending push challenges
     *
     * @param authToken
     * @param allowedClockSkewInSeconds the amount of clock skew in seconds to tolerate when verifying
     * the local time against the exp and nbf claims. Default is set to 5 minutes
     * @return [Result] if successful the value will be a list of [PushChallenge]
     */
    suspend fun retrievePushChallenges(authToken: AuthToken, allowedClockSkewInSeconds: Long = 300L): Result<List<PushChallenge>>
}
