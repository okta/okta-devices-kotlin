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

import com.okta.devices.api.DeviceAuthenticator
import com.okta.devices.api.model.AuthToken
import com.okta.devices.api.model.DeviceAuthenticatorConfig
import com.okta.devices.api.model.EnrollmentParameters

/**
 * Interface for push authenticator operations.
 */
interface PushAuthenticator : DeviceAuthenticator {
    /**
     * Parse a push notification challenge
     *
     * @param challenge push notification challenge
     * @param allowedClockSkewInSeconds the amount of clock skew in seconds to tolerate when verifying
     * the local time against the exp and nbf claims. Default is set to 5 minutes
     * @return [Result] if successful the value will be [PushChallenge]
     */
    override suspend fun parseChallenge(challenge: String, allowedClockSkewInSeconds: Long): Result<PushChallenge>

    /**
     * Enroll push authenticator
     *
     * @param authToken Authorization token. See [AuthToken]
     * @param config config and auth token must be from the same oidcClient. See [DeviceAuthenticatorConfig]
     * @param params with registration token and user verification enabled. See [EnrollmentParameters]
     * @return [Result] if successful the value will be [PushEnrollment]
     */
    override suspend fun enroll(authToken: AuthToken, config: DeviceAuthenticatorConfig, params: EnrollmentParameters): Result<PushEnrollment>

    /**
     * Get a list of all of the authenticator's enrollments
     *
     * @return [Result] if successful the value will be a list of [PushEnrollment]
     */
    override suspend fun allEnrollments(): Result<List<PushEnrollment>>
}
