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

import com.okta.devices.api.model.Challenge
import com.okta.devices.push.PushRemediation

/**
 * Push specific MFA challenge interface. In addition to [Challenge] properties, this adds
 * additional push specific properties such as the operating system that initiated the challenge and
 * the location.
 */
interface PushChallenge : Challenge {
    /**
     * Localized location of the client sign-in attempt (e.g. "San Francisco, CA, USA")
     */
    val clientLocation: String

    /**
     * OS of the client sign-in attempt (e.g. "macOS")
     */
    val clientOs: String

    /**
     * Resolve a push challenge to get the [PushRemediation] steps required to complete the transaction.
     *
     * @return [Result] If successful [PushRemediation] step is returned.
     */
    override fun resolve(): Result<PushRemediation>
}
