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
package example.okta.android.sample

object Constants {
    const val NOTIFICATION_ID_KEY = "notificationId"
    const val CHALLENGE_JWS_KEY = "challengeJws"
    const val CHALLENGE_KEY = "okta.challenge"
    const val ACCEPT_REQUEST_CODE = 1
    const val DENY_REQUEST_CODE = 2
    const val NONE_REQUEST_CODE = 3
    const val USER_RESPONSE = "user_response"
    const val TIME_OUT_MS = 10000L // 10s timeout for getting and responding to challenge
    const val DISMISS_DELAY_MS = 1000L // auto dismiss dialog delay

    const val TEXT_STYLE_COLOR = 0xFF6750A4
    const val CONTENT_COLOR = 0xFFFFFBFE
    const val FILLER_COLOR = 0xFFEADDFF
}
