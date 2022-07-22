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
package example.okta.android.sample.model

import androidx.compose.ui.tooling.preview.PreviewParameterProvider

data class UserStatus(val userId: String, val userName: String, val pushEnabled: Boolean, val userVerification: Boolean)

class UserStatusPreview : PreviewParameterProvider<UserStatus> {
    override val values: Sequence<UserStatus> = sequenceOf(
        UserStatus("userId", "userName", pushEnabled = true, userVerification = true)
    )
}
