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

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.material.MaterialTheme
import androidx.compose.ui.graphics.Color
import androidx.core.view.WindowCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import example.okta.android.sample.Constants.CHALLENGE_JWS_KEY
import example.okta.android.sample.Constants.NOTIFICATION_ID_KEY
import example.okta.android.sample.Constants.USER_RESPONSE
import example.okta.android.sample.composable.ChallengeComposable
import example.okta.android.sample.model.UserResponse

/**
 * PushMessagingService creates the notification pending intent that starts the transparent ChallengeActivity.
 * This will bring the sample application to the foreground to process the push notification. A service and WorkManager can also be used to handle and process
 * the push message.
 */
class ChallengeActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val challengeJws = intent.getStringExtra(CHALLENGE_JWS_KEY) ?: ""
        val notificationId = intent.getIntExtra(NOTIFICATION_ID_KEY, 0)
        val response = intent.getStringExtra(USER_RESPONSE)

        if (response == null || challengeJws.isBlank()) { // only start this activity if we have a challenge
            finishAndRemoveTask()
            return
        }

        WindowCompat.setDecorFitsSystemWindows(window, false)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
            WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS
        )

        setContent {
            MaterialTheme(colors = MaterialTheme.colors.copy(primary = Color.Magenta)) {
                ChallengeComposable(
                    { finishAndRemoveTask() }, // navigate back should close this activity
                    viewModel(factory = ChallengeViewModel.Factory(app.authenticatorClient, notificationId, challengeJws, UserResponse.fromString(response)))
                )
            }
        }
    }

    override fun onBackPressed() {
        finishAndRemoveTask()
    }
}
