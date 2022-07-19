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
package example.okta.android.sample.service

import android.app.PendingIntent
import android.content.Intent
import android.graphics.Color
import androidx.core.app.NotificationChannelCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationCompat.DEFAULT_ALL
import androidx.core.app.NotificationCompat.PRIORITY_MAX
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.NotificationManagerCompat.IMPORTANCE_MAX
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import com.okta.devices.push.PushRemediation
import example.okta.android.sample.Constants
import example.okta.android.sample.Constants.ACCEPT_REQUEST_CODE
import example.okta.android.sample.Constants.CHALLENGE_KEY
import example.okta.android.sample.Constants.DENY_REQUEST_CODE
import example.okta.android.sample.Constants.NONE_REQUEST_CODE
import example.okta.android.sample.MyBankApplication
import example.okta.android.sample.R
import example.okta.android.sample.app.ChallengeActivity
import example.okta.android.sample.model.UserResponse
import example.okta.android.sample.model.UserResponse.ACCEPTED
import example.okta.android.sample.model.UserResponse.DENIED
import example.okta.android.sample.model.UserResponse.NONE
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart.LAZY
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import timber.log.Timber
import java.util.Random

class PushMessagingService : FirebaseMessagingService() {
    private val scope = CoroutineScope(Job() + Dispatchers.IO)
    private val notificationBuilder by lazy {
        val channelId = getString(R.string.default_notification_channel_id)
        val channelName = getString(R.string.push_notification_channel_name)
        val channel = NotificationChannelCompat.Builder(channelId, IMPORTANCE_MAX)
            .setShowBadge(true)
            .setName(channelName)
            .build()

        NotificationManagerCompat.from(this).createNotificationChannel(channel)

        NotificationCompat.Builder(this, channelId)
            .setSmallIcon(R.drawable.ic_icon)
            .setPriority(PRIORITY_MAX)
            .setColor(Color.WHITE)
            .setLocalOnly(false)
            .setDefaults(DEFAULT_ALL)
            .setAutoCancel(true)
    }

    private val deferredAuthenticator = scope.async(Dispatchers.Unconfined, start = LAZY) { (application as MyBankApplication).authenticatorClient }

    override fun onMessageReceived(remoteMessage: RemoteMessage) {
        if (!remoteMessage.data.containsKey(CHALLENGE_KEY)) {
            Timber.w("FCM message does not contain okta.challenge payload. Ignoring")
            return
        }

        remoteMessage.data[CHALLENGE_KEY]?.takeIf { it.isNotBlank() }?.let { challengeJws ->
            scope.launch {
                runCatching { onChallenge(challengeJws) }.getOrElse {
                    Timber.i(it, "Challenge resolution failed")
                }
            }
        } ?: Timber.w("FCM message contains invalid challenge payload. Ignoring")
    }

    override fun onNewToken(token: String) {
        scope.launch {
            val authenticator = deferredAuthenticator.await()
            runCatching {
                authenticator.updateRegistrationTokenForAll(token)
                    .onSuccess { Timber.d("FCM token refreshed") }
                    .onFailure { Timber.i(it, "FCM token update failed") }
            }.onFailure { Timber.i(it, "FCM token update failed") }
        }
    }

    private suspend fun onChallenge(challengeJws: String) {
        val pushChallenge = deferredAuthenticator.await().handlePushChallenge(challengeJws).getOrThrow()
        val notificationId = Random().nextInt() and Integer.MAX_VALUE
        when (val remediate = pushChallenge.resolve().getOrThrow()) {
            is PushRemediation.Completed -> Unit // do nothing
            is PushRemediation.UserConsent -> userConsent(remediate, notificationId, challengeJws)
            is PushRemediation.UserVerification, is PushRemediation.UserVerificationError -> userVerification(remediate, notificationId, challengeJws)
        }
    }

    private fun userVerification(userVerification: PushRemediation, notificationId: Int, jws: String) {
        val appName = userVerification.challenge.appInstanceName.takeIf { it.isNotBlank() }
            ?: userVerification.challenge.originUrl
        notificationBuilder
            .clearActions()
            .setContentTitle(getString(R.string.verify_sign_in_title))
            .setContentText(getString(R.string.verify_sign_in_body, appName))
            .setContentIntent(pendingChallengeIntent(notificationId, jws, NONE))
            .setTimeoutAfter(userVerification.challenge.expiration - System.currentTimeMillis())

        NotificationManagerCompat.from(this).notify(notificationId, notificationBuilder.build())
    }

    private fun userConsent(userConsent: PushRemediation.UserConsent, notificationId: Int, jws: String) {
        val appName = userConsent.challenge.appInstanceName.takeIf { it.isNotBlank() }
            ?: userConsent.challenge.originUrl

        notificationBuilder
            .clearActions()
            .setContentTitle(getString(R.string.push_notification_title, appName, userConsent.challenge.clientLocation))
            .setContentIntent(pendingChallengeIntent(notificationId, jws, NONE))
            .addAction(NotificationCompat.Action.Builder(R.drawable.notification_action_accept, getString(R.string.accept_text), pendingChallengeIntent(notificationId, jws, ACCEPTED)).build())
            .addAction(NotificationCompat.Action.Builder(R.drawable.notification_action_deny, getString(R.string.deny_text), pendingChallengeIntent(notificationId, jws, DENIED)).build())
            .setTimeoutAfter(userConsent.challenge.expiration - System.currentTimeMillis())

        NotificationManagerCompat.from(this).notify(notificationId, notificationBuilder.build())
    }

    private fun pendingChallengeIntent(notificationId: Int, jws: String, response: UserResponse): PendingIntent {
        val intent = Intent(this, ChallengeActivity::class.java).apply {
            putExtra(Constants.USER_RESPONSE, response.name)
            putExtra(Constants.CHALLENGE_JWS_KEY, jws)
            putExtra(Constants.NOTIFICATION_ID_KEY, notificationId)
            addFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION)
        }
        val code = when (response) {
            ACCEPTED -> ACCEPT_REQUEST_CODE
            DENIED -> DENY_REQUEST_CODE
            NONE -> NONE_REQUEST_CODE
        }
        return PendingIntent.getActivity(this, notificationId + code, intent, PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_IMMUTABLE)
    }
}
