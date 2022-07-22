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

import android.app.Activity
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.ERROR_NEGATIVE_BUTTON
import androidx.biometric.BiometricPrompt.ERROR_USER_CANCELED
import example.okta.android.sample.MyBankApplication
import example.okta.android.sample.R
import example.okta.android.sample.errors.BiometricError
import kotlinx.coroutines.suspendCancellableCoroutine
import timber.log.Timber
import java.security.Signature
import java.util.concurrent.Executors
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

val Activity.app: MyBankApplication
    get() = applicationContext as MyBankApplication

suspend fun AppCompatActivity.handleBiometric(signature: Signature?): BiometricPrompt.AuthenticationResult? = suspendCancellableCoroutine { continuation ->
    val biometricPrompt = BiometricPrompt(
        this,
        Executors.newSingleThreadExecutor(),
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                Timber.e("onAuthenticatorError $errorCode $errString")
                val exception = when (errorCode) {
                    ERROR_USER_CANCELED, ERROR_NEGATIVE_BUTTON -> BiometricError.UserCancel(errorCode, errString)
                    else -> BiometricError.Error(errorCode, errString)
                }
                continuation.resumeWithException(exception)
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = continuation.resume(result)
            override fun onAuthenticationFailed() {
                Timber.w("Authenticator failed")
            }
        }
    )

    continuation.invokeOnCancellation { biometricPrompt.cancelAuthentication() }

    val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
        .setTitle(getString(R.string.biometric_confirm))
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .setConfirmationRequired(true)
        .setNegativeButtonText(getString(R.string.cancel))

    val promptInfo = promptInfoBuilder.build()
    signature?.run {
        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(this))
    } ?: biometricPrompt.authenticate(promptInfo)
}
