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
package com.okta.devices.push

import com.okta.devices.api.errors.DeviceAuthenticatorError
import com.okta.devices.api.errors.DeviceAuthenticatorError.SecurityError.SecurityException
import com.okta.devices.api.errors.DeviceAuthenticatorError.SecurityError.UserVerificationRequired
import com.okta.devices.authenticator.model.ChallengeContext
import com.okta.devices.model.ErrorCode
import com.okta.devices.model.ErrorCode.USER_VERIFICATION_FAILED
import com.okta.devices.push.PushRemediation.UserConsent
import com.okta.devices.push.PushRemediation.UserVerification
import com.okta.devices.push.PushRemediation.UserVerificationError
import com.okta.devices.push.api.PushChallenge
import com.okta.devices.util.UserVerificationChallenge.PREFERRED
import com.okta.devices.util.UserVerificationChallenge.REQUIRED
import io.jsonwebtoken.security.SignatureException
import java.security.GeneralSecurityException
import java.security.InvalidKeyException
import java.security.KeyStoreException
import java.util.concurrent.TimeUnit

internal class PushChallengeImpl(private val ctx: ChallengeContext, private val allowedClockSkewInSeconds: Long) : PushChallenge {
    internal val info = ctx.challengeInformation
    override val clientLocation: String = info.clientLocation
    override val clientOs: String = info.clientOs

    override val originUrl: String = info.issuer
    override val transactionTime: String = info.transactionTime
    override val expiration: Long = info.expiration
    override val appInstanceName: String = info.appInstanceName

    private val validTime: Boolean
        get() {
            val clockSkewMillis = TimeUnit.SECONDS.toMillis(allowedClockSkewInSeconds)
            val now = ctx.baseEnrollment.timeProvider.currentTimeMillis()
            return now < (info.expiration + clockSkewMillis) &&
                now > (info.notBefore - clockSkewMillis)
        }

    override fun resolve(): Result<PushRemediation> = runCatching {
        val userVerification = info.userVerificationChallenge
        if (!validTime) return Result.failure(DeviceAuthenticatorError.SecurityError.InvalidToken(ErrorCode.INVALID_OR_EXPIRED_TOKEN.value, "Expired token, check device clock"))

        val remediation = when {
            userVerification == REQUIRED && !ctx.uvEnabled -> UserVerificationError(this, ctx, UserVerificationRequired(USER_VERIFICATION_FAILED.value, ""))
            (userVerification == PREFERRED && ctx.uvEnabled) || userVerification == REQUIRED -> UserVerification(this, ctx, ctx.baseEnrollment.userVerificationSignature())
            else -> UserConsent(this, ctx)
        }
        Result.success(remediation)
    }.getOrElse {
        when (it) {
            is SignatureException, is GeneralSecurityException, is KeyStoreException, is InvalidKeyException ->
                Result.success(UserVerificationError(this, ctx, SecurityException(USER_VERIFICATION_FAILED.value, "User verification failure", it)))
            else -> Result.failure(it)
        }
    }
}
