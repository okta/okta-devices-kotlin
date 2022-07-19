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

import com.okta.devices.api.errors.DeviceAuthenticatorError.SecurityError.SecurityException
import com.okta.devices.api.errors.DeviceAuthenticatorError.SecurityError.UserVerificationRequired
import com.okta.devices.authenticator.exceptions.toResult
import com.okta.devices.authenticator.model.ChallengeContext
import com.okta.devices.model.ErrorCode
import com.okta.devices.model.ErrorResponse
import com.okta.devices.model.errorResponse
import com.okta.devices.push.PushRemediation.UserConsent
import com.okta.devices.push.PushRemediation.UserVerification
import com.okta.devices.push.PushRemediation.UserVerificationError
import com.okta.devices.push.api.PushChallenge
import com.okta.devices.request.DeviceResult
import com.okta.devices.request.DeviceResult.Success
import com.okta.devices.util.UserVerificationChallenge
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

        val deviceResult =
            if (!validTime) DeviceResult.Error(ErrorResponse(ErrorCode.INVALID_OR_EXPIRED_TOKEN.value, "Expired token, check device clock"))
            else if (userVerification == UserVerificationChallenge.REQUIRED && !ctx.uvEnabled) {
                Success(UserVerificationError(this, ctx, UserVerificationRequired(ErrorCode.USER_VERIFICATION_FAILED.value, "")))
            } else if ((userVerification == UserVerificationChallenge.PREFERRED && ctx.uvEnabled) || userVerification == UserVerificationChallenge.REQUIRED) {
                Success(UserVerification(this, ctx, ctx.baseEnrollment.userVerificationSignature()))
            } else Success(UserConsent(this, ctx))
        deviceResult.toResult()
    }.getOrElse {
        if (it is SignatureException || it is GeneralSecurityException || it is KeyStoreException || it is InvalidKeyException) {
            val error = it.errorResponse()
            Result.success(UserVerificationError(this, ctx, SecurityException(error.errorCode, error.errorSummary ?: "", error.exception)))
        } else Result.failure(it)
    }
}
