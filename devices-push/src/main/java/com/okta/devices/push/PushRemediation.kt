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

import androidx.biometric.BiometricPrompt.AuthenticationResult
import com.okta.devices.api.errors.DeviceAuthenticatorError.SecurityError
import com.okta.devices.api.model.CompletionState
import com.okta.devices.api.model.Remediation
import com.okta.devices.authenticator.model.ChallengeContext
import com.okta.devices.push.api.PushChallenge
import com.okta.devices.util.ConsentResponse
import com.okta.devices.util.ConsentResponse.APPROVED_CONSENT_PROMPT
import com.okta.devices.util.ConsentResponse.APPROVED_USER_VERIFICATION
import com.okta.devices.util.ConsentResponse.CANCELLED_USER_VERIFICATION
import com.okta.devices.util.ConsentResponse.UV_PERMANENTLY_UNAVAILABLE
import com.okta.devices.util.ConsentResponse.UV_TEMPORARILY_UNAVAILABLE
import com.okta.devices.util.UserVerificationChallenge
import java.security.Signature

/**
 * Represent different states of the push challenge remediation.
 *
 * @property challenge Push MFA challenge that the remediation is operation on.
 */
sealed class PushRemediation(override val challenge: PushChallenge, internal val ctx: ChallengeContext) : Remediation {

    /**
     * Sign the push MFA challenge and respond to the server that the challenge is denied.
     *
     * @param exp Set the expiration time in minutes of the signed jwt. The default is 5 minutes
     * @return [Result] If successful a completed [Remediation].
     */
    override suspend fun deny(exp: Long): Result<PushRemediation> = ctx.copy(consentResponse = ConsentResponse.DENIED_CONSENT_PROMPT).verify(exp).fold(
        { Result.success(Completed(challenge, ctx, it)) },
        { Result.failure(it) }
    )

    /**
     * Completed remediation represents a successful transaction with the authenticator.
     *
     * @property state The completion state. See [CompletionState] for status
     */
    class Completed internal constructor(challenge: PushChallenge, context: ChallengeContext, val state: CompletionState) : PushRemediation(challenge, context)

    /**
     * Remediation step requires a user interaction to accept or deny the challenge, used for LOGIN transaction type
     */
    class UserConsent internal constructor(challenge: PushChallenge, context: ChallengeContext) : PushRemediation(challenge, context) {
        /**
         * Sign the push MFA challenge and respond to the server that the challenge is accepted.
         *
         * @param exp Set the expiration time in minutes of the signed jwt. The default is 5 minutes
         * @return [Result] If successful a completed [Remediation].
         */
        suspend fun accept(exp: Long = 5L): Result<PushRemediation> {
            val acceptedCtx = if (ctx.consentResponse != APPROVED_USER_VERIFICATION) ctx.copy(consentResponse = APPROVED_CONSENT_PROMPT) else ctx
            return acceptedCtx.verify(exp).fold(
                { Result.success(Completed(challenge, acceptedCtx, it)) },
                { Result.failure(it) }
            )
        }
    }

    /**
     * Remediation step requires a user interaction to accept or deny the challenge, used for CIBA transaction type
     */
    class CibaConsent internal constructor(challenge: PushChallenge, context: ChallengeContext) : PushRemediation(challenge, context) {
        /**
         * A binding message is an identifier that help user to ensure that the action taken during remediation is related to the request initiated by the consumption devices.
         * You can use any human-readable random value (e.g. a transactional approval code) for this message
         * Display this message on both the consumption device and authentication device for user to do a visual inspection before confirm any authentication attempt
         */
        val bindingMessage: String = context.challengeInformation.bindingMessage

        /**
         * Sign the push CIBA request and respond to the server that the request is accepted.
         *
         * @param exp Set the expiration time in minutes of the signed jwt. The default is 5 minutes
         * @return [Result] If successful a completed [Remediation].
         */
        suspend fun accept(exp: Long = 5L): Result<PushRemediation> {
            val acceptedCtx = if (ctx.consentResponse != APPROVED_USER_VERIFICATION) ctx.copy(consentResponse = APPROVED_CONSENT_PROMPT) else ctx
            return acceptedCtx.verify(exp).fold(
                { Result.success(Completed(challenge, acceptedCtx, it)) },
                { Result.failure(it) }
            )
        }
    }

    /**
     * Remediation step for errors related to user verification. Inspect the [securityError] for the reason of the failure.
     *
     * @property securityError
     */
    class UserVerificationError internal constructor(challenge: PushChallenge, context: ChallengeContext, val securityError: SecurityError) : PushRemediation(challenge, context) {
        /**
         * Resolve the error to allow the user to continue the sign-in attempt.
         *
         * @param consentOnFailure Set this true to ask for [UserConsent] if user verification continue to fail. Depending on the policy, the server may reject the sign-in attempt even
         * if the user accepts the challenge remediation.
         * @return [Result] If successful the next [Remediation] step.
         */
        fun resolve(consentOnFailure: Boolean = true): Result<PushRemediation> = runCatching {
            Result.success(UserVerification(challenge, ctx, ctx.baseEnrollment.userVerificationSignature()))
        }.getOrElse {
            if (consentOnFailure) Result.success(if (ctx.cibaEnabled)CibaConsent(challenge, ctx) else UserConsent(challenge, ctx)) else Result.failure(it)
        }
    }

    /**
     * Remediation step that requires user verification.
     *
     * @property signature Optional signature is provided to the application. This is used for constructing a CryptoObject for biometric prompt.
     */
    class UserVerification internal constructor(challenge: PushChallenge, context: ChallengeContext, val signature: Signature? = null) : PushRemediation(challenge, context) {
        /**
         * Resolve the user verification step.
         *
         * @param authResult The [AuthenticationResult] from a successful biometric prompt.
         * @return [Result] If successful the next [Remediation] step.
         */
        fun resolve(authResult: AuthenticationResult): Result<PushRemediation> {
            val authedCtx = ctx.copy(authResult = authResult, consentResponse = APPROVED_USER_VERIFICATION)
            return Result.success(if (ctx.cibaEnabled)CibaConsent(challenge, authedCtx) else UserConsent(challenge, authedCtx))
        }

        /**
         * Cancels the user verification step and ask for user approval instead.
         *
         * @return [Result] If successful the next [Remediation] step will be [UserConsent]
         */
        fun cancel(): Result<PushRemediation> {
            val authedCtx = ctx.copy(consentResponse = CANCELLED_USER_VERIFICATION)
            return Result.success(if (ctx.cibaEnabled)CibaConsent(challenge, authedCtx) else UserConsent(challenge, authedCtx))
        }

        /**
         * Biometric is temporary unavailable due to lock up, ask for user approval instead
         *
         * @return [Result] if successful the next [Remediation] step will be [UserConsent]
         */
        fun temporarilyUnavailable(): Result<PushRemediation> {
            val authedCtx = if (ctx.challengeInformation.userVerificationChallenge == UserVerificationChallenge.REQUIRED) ctx.copy(consentResponse = UV_TEMPORARILY_UNAVAILABLE)
            else ctx.copy(consentResponse = CANCELLED_USER_VERIFICATION)
            return Result.success(if (ctx.cibaEnabled)CibaConsent(challenge, authedCtx) else UserConsent(challenge, authedCtx))
        }

        /**
         * Biometric is removed from device, ask for user approval instead
         *
         * @return [Result] if successful the next [Remediation] step will be [UserConsent]
         */
        fun permanentlyUnavailable(): Result<PushRemediation> {
            val authedCtx = if (ctx.challengeInformation.userVerificationChallenge == UserVerificationChallenge.REQUIRED) ctx.copy(consentResponse = UV_PERMANENTLY_UNAVAILABLE)
            else ctx.copy(consentResponse = CANCELLED_USER_VERIFICATION)
            return Result.success(if (ctx.cibaEnabled)CibaConsent(challenge, authedCtx) else UserConsent(challenge, authedCtx))
        }

        /**
         * Sign the push MFA challenge and respond to the server that the challenge is denied.
         *
         * @param exp Set the expiration time in minutes of the signed jwt. The default is 5 minutes
         * @return [Result] If successful a completed [Remediation].
         */
        override suspend fun deny(exp: Long): Result<PushRemediation> = ctx.copy(consentResponse = CANCELLED_USER_VERIFICATION).verify(exp).fold(
            { Result.success(Completed(challenge, ctx, it)) },
            { Result.failure(it) }
        )
    }
}
