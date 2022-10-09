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
package com.okta.devices.push.domain

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.okta.devices.data.repository.MethodType.PUSH
import com.okta.devices.device.signals.data.Collect
import com.okta.devices.device.signals.data.SignalProviderEntry
import com.okta.devices.fake.generator.JwtGenerator
import com.okta.devices.fake.generator.JwtGenerator.createIdxPushJws
import com.okta.devices.fake.util.FakeKeyStore
import com.okta.devices.fake.util.uuid
import com.okta.devices.model.local.ChallengeInformation
import com.okta.devices.push.utils.BaseTest
import com.okta.devices.util.TransactionType
import com.okta.devices.util.UserMediationChallenge
import com.okta.devices.util.UserVerificationChallenge
import io.jsonwebtoken.Jwts
import org.hamcrest.CoreMatchers.`is`
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Date
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class ChallengeInformationTest : BaseTest() {
    private val keyStore: FakeKeyStore = FakeKeyStore()
    private val serverKey = keyStore.serverKeyPair.private
    private val serverPubKey = keyStore.serverKeyPair.public
    private val serverKid = keyStore.serverKeyAlias

    @Test
    fun `parse challenge jws expect values match in challenge information`() {
        // arrange
        val issuer = "https://hityme.okta.com"
        val authenticatorEnrollmentId = uuid()
        val methodEnrollmentId = uuid()
        val aud = uuid()
        val iat = System.currentTimeMillis()
        val nbf = iat - TimeUnit.MINUTES.toMillis(5)
        val exp = iat + TimeUnit.MINUTES.toMillis(5)
        val method = PUSH
        val transactionId = uuid()
        val transactionType = TransactionType.LOGIN
        val bindingMessage = "bindingMessage"
        val transactionTime = Date(System.currentTimeMillis()).toString()
        val clientLocation = "San Francisco, CA, USA"
        val clientOs = "Mac OS X"
        val keyTypes = listOf("userVerification", "proofOfPossession")
        val riskLevel = "HIGH"
        val challengeTextItems = listOf("1", "2", "3")
        val unusualActivities = listOf("ANOMALOUS_DEVICE", "ANOMALOUS_LOCATION")
        val requestReferrer = "https://hityme.okta.com"
        val appInstanceName = "HiTyme"
        val userMediationChallenge = UserMediationChallenge.REQUIRED
        val userVerificationChallenge = UserVerificationChallenge.PREFERRED
        val requiredSignals = JwtGenerator.signalClaims
        val requiredSignalProviders = JwtGenerator.signalProvider
        val loginHint: String = uuid()
        val orgId: String = uuid()
        val userId: String = uuid()

        val pushJws = createIdxPushJws(
            serverKey, serverKid, issuer, authenticatorEnrollmentId, methodEnrollmentId, aud,
            iat, nbf, exp, method, transactionId, transactionType, bindingMessage, transactionTime, clientLocation, clientOs,
            keyTypes, riskLevel, challengeTextItems, unusualActivities, requestReferrer, appInstanceName,
            userMediationChallenge, userVerificationChallenge, requiredSignals, requiredSignalProviders,
            loginHint, orgId, userId
        )
        val claims = Jwts.parserBuilder().setSigningKey(serverPubKey).build().parseClaimsJws(pushJws).body

        // act
        val challengeInfo = ChallengeInformation.parse(claims)

        // assert
        assertThat(challengeInfo.issuer, `is`(issuer))
        assertThat(challengeInfo.authenticatorEnrollmentId, `is`(authenticatorEnrollmentId))
        assertThat(challengeInfo.methodEnrollmentId, `is`(methodEnrollmentId))
        assertThat(challengeInfo.aud, `is`(aud))
        assertThat(Date(challengeInfo.issuedAt).toString(), `is`(Date(iat).toString()))
        assertThat(Date(challengeInfo.notBefore).toString(), `is`(Date(nbf).toString()))
        assertThat(Date(challengeInfo.expiration).toString(), `is`(Date(exp).toString()))
        assertThat(challengeInfo.method, `is`(method))
        assertThat(challengeInfo.transactionId, `is`(transactionId))
        assertThat(challengeInfo.transactionType, `is`(transactionType))
        assertThat(challengeInfo.bindingMessage, `is`(bindingMessage))
        assertThat(challengeInfo.transactionTime, `is`(transactionTime))
        assertThat(challengeInfo.clientLocation, `is`(clientLocation))
        assertThat(challengeInfo.clientOs, `is`(clientOs))
        assertThat(challengeInfo.riskLevel, `is`(riskLevel))
        assertThat(challengeInfo.challengeItems, `is`(challengeTextItems))
        assertThat(challengeInfo.unusualActivities, `is`(unusualActivities))
        assertThat(challengeInfo.requestReferrer, `is`(requestReferrer))
        assertThat(challengeInfo.appInstanceName, `is`(appInstanceName))
        assertThat(challengeInfo.userMediationChallenge, `is`(userMediationChallenge))
        assertThat(challengeInfo.userVerificationChallenge, `is`(userVerificationChallenge))
        assertThat(challengeInfo.requiredSignals, `is`(requiredSignals["signals"]))
        assertThat(
            challengeInfo.requiredSignalProviders,
            `is`(
                listOf(
                    SignalProviderEntry("com.okta.device.integrity", Collect.REQUIRED),
                    SignalProviderEntry("com.okta.device.attestation", Collect.REQUIRED),
                    SignalProviderEntry("com.okta.device.malware", Collect.REQUIRED)
                )
            )
        )
        assertThat(challengeInfo.loginHint, `is`(loginHint))
        assertThat(challengeInfo.orgId, `is`(orgId))
        assertThat(challengeInfo.userId, `is`(userId))
    }
}
