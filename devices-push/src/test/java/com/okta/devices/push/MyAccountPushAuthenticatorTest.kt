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

import android.content.Context
import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.AuthenticationResult
import androidx.test.core.app.ApplicationProvider.getApplicationContext
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.okta.devices.api.errors.DeviceAuthenticatorError
import com.okta.devices.api.errors.DeviceAuthenticatorError.InternalDeviceError
import com.okta.devices.api.errors.DeviceAuthenticatorError.SecurityError.InvalidToken
import com.okta.devices.api.errors.DeviceAuthenticatorError.SecurityError.UserVerificationRequired
import com.okta.devices.api.errors.DeviceAuthenticatorError.ServerApiError
import com.okta.devices.api.log.DeviceLog
import com.okta.devices.api.model.ApplicationConfig
import com.okta.devices.api.model.AuthToken
import com.okta.devices.api.model.Challenge
import com.okta.devices.api.model.DeviceAuthenticatorConfig
import com.okta.devices.api.model.EnrollmentParameters
import com.okta.devices.api.model.RegistrationToken.FcmToken
import com.okta.devices.api.security.SignatureProvider
import com.okta.devices.api.time.DeviceClock
import com.okta.devices.data.repository.KeyType
import com.okta.devices.data.repository.KeyType.PROOF_OF_POSSESSION_KEY
import com.okta.devices.data.repository.KeyType.USER_VERIFICATION_KEY
import com.okta.devices.data.repository.MethodType
import com.okta.devices.data.repository.MethodType.PUSH
import com.okta.devices.data.repository.MethodType.UNKNOWN
import com.okta.devices.fake.FakeServerBuilder
import com.okta.devices.fake.generator.JwtGenerator.createAuthorizationJwt
import com.okta.devices.fake.generator.JwtGenerator.createIdxPushJws
import com.okta.devices.fake.generator.OrganizationGenerator
import com.okta.devices.fake.server.FakeServer
import com.okta.devices.fake.server.api.FakeApiEndpoint
import com.okta.devices.fake.util.FakeHttpsConfiguration
import com.okta.devices.fake.util.FakeKeyStore
import com.okta.devices.fake.util.SslConfiguration
import com.okta.devices.fake.util.toJson
import com.okta.devices.fake.util.uuid
import com.okta.devices.model.ErrorCode.AUTHENTICATION_EXCEPTION
import com.okta.devices.model.errorResponse
import com.okta.devices.push.PushRemediation.CibaConsent
import com.okta.devices.push.PushRemediation.Completed
import com.okta.devices.push.PushRemediation.UserConsent
import com.okta.devices.push.PushRemediation.UserVerification
import com.okta.devices.push.PushRemediation.UserVerificationError
import com.okta.devices.push.api.PushAuthenticator
import com.okta.devices.push.api.PushChallenge
import com.okta.devices.push.api.PushEnrollment
import com.okta.devices.push.utils.BaseTest
import com.okta.devices.push.utils.RemediationHandler
import com.okta.devices.push.utils.TestDeviceStore
import com.okta.devices.storage.AuthenticatorDatabase
import com.okta.devices.storage.EncryptionOption
import com.okta.devices.storage.api.DeviceStore
import com.okta.devices.util.TransactionType
import com.okta.devices.util.UserMediationChallenge
import com.okta.devices.util.UserVerificationChallenge
import com.okta.devices.util.UserVerificationChallenge.PREFERRED
import com.okta.devices.util.UserVerificationChallenge.REQUIRED
import io.jsonwebtoken.IncorrectClaimException
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.hamcrest.CoreMatchers.instanceOf
import org.hamcrest.CoreMatchers.`is`
import org.hamcrest.CoreMatchers.not
import org.hamcrest.CoreMatchers.notNullValue
import org.hamcrest.CoreMatchers.nullValue
import org.hamcrest.MatcherAssert.assertThat
import org.junit.AfterClass
import org.junit.Assert
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.net.HttpURLConnection.HTTP_INTERNAL_ERROR
import java.net.URL
import java.security.PrivateKey
import java.security.Signature
import java.security.UnrecoverableKeyException
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date

@ExperimentalCoroutinesApi
@RunWith(AndroidJUnit4::class)
class MyAccountPushAuthenticatorTest : BaseTest() {
    @get:Rule
    var instantTaskExecutor = InstantTaskExecutorRule()

    private lateinit var authenticator: PushAuthenticator
    private lateinit var testDeviceStorage: DeviceStore
    private lateinit var testScope: TestScope

    private val oidcClientId = uuid()
    private val config = DeviceAuthenticatorConfig(URL(testServer.url), oidcClientId)
    private val context: Context = getApplicationContext()
    private val serverKey: PrivateKey = testServer.fakeKeyStore.serverKeyPair.private
    private val serverKid: String = testServer.fakeKeyStore.serverKeyAlias
    private val testKeyStore: FakeKeyStore = testServer.fakeKeyStore
    private val customOkHttpClient = OkHttpClient.Builder()
        .retryOnConnectionFailure(false)
        .sslSocketFactory(sslConfig.sslContext.socketFactory, sslConfig.x509TrustManager)
        .hostnameVerifier { _, _ -> true }
        .build()

    companion object {
        lateinit var testServer: FakeServer
        lateinit var sslConfig: SslConfiguration

        @BeforeClass
        @JvmStatic
        fun beforeClass() {
            BaseTest.beforeClass()
            sslConfig = FakeHttpsConfiguration().configureHttps()
            testServer = runBlocking {
                FakeServerBuilder.build(CoroutineScope(Dispatchers.Default)) {
                    mockWebServer = MockWebServer().apply { useHttps(sslConfig.sslContext.socketFactory, false) }
                }
            }
        }

        @AfterClass
        @JvmStatic
        fun afterClass() {
            testServer.tearDown()
            BaseTest.afterClass()
        }
    }

    override fun setUp() {
        super.setUp()
        val testDispatcher = StandardTestDispatcher()
        testScope = TestScope(Job() + testDispatcher)
        testDeviceStorage = TestDeviceStore(AuthenticatorDatabase.instance(context, EncryptionOption.None, true))
        authenticator = PushAuthenticatorBuilder.create(
            ApplicationConfig(getApplicationContext(), "test", "version")
        ) {
            signer = testKeyStore.testSigner
            encryptionProvider = testKeyStore.encrypt
            deviceStore = testDeviceStorage
            coroutineScope = testScope
            deviceLog = object : DeviceLog {
                override fun shouldDebugLog(): Boolean = true
            }
            okHttpClient = customOkHttpClient
            useMyAccount = true
        }.getOrThrow()
    }

    override fun tearDown() {
        super.tearDown()
        testServer.fakApiEndpointImpl.reset()
        testScope.testScheduler.advanceUntilIdle()
        testScope.cancel()
        testDeviceStorage.close()
    }

    @Test
    fun `enroll with invalid token expect invalid token failure`() = runTest {
        // arrange
        testKeyStore.testSigner.generateAndStoreKeyPair("notServerKey", false)
        val badKey = testKeyStore.testSigner.getPrivateKey("notServerKey") ?: error("Unable to generate test key")
        val authToken = AuthToken.Bearer(createAuthorizationJwt(badKey))

        // act
        val result = authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid())))

        // assert
        assertThat(result.isFailure, `is`(true))
        val exception = result.exceptionOrNull()
        assertThat(exception, instanceOf(ServerApiError::class.java))
        assertThat((exception as ServerApiError).errorCode, `is`(AUTHENTICATION_EXCEPTION.value))
    }

    @Test
    fun `enroll with expired token expect invalid token failure`() = runTest {
        // arrange
        val authToken = AuthToken.Bearer(
            createAuthorizationJwt(
                serverKey,
                iat = Instant.now().minus(1, ChronoUnit.DAYS).toEpochMilli() // expired
            )
        )

        // act
        val result = authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid())))

        // assert
        assertThat(result.isFailure, `is`(true))
        val exception = result.exceptionOrNull()
        assertThat(exception, instanceOf(ServerApiError::class.java))
        assertThat((exception as ServerApiError).errorCode, `is`(AUTHENTICATION_EXCEPTION.value))
    }

    @Test
    fun `call set enable user verification, expect user verification enabled`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow()
        }
        val currentMethod = runBlocking {
            testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first()
                .methodInformation.first { PUSH.isEqual(it.methodType) }
        }

        // act
        val result = runBlocking { enrollment.setUserVerification(authToken, enable = true) }

        // assert
        assertThat(result.getOrThrow(), `is`(true))
        testScope.advanceUntilIdle()
        val methodUpdated = runBlocking {
            testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first()
                .methodInformation.first { PUSH.isEqual(it.methodType) }
        }
        assertThat(methodUpdated.userVerificationKey, notNullValue())
        assertThat(currentMethod.userVerificationKey, nullValue())
        assertThat(testKeyStore.testSigner.deviceKeyStore.containsAlias(checkNotNull(methodUpdated.userVerificationKey?.keyId)), `is`(true))
        // Only difference is the uv key. so copy the new key to check other fields are same
        assertThat(methodUpdated, `is`(currentMethod.copy(userVerificationKey = methodUpdated.userVerificationKey)))
    }

    @Test
    fun `enable user verification on existing uv enabled enrollment, expect user verification replaced`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = true)).getOrThrow()
        }
        val currentMethod = runBlocking {
            testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first()
                .methodInformation.first { PUSH.isEqual(it.methodType) }
        }

        // act
        val result = runBlocking { enrollment.setUserVerification(authToken, enable = true) }

        // assert
        assertThat(result.getOrThrow(), `is`(true))
        testScope.advanceUntilIdle()
        val methodUpdated = runBlocking {
            testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first()
                .methodInformation.first { PUSH.isEqual(it.methodType) }
        }
        assertThat(methodUpdated.userVerificationKey, notNullValue())
        assertThat(currentMethod.userVerificationKey, notNullValue())
        assertThat(testKeyStore.testSigner.deviceKeyStore.containsAlias(checkNotNull(methodUpdated.userVerificationKey?.keyId)), `is`(true))
        // check the previous uv key is removed
        assertThat(testKeyStore.testSigner.deviceKeyStore.containsAlias(checkNotNull(currentMethod.userVerificationKey?.keyId)), `is`(false))
        // Only difference is the uv key. so copy the new key to check other fields are same
        assertThat(methodUpdated, `is`(currentMethod.copy(userVerificationKey = methodUpdated.userVerificationKey)))
    }

    @Test
    fun `call set disable user verification, expect user verification disable`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = true)).getOrThrow()
        }
        val currentMethod = runBlocking {
            testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first()
                .methodInformation.first { PUSH.isEqual(it.methodType) }
        }

        // act
        val result = runBlocking { enrollment.setUserVerification(authToken, enable = false) }

        // assert
        assertThat(result.getOrThrow(), `is`(true))
        testScope.advanceUntilIdle()
        val methodUpdated = runBlocking {
            testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first()
                .methodInformation.first { PUSH.isEqual(it.methodType) }
        }
        assertThat(methodUpdated.userVerificationKey, nullValue())
        assertThat(currentMethod.userVerificationKey, notNullValue())
        // check the key is deleted from keystore
        assertThat(testKeyStore.testSigner.deviceKeyStore.containsAlias(checkNotNull(currentMethod.userVerificationKey?.keyId)), `is`(false))
        // Only difference is the uv key. so copy the new key to check other fields are same
        assertThat(methodUpdated, `is`(currentMethod.copy(userVerificationKey = methodUpdated.userVerificationKey)))
    }

    @Test
    fun `call delete, expect enrollment deleted`() {
        // arrange
        val userId = uuid()
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey, userId = userId))
        val authenticatorEnrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow()
        }

        // act
        val result = runBlocking { authenticator.delete(authToken, authenticatorEnrollment).getOrThrow() }

        // assert
        val deletedFromDataStore = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(userId).isEmpty() }
        assertThat(authenticatorEnrollment.user().id, `is`(userId))
        assertThat(result, `is`(true))
        assertThat(deletedFromDataStore, `is`(true))
    }

    @Test
    fun `call local delete, expect enrollment deleted`() {
        // arrange
        val userId = uuid()
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey, userId = userId))
        val authenticatorEnrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow()
        }

        // act
        val result = runBlocking { authenticatorEnrollment.deleteFromDevice().getOrThrow() }

        // assert
        val deletedFromDataStore = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(userId).isEmpty() }
        assertThat(authenticatorEnrollment.user().id, `is`(userId))
        assertThat(result, `is`(true))
        assertThat(deletedFromDataStore, `is`(true))
    }

    @Test
    fun `call downloadPolicy expect policy returned`() {
        // act
        val result = runBlocking { authenticator.downloadPolicy(config) }

        // assert
        assertThat(result.isSuccess, `is`(true))
        assertThat(result.getOrNull(), notNullValue())
        assertThat(result.getOrThrow().requireUserVerification, `is`(false))
    }

    @Test
    fun `call updateRegistrationToken for multiple enrollments expect success returned`() {
        // arrange
        val updatedRegistrationToken = uuid()
        val authToken1 = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val authToken2 = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment1 = runBlocking { authenticator.enroll(authToken1, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow() }
        val enrollment2 = runBlocking { authenticator.enroll(authToken2, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow() }

        val currentMethodForEnrollment1 = runBlocking {
            testDeviceStorage.accountInformationStore().getByUserId(enrollment1.user().id).first()
                .methodInformation.first { PUSH.isEqual(it.methodType) }
        }
        val currentMethodForEnrollment2 = runBlocking {
            testDeviceStorage.accountInformationStore().getByUserId(enrollment2.user().id).first()
                .methodInformation.first { PUSH.isEqual(it.methodType) }
        }

        val initialPushTokenForEnrollment1 = checkNotNull(currentMethodForEnrollment1.pushToken)
        val initialPushTokenForEnrollment2 = checkNotNull(currentMethodForEnrollment2.pushToken)

        // act
        val result1 = runBlocking { enrollment1.updateRegistrationToken(authToken1, FcmToken(updatedRegistrationToken)) }
        val result2 = runBlocking { enrollment2.updateRegistrationToken(authToken2, FcmToken(updatedRegistrationToken)) }

        // assert
        assertThat(initialPushTokenForEnrollment1, not(updatedRegistrationToken))
        assertThat(result1.getOrThrow(), `is`(updatedRegistrationToken))
        assertThat(initialPushTokenForEnrollment2, not(updatedRegistrationToken))
        assertThat(result2.getOrThrow(), `is`(updatedRegistrationToken))

        testScope.advanceUntilIdle()
        val methodUpdated1 = runBlocking {
            testDeviceStorage.accountInformationStore().getByUserId(enrollment1.user().id).first()
                .methodInformation.first { PUSH.isEqual(it.methodType) }
        }
        val methodUpdated2 = runBlocking {
            testDeviceStorage.accountInformationStore().getByUserId(enrollment2.user().id).first()
                .methodInformation.first { PUSH.isEqual(it.methodType) }
        }
        // Only difference is the registration token. so copy the new registration token to check other fields are same
        assertThat(methodUpdated1, `is`(currentMethodForEnrollment1.copy(pushToken = updatedRegistrationToken)))
        assertThat(methodUpdated2, `is`(currentMethodForEnrollment2.copy(pushToken = updatedRegistrationToken)))
    }

    @Test
    fun `call parse expect parsed push challenge returned`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow()
        }
        val transactionTime: String = Date(System.currentTimeMillis()).toString()
        val pushMessage = createPushJws(enrollment, PROOF_OF_POSSESSION_KEY, transactionTime = transactionTime)

        // act
        val pushChallenge = runBlocking { authenticator.parseChallenge(pushMessage).getOrThrow() }

        // assert
        assertThat(pushChallenge.clientLocation, `is`("San Francisco, CA, USA"))
        assertThat(pushChallenge.clientOs, `is`("Mac OS X"))
        assertThat(pushChallenge.originUrl, `is`(testServer.url))
        assertThat(pushChallenge.transactionTime, `is`(transactionTime))
    }

    @Test
    fun `parse a mismatch audience claim expect error returned`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking { authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow() }
        val pushJws = createPushJws(enrollment, PROOF_OF_POSSESSION_KEY, aud = uuid())

        // act
        val error = runBlocking { authenticator.parseChallenge(pushJws).exceptionOrNull() }

        // assert
        assertThat(error, notNullValue())
        assertThat(error, instanceOf(InternalDeviceError::class.java))
        assertThat(error?.cause, instanceOf(IncorrectClaimException::class.java))
    }

    @Test
    fun `parse a non push challenge expect error returned`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking { authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow() }
        val pushJws = createPushJws(enrollment, PROOF_OF_POSSESSION_KEY, methodType = UNKNOWN)

        // act
        val error = runBlocking { authenticator.parseChallenge(pushJws).exceptionOrNull() }

        // assert
        assertThat(error, notNullValue())
        assertThat(error is IllegalArgumentException, `is`(true))
    }

    @Test
    fun `enroll a non push enrollment parameter expect error returned`() {
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollmentParameters = mockk<EnrollmentParameters>()
        val enrollment = runBlocking { authenticator.enroll(authToken, config, enrollmentParameters).exceptionOrNull() }
        assertThat(enrollment is IllegalArgumentException, `is`(true))
    }

    @Test
    fun `retrieve pending CIBA challenge expect list of challenges returned`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableCiba = true)).getOrThrow()
        }
        val transactionId = uuid()
        val accountInfo = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first() }
        val method = accountInfo.methodInformation.first { PUSH.isEqual(it.methodType) }
        val bindingMessage = uuid()
        val pushJwsChallenge = createPushJws(enrollment, PROOF_OF_POSSESSION_KEY, transactionId, transactionType = TransactionType.CIBA, bindingMessage = bindingMessage)

        val parsedChallenge = runBlocking { authenticator.parseChallenge(pushJwsChallenge) }.getOrThrow() as PushChallengeImpl
        testServer.fakApiEndpointImpl.signInRequest(enrollment.user().id, method.methodId, method.enrollmentId, transactionId, oidcClientId, pushJwsChallenge)

        // act
        val challenges: List<PushChallenge> = runBlocking { enrollment.retrievePushChallenges(authToken).getOrThrow() }

        // assert
        assertThat(challenges.isNotEmpty(), `is`(true))
        assertThat((challenges.first() as PushChallengeImpl).info, `is`(parsedChallenge.info))
    }

    @Test
    fun `retrieve pending challenges with expired challenge expect only valid challenge returned`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow()
        }
        val transactionId = uuid()
        val transactionIdInvalid = uuid()
        val accountInfo = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first() }
        val enrollmentId = accountInfo.enrollmentInformation.enrollmentId
        val method = accountInfo.methodInformation.first { PUSH.isEqual(it.methodType) }
        val validChallenge = createIdxPushJws(
            serverKey,
            serverKid,
            testServer.url,
            enrollmentId,
            method.methodId,
            transactionId = transactionId,
            keyTypes = listOf(PROOF_OF_POSSESSION_KEY.serializedName),
            aud = oidcClientId
        )
        testServer.fakApiEndpointImpl.signInRequest(enrollment.user().id, method.methodId, method.enrollmentId, transactionId, oidcClientId, validChallenge)

        val expiredChallenge = createIdxPushJws(
            serverKey, serverKid, testServer.url, enrollmentId, method.methodId,
            transactionId = transactionIdInvalid,
            keyTypes = listOf(PROOF_OF_POSSESSION_KEY.serializedName),
            iat = Instant.now().minus(1, ChronoUnit.DAYS).toEpochMilli(), // expired yesterday
            aud = oidcClientId
        )
        testServer.fakApiEndpointImpl.signInRequest(enrollment.user().id, method.methodId, method.enrollmentId, transactionIdInvalid, oidcClientId, expiredChallenge)

        // act
        val challenges: List<PushChallenge> = runBlocking { enrollment.retrievePushChallenges(authToken).getOrThrow() }

        // assert
        val parsedValidChallenge = runBlocking { authenticator.parseChallenge(validChallenge) }.getOrThrow() as PushChallengeImpl

        assertThat(challenges.size, `is`(1)) // should only contain the valid challenge
        assertThat((challenges.first() as PushChallengeImpl).info, `is`(parsedValidChallenge.info))
    }

    @Test
    fun `call retrievePushChallenges expect list of challenges returned`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow()
        }
        val transactionId = uuid()
        val accountInfo = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first() }
        val method = accountInfo.methodInformation.first { PUSH.isEqual(it.methodType) }
        val firstChallenge = createPushJws(enrollment, PROOF_OF_POSSESSION_KEY, transactionId)

        val parsedFirstChallenge = runBlocking { authenticator.parseChallenge(firstChallenge) }.getOrThrow() as PushChallengeImpl
        testServer.fakApiEndpointImpl.signInRequest(enrollment.user().id, method.methodId, method.enrollmentId, transactionId, oidcClientId, firstChallenge)

        // act
        val challenges: List<PushChallenge> = runBlocking { enrollment.retrievePushChallenges(authToken).getOrThrow() }

        // assert
        assertThat(challenges.isNotEmpty(), `is`(true))
        assertThat((challenges.first() as PushChallengeImpl).info, `is`(parsedFirstChallenge.info))
    }

    @Test
    fun `multiple pending challenges from multiple enrollments expect list of challenges returned`() {
        // arrange
        val authToken1 = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val authToken2 = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment1 = runBlocking { authenticator.enroll(authToken1, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow() }
        val enrollment2 = runBlocking { authenticator.enroll(authToken2, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow() }

        val transactionId1ForEnrollment1 = uuid()
        val transactionId2ForEnrollment1 = uuid()
        val transactionId1ForEnrollment2 = uuid()
        val transactionId2ForEnrollment2 = uuid()

        val accountInfo1 = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(enrollment1.user().id).first() }
        val accountInfo2 = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(enrollment2.user().id).first() }

        val enrollmentId1 = accountInfo1.enrollmentInformation.enrollmentId
        val enrollmentId2 = accountInfo2.enrollmentInformation.enrollmentId

        val methodForEnrollment1 = accountInfo1.methodInformation.first { PUSH.isEqual(it.methodType) }
        val methodForEnrollment2 = accountInfo2.methodInformation.first { PUSH.isEqual(it.methodType) }

        val challenge1ForEnrollment1 = createIdxPushJws(
            serverKey,
            serverKid,
            testServer.url,
            enrollmentId1,
            methodForEnrollment1.methodId,
            transactionId = transactionId1ForEnrollment1,
            keyTypes = listOf(PROOF_OF_POSSESSION_KEY.serializedName),
            aud = oidcClientId
        )
        testServer.fakApiEndpointImpl.signInRequest(
            enrollment1.user().id,
            methodForEnrollment1.methodId,
            methodForEnrollment1.enrollmentId,
            transactionId1ForEnrollment1,
            oidcClientId,
            challenge1ForEnrollment1
        )

        val challenge2ForEnrollment1 = createIdxPushJws(
            serverKey,
            serverKid,
            testServer.url,
            enrollmentId1,
            methodForEnrollment1.methodId,
            transactionId = transactionId2ForEnrollment1,
            keyTypes = listOf(PROOF_OF_POSSESSION_KEY.serializedName),
            aud = oidcClientId
        )
        testServer.fakApiEndpointImpl.signInRequest(
            enrollment1.user().id,
            methodForEnrollment1.methodId,
            methodForEnrollment1.enrollmentId,
            transactionId2ForEnrollment1,
            oidcClientId,
            challenge2ForEnrollment1
        )

        val challenge1ForEnrollment2 = createIdxPushJws(
            serverKey,
            serverKid,
            testServer.url,
            enrollmentId2,
            methodForEnrollment2.methodId,
            transactionId = transactionId1ForEnrollment2,
            keyTypes = listOf(PROOF_OF_POSSESSION_KEY.serializedName),
            aud = oidcClientId
        )
        testServer.fakApiEndpointImpl.signInRequest(
            enrollment2.user().id,
            methodForEnrollment2.methodId,
            methodForEnrollment2.enrollmentId,
            transactionId1ForEnrollment2,
            oidcClientId,
            challenge1ForEnrollment2
        )

        val challenge2ForEnrollment2 = createIdxPushJws(
            serverKey,
            serverKid,
            testServer.url,
            enrollmentId2,
            methodForEnrollment2.methodId,
            transactionId = transactionId2ForEnrollment2,
            keyTypes = listOf(PROOF_OF_POSSESSION_KEY.serializedName),
            aud = oidcClientId
        )
        testServer.fakApiEndpointImpl.signInRequest(
            enrollment2.user().id,
            methodForEnrollment2.methodId,
            methodForEnrollment2.enrollmentId,
            transactionId2ForEnrollment2,
            oidcClientId,
            challenge2ForEnrollment2
        )

        val parsedChallenge1ForEnrollment1 = runBlocking { authenticator.parseChallenge(challenge1ForEnrollment1) }.getOrThrow() as PushChallengeImpl
        val parsedChallenge2ForEnrollment1 = runBlocking { authenticator.parseChallenge(challenge2ForEnrollment1) }.getOrThrow() as PushChallengeImpl
        val parsedChallenge1ForEnrollment2 = runBlocking { authenticator.parseChallenge(challenge1ForEnrollment2) }.getOrThrow() as PushChallengeImpl
        val parsedChallenge2ForEnrollment2 = runBlocking { authenticator.parseChallenge(challenge2ForEnrollment2) }.getOrThrow() as PushChallengeImpl

        // act
        val challengesForEnrollment1: List<PushChallenge> = runBlocking { enrollment1.retrievePushChallenges(authToken1).getOrThrow() }
        val challengesForEnrollment2: List<PushChallenge> = runBlocking { enrollment2.retrievePushChallenges(authToken2).getOrThrow() }

        // assert
        assertThat(challengesForEnrollment1.size, `is`(2))
        assertThat(challengesForEnrollment2.size, `is`(2))

        val enrollment1Challenges = listOf(parsedChallenge1ForEnrollment1.info, parsedChallenge2ForEnrollment1.info)
        val enrollment2Challenges = listOf(parsedChallenge1ForEnrollment2.info, parsedChallenge2ForEnrollment2.info)
        assertThat(challengesForEnrollment1.map { (it as PushChallengeImpl).info }.containsAll(enrollment1Challenges), `is`(true))
        assertThat(challengesForEnrollment2.map { (it as PushChallengeImpl).info }.containsAll(enrollment2Challenges), `is`(true))
    }

    @Test
    fun `call challenge resolve to accept push with UV, expect successful complete status with success`() = runTest {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = true)).getOrThrow()
        }
        val accountInfo = testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first()
        val method = accountInfo.methodInformation.first { PUSH.isEqual(it.methodType) }
        val transactionId = uuid()
        val pushChallengeJws =
            createPushJws(enrollment, USER_VERIFICATION_KEY, transactionId, userVerificationChallenge = REQUIRED, transactionType = TransactionType.LOGIN)

        // send push
        testServer.fakApiEndpointImpl.signInRequest(enrollment.user().id, method.methodId, method.enrollmentId, transactionId, pushChallengeJws)

        // act
        val parseResult = authenticator.parseChallenge(pushChallengeJws).getOrThrow()
        val userVerification: UserVerification = parseResult.resolve().getOrThrow() as UserVerification
        val authenticationResult = mockk<AuthenticationResult>()
        userVerification.signature?.run {
            every { authenticationResult.authenticationType } returns BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC
            every { authenticationResult.cryptoObject } returns BiometricPrompt.CryptoObject(this)
        }
        val userConsent: UserConsent = userVerification.resolve(authenticationResult).getOrThrow() as UserConsent
        val completed = userConsent.accept().getOrThrow() as Completed
        // assert
        assertThat(completed.state.userVerificationUsed, `is`(true))
        assertThat(completed.state.accepted, `is`(true))
        assertThat(completed.state.throwable, `is`(nullValue()))
    }

    @Test
    fun `call challenge resolve to accept push, expect successful complete status`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow()
        }
        val accountInfo = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first() }
        val method = accountInfo.methodInformation.first { PUSH.isEqual(it.methodType) }
        val transactionId = uuid()
        val pushChallengeJws = createPushJws(enrollment, PROOF_OF_POSSESSION_KEY, transactionId)

        // ux handling
        val userInteraction = object : RemediationHandler.UserInteraction {
            override fun confirm(challenge: Challenge): Boolean = true // accept
            override fun userVerification(challenge: Challenge): AuthenticationResult? = null
            override fun fixUserVerificationError(securityError: DeviceAuthenticatorError.SecurityError): Boolean = true
        }
        val handler = RemediationHandler(userInteraction)

        // sign in
        testServer.fakApiEndpointImpl.signInRequest(enrollment.user().id, method.methodId, method.enrollmentId, transactionId, pushChallengeJws)

        // act
        val parseResult = runBlocking { authenticator.parseChallenge(pushChallengeJws) }.getOrThrow()
        val remediation = parseResult.resolve().getOrThrow()
        val completed: Completed = runBlocking { handler.handleRemediation(remediation).getOrThrow() as Completed }
        // assert
        assertThat(completed.state.userVerificationUsed, `is`(false))
        assertThat(completed.state.accepted, `is`(true))
        assertThat(completed.state.throwable, `is`(nullValue()))
    }

    @Test
    fun `call challenge resolve to accept CIBA push, expect successful complete status`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableCiba = true)).getOrThrow()
        }
        val accountInfo = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first() }
        val method = accountInfo.methodInformation.first { PUSH.isEqual(it.methodType) }
        val transactionId = uuid()
        val bindingMessage = uuid()
        val pushChallengeJws = createPushJws(enrollment, PROOF_OF_POSSESSION_KEY, transactionId, transactionType = TransactionType.CIBA, bindingMessage = bindingMessage)

        // ux handling
        val userInteraction = object : RemediationHandler.UserInteraction {
            override fun confirm(challenge: Challenge): Boolean = true // accept
            override fun userVerification(challenge: Challenge): AuthenticationResult? = null
            override fun fixUserVerificationError(securityError: DeviceAuthenticatorError.SecurityError): Boolean = true
        }
        val handler = RemediationHandler(userInteraction)

        // send ciba push
        testServer.fakApiEndpointImpl.signInRequest(enrollment.user().id, method.methodId, method.enrollmentId, transactionId, pushChallengeJws)

        // act
        val parseResult = runBlocking { authenticator.parseChallenge(pushChallengeJws) }.getOrThrow()
        val remediation = parseResult.resolve().getOrThrow()
        assertThat(remediation, instanceOf(CibaConsent::class.java))
        assertThat((remediation as CibaConsent).bindingMessage, `is`(bindingMessage))
        val completed: Completed = runBlocking { handler.handleRemediation(remediation).getOrThrow() as Completed }
        // assert
        assertThat(completed.state.userVerificationUsed, `is`(false))
        assertThat(completed.state.accepted, `is`(true))
        assertThat(completed.state.throwable, `is`(nullValue()))
    }

    @Test
    fun `call challenge resolve to accept CIBA push with UV, expect successful complete status with success`() = runTest {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = true, enableCiba = true)).getOrThrow()
        }
        val accountInfo = testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first()
        val method = accountInfo.methodInformation.first { PUSH.isEqual(it.methodType) }
        val transactionId = uuid()
        val bindingMessage = uuid()
        val pushChallengeJws =
            createPushJws(enrollment, USER_VERIFICATION_KEY, transactionId, userVerificationChallenge = REQUIRED, transactionType = TransactionType.CIBA, bindingMessage = bindingMessage)

        // send ciba push
        testServer.fakApiEndpointImpl.signInRequest(enrollment.user().id, method.methodId, method.enrollmentId, transactionId, pushChallengeJws)

        // act
        val parseResult = authenticator.parseChallenge(pushChallengeJws).getOrThrow()
        val userVerification: UserVerification = parseResult.resolve().getOrThrow() as UserVerification
        val authenticationResult = mockk<AuthenticationResult>()
        userVerification.signature?.run {
            every { authenticationResult.authenticationType } returns BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC
            every { authenticationResult.cryptoObject } returns BiometricPrompt.CryptoObject(this)
        }
        val cibaConsent: CibaConsent = userVerification.resolve(authenticationResult).getOrThrow() as CibaConsent
        assertThat(cibaConsent.bindingMessage, `is`(bindingMessage))
        val completed = cibaConsent.accept().getOrThrow() as Completed
        // assert
        assertThat(completed.state.userVerificationUsed, `is`(true))
        assertThat(completed.state.accepted, `is`(true))
        assertThat(completed.state.throwable, `is`(nullValue()))
    }

    @Test
    fun `call challenge resolve to accept CIBA push with UV, expect successful complete status with error`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = true, enableCiba = true)).getOrThrow()
        }
        val accountInfo = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first() }
        val method = accountInfo.methodInformation.first { PUSH.isEqual(it.methodType) }
        val transactionId = uuid()
        val bindingMessage = uuid()
        val pushChallengeJws =
            createPushJws(enrollment, USER_VERIFICATION_KEY, transactionId, userVerificationChallenge = REQUIRED, transactionType = TransactionType.CIBA, bindingMessage = bindingMessage)

        // send ciba push
        testServer.fakApiEndpointImpl.signInRequest(enrollment.user().id, method.methodId, method.enrollmentId, transactionId, pushChallengeJws)

        // act
        val parseResult = runBlocking { authenticator.parseChallenge(pushChallengeJws) }.getOrThrow()
        val remediation = parseResult.resolve().getOrThrow()
        assertThat(remediation, instanceOf(UserVerification::class.java))
        val authenticationResult = mockk<AuthenticationResult>()
        val cibaConsent = (remediation as UserVerification).resolve(authenticationResult).getOrThrow()
        assertThat(cibaConsent, instanceOf(CibaConsent::class.java))
        assertThat((cibaConsent as CibaConsent).bindingMessage, `is`(bindingMessage))
        val serverApiError = runBlocking { cibaConsent.accept().exceptionOrNull() }
        assertThat(serverApiError, instanceOf(ServerApiError::class.java))
    }

    @Test
    fun `call challenge resolve to accept cancel UV then accept consent, expect successful complete status`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = true)).getOrThrow()
        }
        val accountInfo = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first() }
        val method = accountInfo.methodInformation.first { PUSH.isEqual(it.methodType) }
        val transactionId = uuid()
        val pushChallengeJws = createPushJws(enrollment, USER_VERIFICATION_KEY, transactionId, userVerificationChallenge = REQUIRED)

        // sign in
        testServer.fakApiEndpointImpl.signInRequest(enrollment.user().id, method.methodId, method.enrollmentId, transactionId, pushChallengeJws)

        // act
        val parseResult = runBlocking { authenticator.parseChallenge(pushChallengeJws) }.getOrThrow()

        when (val remediation = parseResult.resolve().getOrThrow()) {
            is UserVerification -> {
                val userConsent = remediation.cancel().getOrThrow() as UserConsent
                val completed = runBlocking { userConsent.accept().getOrThrow() as Completed }

                // assert
                assertThat(completed.state.userVerificationUsed, `is`(false))
                assertThat(completed.state.accepted, `is`(true))
                assertThat(completed.state.throwable, `is`(nullValue()))
            }
            else -> Assert.fail("UserVerification remediation expected")
        }
    }

    @Test
    fun `call CIBA challenge resolve to accept cancel UV then accept consent, expect successful complete status`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = true, enableCiba = true)).getOrThrow()
        }
        val accountInfo = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first() }
        val method = accountInfo.methodInformation.first { PUSH.isEqual(it.methodType) }
        val transactionId = uuid()
        val bindingMessage = uuid()
        val pushChallengeJws =
            createPushJws(enrollment, USER_VERIFICATION_KEY, transactionId, userVerificationChallenge = PREFERRED, transactionType = TransactionType.CIBA, bindingMessage = bindingMessage)

        // sign in
        testServer.fakApiEndpointImpl.signInRequest(enrollment.user().id, method.methodId, method.enrollmentId, transactionId, pushChallengeJws)

        // act
        val parseResult = runBlocking { authenticator.parseChallenge(pushChallengeJws) }.getOrThrow()

        when (val remediation = parseResult.resolve().getOrThrow()) {
            is UserVerification -> {
                val cibaConsent = remediation.cancel().getOrThrow() as CibaConsent
                assertThat(cibaConsent.bindingMessage, `is`(bindingMessage))
                val completed = runBlocking { cibaConsent.accept().getOrThrow() as Completed }

                // assert
                assertThat(completed.state.userVerificationUsed, `is`(false))
                assertThat(completed.state.accepted, `is`(true))
                assertThat(completed.state.throwable, `is`(nullValue()))
            }
            else -> Assert.fail("UserVerification remediation expected")
        }
    }

    @Test
    fun `call challenge resolve when biometric is locked then accept consent, expect successful complete status`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = true)).getOrThrow()
        }
        val accountInfo = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first() }
        val method = accountInfo.methodInformation.first { PUSH.isEqual(it.methodType) }
        val transactionId = uuid()
        val pushChallengeJws = createPushJws(enrollment, USER_VERIFICATION_KEY, transactionId, userVerificationChallenge = REQUIRED)

        // sign in
        testServer.fakApiEndpointImpl.signInRequest(enrollment.user().id, method.methodId, method.enrollmentId, transactionId, pushChallengeJws)

        // act
        val parseResult = runBlocking { authenticator.parseChallenge(pushChallengeJws) }.getOrThrow()

        when (val remediation = parseResult.resolve().getOrThrow()) {
            is UserVerification -> {
                val userConsent = remediation.temporarilyUnavailable().getOrThrow() as UserConsent
                val completed = runBlocking { userConsent.accept().getOrThrow() as Completed }

                // assert
                assertThat(completed.state.userVerificationUsed, `is`(false))
                assertThat(completed.state.accepted, `is`(true))
                assertThat(completed.state.throwable, `is`(nullValue()))
            }
            else -> Assert.fail("UserVerification remediation expected")
        }
    }

    @Test
    fun `call challenge resolve when biometric is removed then accept consent, expect successful complete status`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = true)).getOrThrow()
        }
        val accountInfo = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first() }
        val method = accountInfo.methodInformation.first { PUSH.isEqual(it.methodType) }
        val transactionId = uuid()
        val pushChallengeJws = createPushJws(enrollment, USER_VERIFICATION_KEY, transactionId, userVerificationChallenge = REQUIRED)

        // sign in
        testServer.fakApiEndpointImpl.signInRequest(enrollment.user().id, method.methodId, method.enrollmentId, transactionId, pushChallengeJws)

        // act
        val parseResult = runBlocking { authenticator.parseChallenge(pushChallengeJws) }.getOrThrow()

        when (val remediation = parseResult.resolve().getOrThrow()) {
            is UserVerification -> {
                val userConsent = remediation.permanentlyUnavailable().getOrThrow() as UserConsent
                val completed = runBlocking { userConsent.accept().getOrThrow() as Completed }

                // assert
                assertThat(completed.state.userVerificationUsed, `is`(false))
                assertThat(completed.state.accepted, `is`(true))
                assertThat(completed.state.throwable, `is`(nullValue()))
            }
            else -> Assert.fail("UserVerification remediation expected")
        }
    }

    @Test
    fun `remediate unrecoverable UV then resolve without consent on failure, expect unrecoverable key returned`() {
        // arrange
        val keySigner: SignatureProvider = object : SignatureProvider by testKeyStore.testSigner {
            override fun getSignature(alias: String): Signature = throw UnrecoverableKeyException()
        }

        val authenticator = PushAuthenticatorBuilder.create(ApplicationConfig(getApplicationContext(), "test", "version")) {
            signer = keySigner
            encryptionProvider = testKeyStore.encrypt
            deviceStore = testDeviceStorage
            coroutineScope = testScope
            okHttpClient = customOkHttpClient
            useMyAccount = true
        }.getOrThrow()
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = true)).getOrThrow()
        }
        val accountInfo = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first() }
        val method = accountInfo.methodInformation.first { PUSH.isEqual(it.methodType) }
        val transactionId = uuid()
        val pushChallengeJws = createPushJws(enrollment, USER_VERIFICATION_KEY, transactionId, userVerificationChallenge = REQUIRED)

        // sign in
        testServer.fakApiEndpointImpl.signInRequest(enrollment.user().id, method.methodId, method.enrollmentId, transactionId, pushChallengeJws)

        // act
        val parseResult = runBlocking { authenticator.parseChallenge(pushChallengeJws) }.getOrThrow()

        when (val remediation = parseResult.resolve().getOrThrow()) {
            is UserVerificationError -> {
                val result = remediation.resolve(consentOnFailure = false)
                // assert
                assertThat(result.isFailure, `is`(true))
                assertThat(result.exceptionOrNull(), instanceOf(UnrecoverableKeyException::class.java))
            }
            else -> Assert.fail("UserVerification remediation expected")
        }
    }

    @Test
    fun `remediate unrecoverable UV then resolve with consent on failure, expect user consent returned`() {
        // arrange
        val keySigner: SignatureProvider = object : SignatureProvider by testKeyStore.testSigner {
            override fun getSignature(alias: String): Signature = throw UnrecoverableKeyException()
        }

        val authenticator = PushAuthenticatorBuilder.create(ApplicationConfig(getApplicationContext(), "test", "version")) {
            signer = keySigner
            encryptionProvider = testKeyStore.encrypt
            deviceStore = testDeviceStorage
            coroutineScope = testScope
            okHttpClient = customOkHttpClient
            useMyAccount = true
        }.getOrThrow()
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = true)).getOrThrow()
        }
        val accountInfo = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first() }
        val method = accountInfo.methodInformation.first { PUSH.isEqual(it.methodType) }
        val transactionId = uuid()
        val pushChallengeJws = createPushJws(enrollment, USER_VERIFICATION_KEY, transactionId, userVerificationChallenge = REQUIRED)

        // sign in
        testServer.fakApiEndpointImpl.signInRequest(enrollment.user().id, method.methodId, method.enrollmentId, transactionId, pushChallengeJws)

        // act
        val parseResult = runBlocking { authenticator.parseChallenge(pushChallengeJws) }.getOrThrow()

        when (val remediation = parseResult.resolve().getOrThrow()) {
            is UserVerificationError -> {
                val userConsent = remediation.resolve(consentOnFailure = true).getOrThrow() as UserConsent
                // assert
                val completed = runBlocking { userConsent.accept().getOrThrow() as Completed }

                // assert
                assertThat(completed.state.userVerificationUsed, `is`(false))
                assertThat(completed.state.accepted, `is`(true))
                assertThat(completed.state.throwable, `is`(nullValue()))
            }
            else -> Assert.fail("UserVerification remediation expected")
        }
    }

    @Test
    fun `remediate unrecoverable UV then repair, expect resolve to return UserVerification`() {
        // arrange
        var repairedUv = false
        val keySigner: SignatureProvider = object : SignatureProvider by testKeyStore.testSigner {
            override fun getSignature(alias: String): Signature? {
                if (repairedUv) return testKeyStore.testSigner.getSignature(alias)
                else throw UnrecoverableKeyException()
            }
        }

        val authenticator = PushAuthenticatorBuilder.create(ApplicationConfig(getApplicationContext(), "test", "version")) {
            signer = keySigner
            encryptionProvider = testKeyStore.encrypt
            deviceStore = testDeviceStorage
            coroutineScope = testScope
            okHttpClient = customOkHttpClient
            useMyAccount = true
        }.getOrThrow()
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = true)).getOrThrow()
        }
        val accountInfo = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first() }
        val method = accountInfo.methodInformation.first { PUSH.isEqual(it.methodType) }
        val transactionId = uuid()
        val pushChallengeJws = createPushJws(enrollment, USER_VERIFICATION_KEY, transactionId, userVerificationChallenge = REQUIRED)

        // sign in
        testServer.fakApiEndpointImpl.signInRequest(enrollment.user().id, method.methodId, method.enrollmentId, transactionId, pushChallengeJws)

        // act
        val parseResult = runBlocking { authenticator.parseChallenge(pushChallengeJws) }.getOrThrow()

        when (val remediation = parseResult.resolve().getOrThrow()) {
            is UserVerificationError -> {
                repairedUv = true
                val result = remediation.resolve(consentOnFailure = false)

                // assert
                assertThat(result.isSuccess, `is`(true))
                assertThat(result.getOrNull(), instanceOf(UserVerification::class.java))
            }
            else -> Assert.fail("UserVerification remediation expected")
        }
    }

    @Test
    fun `remediate with expired token expect security error with invalid token returned`() {
        // arrange
        var invalidTime = false
        val time = DeviceClock {
            if (invalidTime) Instant.now().plus(1, ChronoUnit.DAYS).toEpochMilli() // expired
            else System.currentTimeMillis()
        }
        val authenticator = PushAuthenticatorBuilder.create(ApplicationConfig(getApplicationContext(), "test", "version")) {
            signer = testKeyStore.testSigner
            encryptionProvider = testKeyStore.encrypt
            deviceStore = testDeviceStorage
            coroutineScope = testScope
            deviceClock = time
            okHttpClient = customOkHttpClient
            useMyAccount = true
        }.getOrThrow()

        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking {
            authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = true)).getOrThrow()
        }
        val accountInfo = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first() }
        val method = accountInfo.methodInformation.first { PUSH.isEqual(it.methodType) }
        val transactionId = uuid()
        val pushChallengeJws = createPushJws(enrollment, USER_VERIFICATION_KEY, transactionId, userVerificationChallenge = REQUIRED)

        // sign in
        testServer.fakApiEndpointImpl.signInRequest(enrollment.user().id, method.methodId, method.enrollmentId, transactionId, pushChallengeJws)

        // act
        invalidTime = true
        val parseResult = runBlocking { authenticator.parseChallenge(pushChallengeJws) }

        assertThat(parseResult.isFailure, `is`(true))
        assertThat(parseResult.exceptionOrNull(), instanceOf(InvalidToken::class.java))
    }

    @Test
    fun `call challenge resolve to deny push, expect successful complete status`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking { authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow() }
        val transactionId = uuid()
        val accountInfo = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first() }
        val method = accountInfo.methodInformation.first { PUSH.isEqual(it.methodType) }
        val pushChallengeJws = createPushJws(enrollment, PROOF_OF_POSSESSION_KEY, transactionId)

        // ux handling
        val userInteraction = object : RemediationHandler.UserInteraction {
            override fun confirm(challenge: Challenge): Boolean = false // deny
            override fun userVerification(challenge: Challenge): AuthenticationResult? = null
            override fun fixUserVerificationError(securityError: DeviceAuthenticatorError.SecurityError): Boolean = true
        }
        val handler = RemediationHandler(userInteraction)
        // sign in
        testServer.fakApiEndpointImpl.signInRequest(enrollment.user().id, method.methodId, method.enrollmentId, transactionId, pushChallengeJws)

        // act
        val parseResult = runBlocking { authenticator.parseChallenge(pushChallengeJws) }.getOrThrow()
        val remediation = parseResult.resolve().getOrThrow()
        val completed: Completed = runBlocking { handler.handleRemediation(remediation).getOrThrow() as Completed }

        // assert
        assertThat(completed.state.userVerificationUsed, `is`(false))
        assertThat(completed.state.accepted, `is`(false))
        assertThat(completed.state.throwable, `is`(nullValue()))
    }

    @Test
    fun `call challenge resolve to deny CIBA challenge, expect successful complete status`() {
        // arrange
        val bindingMessage = uuid()
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking { authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableCiba = true)).getOrThrow() }
        val transactionId = uuid()
        val accountInfo = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first() }
        val method = accountInfo.methodInformation.first { PUSH.isEqual(it.methodType) }
        val cibaChallengeJws =
            createPushJws(enrollment, PROOF_OF_POSSESSION_KEY, transactionId, userVerificationChallenge = PREFERRED, transactionType = TransactionType.CIBA, bindingMessage = bindingMessage)

        // fake ciba request
        testServer.fakApiEndpointImpl.signInRequest(enrollment.user().id, method.methodId, method.enrollmentId, transactionId, cibaChallengeJws)

        // act
        val parseResult = runBlocking { authenticator.parseChallenge(cibaChallengeJws) }.getOrThrow()
        val cibaConsent = parseResult.resolve().getOrThrow() as CibaConsent
        val completed = runBlocking { cibaConsent.deny().getOrThrow() as Completed }

        // assert
        assertThat(cibaConsent.bindingMessage, `is`(bindingMessage))
        assertThat(completed.state.userVerificationUsed, `is`(false))
        assertThat(completed.state.accepted, `is`(false))
        assertThat(completed.state.throwable, `is`(nullValue()))
    }

    @Test
    fun `call enroll expect authenticator enrollment returned`() = runTest {
        // arrange
        val userId = uuid()
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey, userId = userId))

        // act
        val enrollment = authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow()

        // assert
        assertThat(enrollment.user().id, `is`(userId))
    }

    @Test
    fun `call allEnrollment expect all enrollments returned`() = runTest {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val authToken2 = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow()

        authenticator.enroll(authToken2, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow()

        // act
        val authenticators: List<PushEnrollment> = authenticator.allEnrollments().getOrThrow()

        // assert
        assertThat(authenticators.size, `is`(2))
    }

    @Test
    fun `multi enrollment with different users on same org expect multiple authenticator enrolled`() = runTest {
        // arrange
        val userId1 = uuid()
        val userId2 = uuid()
        val authToken1 = AuthToken.Bearer(createAuthorizationJwt(serverKey, userId = userId1))
        val authToken2 = AuthToken.Bearer(createAuthorizationJwt(serverKey, userId = userId2))

        // act
        val authenticatorEnrollment1 = authenticator.enroll(authToken1, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow()
        val authenticatorEnrollment2 = authenticator.enroll(authToken2, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow()

        // assert
        assertThat(authenticatorEnrollment1.user().id, `is`(userId1))
        assertThat(authenticatorEnrollment2.user().id, `is`(userId2))
        val enrollments = authenticator.allEnrollments().getOrThrow().map { it.enrollmentId() }
        assertThat(enrollments.containsAll(listOf(authenticatorEnrollment1.enrollmentId(), authenticatorEnrollment2.enrollmentId())), `is`(true))
    }

    @Test
    fun `resolve challenge jws with user verification NONE and uv enabled, expect UserConsent returned`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking { authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = true)).getOrThrow() }
        val pushJws = createPushJws(enrollment, PROOF_OF_POSSESSION_KEY, userVerificationChallenge = UserVerificationChallenge.NONE)

        // act
        val remediation = runBlocking { authenticator.parseChallenge(pushJws).getOrThrow().resolve().getOrThrow() }

        // assert
        assertThat(remediation, instanceOf(UserConsent::class.java))
    }

    @Test
    fun `resolve challenge jws with user verification NONE and uv disable, expect UserConsent returned`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking { authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = false)).getOrThrow() }
        val pushJws = createPushJws(enrollment, PROOF_OF_POSSESSION_KEY, userVerificationChallenge = UserVerificationChallenge.NONE)

        // act
        val remediation = runBlocking { authenticator.parseChallenge(pushJws).getOrThrow().resolve().getOrThrow() }

        // assert
        assertThat(remediation, instanceOf(UserConsent::class.java))
    }

    @Test
    fun `resolve CIBA challenge jws with user verification NONE and uv enabled, expect CibaUserConsent returned`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking { authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = true, enableCiba = true)).getOrThrow() }
        val testBindingMessage = uuid()
        val pushJws =
            createPushJws(enrollment, PROOF_OF_POSSESSION_KEY, userVerificationChallenge = UserVerificationChallenge.NONE, transactionType = TransactionType.CIBA, bindingMessage = testBindingMessage)

        // act
        val remediation = runBlocking { authenticator.parseChallenge(pushJws).getOrThrow().resolve().getOrThrow() }

        // assert
        assertThat(remediation, instanceOf(CibaConsent::class.java))
        assertThat((remediation as CibaConsent).bindingMessage, `is`(testBindingMessage))
    }

    @Test
    fun `resolve CIBA challenge jws with user verification NONE and uv disable, expect CibaUserConsent returned`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking { authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = false, enableCiba = true)).getOrThrow() }
        val testBindingMessage = uuid()
        val pushJws =
            createPushJws(enrollment, PROOF_OF_POSSESSION_KEY, userVerificationChallenge = UserVerificationChallenge.NONE, transactionType = TransactionType.CIBA, bindingMessage = testBindingMessage)

        // act
        val remediation = runBlocking { authenticator.parseChallenge(pushJws).getOrThrow().resolve().getOrThrow() }

        // assert
        assertThat(remediation, instanceOf(CibaConsent::class.java))
        assertThat((remediation as CibaConsent).bindingMessage, `is`(testBindingMessage))
    }

    @Test
    fun `resolve challenge jws with user verification PREFERRED and uv enabled, expect UserVerification returned`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking { authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = true)).getOrThrow() }
        val pushJws = createPushJws(enrollment, USER_VERIFICATION_KEY, userVerificationChallenge = PREFERRED)

        // act
        val remediation = runBlocking { authenticator.parseChallenge(pushJws).getOrThrow().resolve().getOrThrow() }

        // assert
        assertThat(remediation, instanceOf(UserVerification::class.java))
        val userVerification = remediation as UserVerification
        val authenticationResult = mockk<AuthenticationResult>()

        val resultDeny = runBlocking { userVerification.deny() }
        assertThat(resultDeny.isFailure, `is`(true))
        val resultAccept = runBlocking { userVerification.resolve(authenticationResult) }
        assertThat(resultAccept.isSuccess, `is`(true))
    }

    @Test
    fun `resolve challenge jws with user verification PREFERRED and uv disabled, expect UserConsent returned`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking { authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = false)).getOrThrow() }
        val pushJws = createPushJws(enrollment, PROOF_OF_POSSESSION_KEY, userVerificationChallenge = PREFERRED)

        // act
        val remediation = runBlocking { authenticator.parseChallenge(pushJws).getOrThrow().resolve().getOrThrow() }

        // assert
        assertThat(remediation, instanceOf(UserConsent::class.java))
    }

    @Test
    fun `resolve CIBA challenge jws with user verification PREFERRED and uv disabled, expect CibaUserConsent returned`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking { authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = false, enableCiba = true)).getOrThrow() }
        val testBindingMessage = uuid()
        val pushJws = createPushJws(
            enrollment,
            PROOF_OF_POSSESSION_KEY,
            userVerificationChallenge = PREFERRED,
            transactionType = TransactionType.CIBA,
            bindingMessage = testBindingMessage
        )

        // act
        val remediation = runBlocking { authenticator.parseChallenge(pushJws).getOrThrow().resolve().getOrThrow() }

        // assert
        assertThat(remediation, instanceOf(CibaConsent::class.java))
        assertThat((remediation as CibaConsent).bindingMessage, `is`(testBindingMessage))
    }

    @Test
    fun `resolve challenge jws with user verification REQUIRED and uv enabled, expect UserVerification returned`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking { authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = true)).getOrThrow() }
        val pushJws = createPushJws(enrollment, USER_VERIFICATION_KEY, userVerificationChallenge = REQUIRED)

        // act
        val remediation = runBlocking { authenticator.parseChallenge(pushJws).getOrThrow().resolve().getOrThrow() }

        // assert
        assertThat(remediation, instanceOf(UserVerification::class.java))
    }

    @Test
    fun `resolve challenge jws with user verification REQUIRED and uv disabled, expect UserVerificationError returned`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking { authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = false)).getOrThrow() }
        val pushJws = createPushJws(enrollment, PROOF_OF_POSSESSION_KEY, userVerificationChallenge = REQUIRED)

        // act
        val remediation = runBlocking { authenticator.parseChallenge(pushJws).getOrThrow().resolve().getOrThrow() }

        // assert
        assertThat(remediation, instanceOf(UserVerificationError::class.java))
        assertThat((remediation as UserVerificationError).securityError, instanceOf(UserVerificationRequired::class.java))
    }

    @Test
    fun `resolve challenge with invalid user verification key, expect user verification error returned`() {
        // arrange
        val keySigner: SignatureProvider = object : SignatureProvider by testKeyStore.testSigner {
            override fun getSignature(alias: String): Signature? {
                throw UnrecoverableKeyException()
            }
        }

        val authenticator = PushAuthenticatorBuilder.create(ApplicationConfig(getApplicationContext(), "test", "version")) {
            signer = keySigner
            encryptionProvider = testKeyStore.encrypt
            deviceStore = testDeviceStorage
            coroutineScope = testScope
            okHttpClient = customOkHttpClient
            useMyAccount = true
        }.getOrThrow()

        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking { authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = true)).getOrThrow() }
        val pushJws = createPushJws(enrollment, USER_VERIFICATION_KEY, userVerificationChallenge = REQUIRED)

        // act
        val remediation = runBlocking { authenticator.parseChallenge(pushJws).getOrThrow().resolve() }.getOrThrow()

        // assert
        assertThat(remediation, instanceOf(UserVerificationError::class.java))
        assertThat((remediation as UserVerificationError).securityError.cause, instanceOf(UnrecoverableKeyException::class.java))
    }

    @Test
    fun `resolve CIBA challenge with enrollment not support CIBA, expect throw unsupported transaction type`() {
        // arrange
        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val enrollment = runBlocking { authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()), enableUserVerification = true, enableCiba = false)).getOrThrow() }
        val pushJws = createPushJws(enrollment, PROOF_OF_POSSESSION_KEY, userVerificationChallenge = UserVerificationChallenge.NONE, transactionType = TransactionType.CIBA)

        // act
        val remediationResult = runBlocking { authenticator.parseChallenge(pushJws).getOrThrow().resolve() }

        // assert
        assertThat(remediationResult.isFailure, `is`(true))
        assertThat(remediationResult.exceptionOrNull(), instanceOf(DeviceAuthenticatorError.UnsupportedTransactionType::class.java))
    }

    @Test
    fun `multi enrollment with alternate url, expect enrollment to be successful`() {
        // arrange
        // override default endpoint to make the localhost url as alternate
        testServer.setCustomEndpoint(object : FakeApiEndpoint by testServer.fakApiEndpointImpl {
            override fun oktaOrganization(request: RecordedRequest): MockResponse = runCatching {
                MockResponse().setBody(OrganizationGenerator("https://okta.okta.com").createOktaOrganization().toJson())
            }.getOrElse {
                MockResponse().setResponseCode(HTTP_INTERNAL_ERROR).setBody(it.errorResponse().toJson())
            }
        })

        val authToken = AuthToken.Bearer(createAuthorizationJwt(serverKey))
        val authToken2 = AuthToken.Bearer(createAuthorizationJwt(serverKey))

        // act
        val authenticatorEnrollment = runBlocking { authenticator.enroll(authToken, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow() }
        val authenticatorEnrollment2 = runBlocking { authenticator.enroll(authToken2, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow() }

        // assert
        assertThat(authenticatorEnrollment.organization().url, `is`(testServer.url))
        assertThat(authenticatorEnrollment2.organization().url, `is`(testServer.url))
        testServer.setDefaultEndpoint()
    }

    @Test
    fun `approve challenge from multi account scenario, expect approvals are successful`() = runTest {
        // arrange
        val userId1 = uuid()
        val userId2 = uuid()
        val authToken1 = AuthToken.Bearer(createAuthorizationJwt(serverKey, userId = userId1))
        val authToken2 = AuthToken.Bearer(createAuthorizationJwt(serverKey, userId = userId2))
        val authenticatorEnrollment1 = authenticator.enroll(authToken1, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow()
        val authenticatorEnrollment2 = authenticator.enroll(authToken2, config, EnrollmentParameters.Push(FcmToken(uuid()))).getOrThrow()
        val accountInfo1 = testDeviceStorage.accountInformationStore().getByUserId(userId1).first()
        val accountInfo2 = testDeviceStorage.accountInformationStore().getByUserId(userId2).first()
        val method1 = accountInfo1.methodInformation.first { PUSH.isEqual(it.methodType) }
        val method2 = accountInfo2.methodInformation.first { PUSH.isEqual(it.methodType) }

        val transactionId1 = uuid()
        val transactionId2 = uuid()
        val pushChallengeJws1 = createPushJws(authenticatorEnrollment1, PROOF_OF_POSSESSION_KEY, transactionId1)
        val pushChallengeJws2 = createPushJws(authenticatorEnrollment2, PROOF_OF_POSSESSION_KEY, transactionId2)

        // ux handling
        val userInteraction = object : RemediationHandler.UserInteraction {
            override fun confirm(challenge: Challenge): Boolean = true // accept
            override fun userVerification(challenge: Challenge): AuthenticationResult? = null
            override fun fixUserVerificationError(securityError: DeviceAuthenticatorError.SecurityError): Boolean = true
        }
        val handler = RemediationHandler(userInteraction)

        // sign in for user1 and user2
        testServer.fakApiEndpointImpl.signInRequest(userId1, method1.methodId, method1.enrollmentId, transactionId1, oidcClientId, pushChallengeJws1)
        testServer.fakApiEndpointImpl.signInRequest(userId2, method2.methodId, method2.enrollmentId, transactionId2, oidcClientId, pushChallengeJws2)

        // act
        val remediation1 = authenticator.allEnrollments().getOrThrow().first { it.user().id == userId1 }
            .retrievePushChallenges(authToken1).getOrThrow().first()
        val remediation2 = authenticator.allEnrollments().getOrThrow().first { it.user().id == userId2 }
            .retrievePushChallenges(authToken2).getOrThrow().first()

        val completed1: Completed = handler.handleRemediation(remediation1.resolve().getOrThrow()).getOrThrow() as Completed
        val completed2: Completed = handler.handleRemediation(remediation2.resolve().getOrThrow()).getOrThrow() as Completed

        // assert
        assertThat(completed1.state.userVerificationUsed, `is`(false))
        assertThat(completed1.state.accepted, `is`(true))
        assertThat(completed1.state.throwable, `is`(nullValue()))
        assertThat(completed2.state.userVerificationUsed, `is`(false))
        assertThat(completed2.state.accepted, `is`(true))
        assertThat(completed2.state.throwable, `is`(nullValue()))
    }

    @Test
    fun `authorize CIBA challenge from multi account scenario, expect authorization success`() = runTest {
        // arrange
        val userId1 = uuid()
        val bindingMessage1 = uuid()
        val userId2 = uuid()
        val bindingMessage2 = uuid()
        val authToken1 = AuthToken.Bearer(createAuthorizationJwt(serverKey, userId = userId1))
        val authToken2 = AuthToken.Bearer(createAuthorizationJwt(serverKey, userId = userId2))
        val authenticatorEnrollment1 = authenticator.enroll(authToken1, config, EnrollmentParameters.Push(FcmToken(uuid()), enableCiba = true)).getOrThrow()
        val authenticatorEnrollment2 = authenticator.enroll(authToken2, config, EnrollmentParameters.Push(FcmToken(uuid()), enableCiba = true)).getOrThrow()
        val accountInfo1 = testDeviceStorage.accountInformationStore().getByUserId(userId1).first()
        val accountInfo2 = testDeviceStorage.accountInformationStore().getByUserId(userId2).first()
        val method1 = accountInfo1.methodInformation.first { PUSH.isEqual(it.methodType) }
        val method2 = accountInfo2.methodInformation.first { PUSH.isEqual(it.methodType) }

        val transactionId1 = uuid()
        val transactionId2 = uuid()
        val cibaChallengeJws1 = createPushJws(authenticatorEnrollment1, PROOF_OF_POSSESSION_KEY, transactionId1, transactionType = TransactionType.CIBA, bindingMessage = bindingMessage1)
        val cibaChallengeJws2 = createPushJws(authenticatorEnrollment2, PROOF_OF_POSSESSION_KEY, transactionId2, transactionType = TransactionType.CIBA, bindingMessage = bindingMessage2)

        // fake ciba request
        testServer.fakApiEndpointImpl.signInRequest(userId1, method1.methodId, method1.enrollmentId, transactionId1, oidcClientId, cibaChallengeJws1)
        testServer.fakApiEndpointImpl.signInRequest(userId2, method2.methodId, method2.enrollmentId, transactionId2, oidcClientId, cibaChallengeJws2)

        // act
        val remediation1 = authenticator.allEnrollments().getOrThrow().first { it.user().id == userId1 }
            .retrievePushChallenges(authToken1).getOrThrow().first()
        val remediation2 = authenticator.allEnrollments().getOrThrow().first { it.user().id == userId2 }
            .retrievePushChallenges(authToken2).getOrThrow().first()
        val cibaRequest1 = remediation1.resolve().getOrThrow() as CibaConsent
        val cibaRequest2 = remediation2.resolve().getOrThrow() as CibaConsent
        val completed1: Completed = cibaRequest1.accept().getOrThrow() as Completed
        val completed2: Completed = cibaRequest2.accept().getOrThrow() as Completed

        // assert
        assertThat(cibaRequest1.bindingMessage, `is`(bindingMessage1))
        assertThat(cibaRequest2.bindingMessage, `is`(bindingMessage2))
        assertThat(completed1.state.userVerificationUsed, `is`(false))
        assertThat(completed1.state.accepted, `is`(true))
        assertThat(completed1.state.throwable, `is`(nullValue()))
        assertThat(completed2.state.userVerificationUsed, `is`(false))
        assertThat(completed2.state.accepted, `is`(true))
        assertThat(completed2.state.throwable, `is`(nullValue()))
    }

    private fun createPushJws(
        enrollment: PushEnrollment,
        keyType: KeyType,
        challengeId: String = uuid(),
        transactionTime: String = Date(System.currentTimeMillis()).toString(),
        userVerificationChallenge: UserVerificationChallenge = UserVerificationChallenge.NONE,
        aud: String = oidcClientId,
        methodType: MethodType = PUSH,
        transactionType: TransactionType = TransactionType.LOGIN,
        bindingMessage: String = ""
    ): String {
        val accountInfo = runBlocking { testDeviceStorage.accountInformationStore().getByUserId(enrollment.user().id).first() }
        val enrollmentId = accountInfo.enrollmentInformation.enrollmentId
        val method = accountInfo.methodInformation.first { PUSH.isEqual(it.methodType) }
        return createIdxPushJws(
            serverKey, serverKid, testServer.url, enrollmentId, method.methodId, transactionId = challengeId,
            keyTypes = listOf(keyType.serializedName), transactionTime = transactionTime,
            userMediation = UserMediationChallenge.REQUIRED, userVerification = userVerificationChallenge,
            aud = aud, method = methodType, transactionType = transactionType, bindingMessage = bindingMessage,
            verificationUri = "${testServer.url}/idp/myaccount/app-authenticator/challenge/$challengeId/verify"
        )
    }
}