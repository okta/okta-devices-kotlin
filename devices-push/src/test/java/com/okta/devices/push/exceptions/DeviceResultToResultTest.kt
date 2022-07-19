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
package com.okta.devices.push.exceptions

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.okta.devices.api.errors.DeviceAuthenticatorError.InternalDeviceError
import com.okta.devices.api.errors.DeviceAuthenticatorError.LocalResourceError
import com.okta.devices.api.errors.DeviceAuthenticatorError.NetworkError
import com.okta.devices.api.errors.DeviceAuthenticatorError.SecurityError
import com.okta.devices.api.errors.DeviceAuthenticatorError.ServerApiError
import com.okta.devices.authenticator.exceptions.toResult
import com.okta.devices.model.ErrorCode
import com.okta.devices.model.ErrorCode.DEVICE_INFO_NOT_FOUND
import com.okta.devices.model.ErrorCode.ENROLLMENT_INFO_NOT_FOUND
import com.okta.devices.model.ErrorCode.EXCEPTION
import com.okta.devices.model.ErrorCode.INVALID_OR_EXPIRED_TOKEN
import com.okta.devices.model.ErrorCode.KEY_NOT_FOUND
import com.okta.devices.model.ErrorCode.METHOD_INFO_NOT_FOUND
import com.okta.devices.model.ErrorCode.METHOD_NOT_FOUND
import com.okta.devices.model.ErrorCode.RESPONSE_NOT_FOUND
import com.okta.devices.model.ErrorCode.USER_INFO_NOT_FOUND
import com.okta.devices.model.ErrorCode.USER_VERIFICATION_FAILED
import com.okta.devices.model.ErrorResponse
import com.okta.devices.request.DeviceResult.Error
import io.jsonwebtoken.security.SignatureException
import org.hamcrest.CoreMatchers.instanceOf
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Test
import org.junit.runner.RunWith
import java.io.IOException
import java.net.SocketTimeoutException
import java.security.GeneralSecurityException

@RunWith(AndroidJUnit4::class)
class DeviceResultToResultTest {

    @Test
    fun `test security result conversions, expect security error`() {
        // arrange
        val signatureException = Error(ErrorResponse(EXCEPTION.value, exception = SignatureException("")))
        val generalSecurityException = Error(ErrorResponse(EXCEPTION.value, exception = GeneralSecurityException("")))
        val userVerificationException = Error(ErrorResponse(USER_VERIFICATION_FAILED.value))
        val tokenException = Error(ErrorResponse(INVALID_OR_EXPIRED_TOKEN.value))
        // act
        val signatureError = signatureException.toResult()
        val generalSecurityError = generalSecurityException.toResult()
        val userVerificationError = userVerificationException.toResult()
        val tokenError = tokenException.toResult()

        // assert
        assertThat(signatureError.exceptionOrNull(), instanceOf(SecurityError::class.java))
        assertThat(generalSecurityError.exceptionOrNull(), instanceOf(SecurityError::class.java))
        assertThat(userVerificationError.exceptionOrNull(), instanceOf(SecurityError::class.java))
        assertThat(tokenError.exceptionOrNull(), instanceOf(SecurityError::class.java))
    }

    @Test
    fun `test network result conversions, expect network error for net packages and internal error for io exception`() {
        // arrange
        val socketException = Error(ErrorResponse(EXCEPTION.value, exception = SocketTimeoutException("")))
        val ioException = Error(ErrorResponse(EXCEPTION.value, exception = IOException("")))

        // act
        val socketError = socketException.toResult()
        val ioError = ioException.toResult()

        // assert
        assertThat(socketError.exceptionOrNull(), instanceOf(NetworkError::class.java))
        assertThat(ioError.exceptionOrNull(), instanceOf(InternalDeviceError::class.java))
    }

    @Test
    fun `test resource result conversions, expect resource error for resource not found categories`() {
        // arrange
        val keyNotFound = Error(ErrorResponse(KEY_NOT_FOUND.value))
        val methodNotFound = Error(ErrorResponse(METHOD_NOT_FOUND.value))
        val enrollmentNotFound = Error(ErrorResponse(ENROLLMENT_INFO_NOT_FOUND.value))
        val userInfoNotFound = Error(ErrorResponse(USER_INFO_NOT_FOUND.value))
        val deviceInfoNotFound = Error(ErrorResponse(DEVICE_INFO_NOT_FOUND.value))
        val methodInfoNotFound = Error(ErrorResponse(METHOD_INFO_NOT_FOUND.value))
        val responseNotFound = Error(ErrorResponse(RESPONSE_NOT_FOUND.value))

        // act
        val keyNotFoundError = keyNotFound.toResult()
        val methodNotFoundError = methodNotFound.toResult()
        val enrollmentNotFoundError = enrollmentNotFound.toResult()
        val userInfoNotFoundError = userInfoNotFound.toResult()
        val deviceInfoNotFoundError = deviceInfoNotFound.toResult()
        val methodInfoNotFoundError = methodInfoNotFound.toResult()
        val responseNotFoundError = responseNotFound.toResult()

        // assert
        assertThat(keyNotFoundError.exceptionOrNull(), instanceOf(LocalResourceError::class.java))
        assertThat(methodNotFoundError.exceptionOrNull(), instanceOf(LocalResourceError::class.java))
        assertThat(enrollmentNotFoundError.exceptionOrNull(), instanceOf(LocalResourceError::class.java))
        assertThat(userInfoNotFoundError.exceptionOrNull(), instanceOf(LocalResourceError::class.java))
        assertThat(deviceInfoNotFoundError.exceptionOrNull(), instanceOf(LocalResourceError::class.java))
        assertThat(methodInfoNotFoundError.exceptionOrNull(), instanceOf(LocalResourceError::class.java))
        assertThat(responseNotFoundError.exceptionOrNull(), instanceOf(LocalResourceError::class.java))
    }

    @Test
    fun `test backend api result conversions, expect api error for backend response categories`() {
        // arrange
        val apiValidation = Error(ErrorResponse(ErrorCode.API_VALIDATION.value))
        val authentication = Error(ErrorResponse(ErrorCode.AUTHENTICATION_EXCEPTION.value))
        val resourceNotFound = Error(ErrorResponse(ErrorCode.RESOURCE_NOT_FOUND.value))
        val deviceSuspended = Error(ErrorResponse(ErrorCode.DEVICE_SUSPENDED_DEACTIVATED.value))
        val deviceNotFound = Error(ErrorResponse(ErrorCode.DEVICE_NOT_FOUND.value))
        val enrollmentInactive = Error(ErrorResponse(ErrorCode.ENROLLMENT_INACTIVE.value))
        val userNotActive = Error(ErrorResponse(ErrorCode.USER_NOT_ACTIVE.value))
        val invalidUserId = Error(ErrorResponse(ErrorCode.INVALID_USER_ID.value))
        val biometricCompliance = Error(ErrorResponse(ErrorCode.BIOMETRICS_COMPLIANCE_ERROR.value))
        val fipsCompliance = Error(ErrorResponse(ErrorCode.FIPS_COMPLIANCE_ERROR.value))
        val enrollmentSuspended = Error(ErrorResponse(ErrorCode.ENROLLMENT_SUSPENDED.value))

        // act
        val apiValidationError = apiValidation.toResult()
        val authenticatorError = authentication.toResult()
        val deviceSuspendedError = deviceSuspended.toResult()
        val resourceNotFoundError = resourceNotFound.toResult()
        val deviceNotFoundError = deviceNotFound.toResult()
        val enrollmentInactiveError = enrollmentInactive.toResult()
        val userNotActiveError = userNotActive.toResult()
        val invalidUserIdError = invalidUserId.toResult()
        val biometricComplianceError = biometricCompliance.toResult()
        val fipsComplianceError = fipsCompliance.toResult()
        val enrollmentSuspendedError = enrollmentSuspended.toResult()

        // assert
        assertThat(apiValidationError.exceptionOrNull(), instanceOf(ServerApiError::class.java))
        assertThat(authenticatorError.exceptionOrNull(), instanceOf(ServerApiError::class.java))
        assertThat(deviceSuspendedError.exceptionOrNull(), instanceOf(ServerApiError::class.java))
        assertThat(resourceNotFoundError.exceptionOrNull(), instanceOf(ServerApiError::class.java))
        assertThat(deviceNotFoundError.exceptionOrNull(), instanceOf(ServerApiError::class.java))
        assertThat(enrollmentInactiveError.exceptionOrNull(), instanceOf(ServerApiError::class.java))
        assertThat(userNotActiveError.exceptionOrNull(), instanceOf(ServerApiError::class.java))
        assertThat(invalidUserIdError.exceptionOrNull(), instanceOf(ServerApiError::class.java))
        assertThat(biometricComplianceError.exceptionOrNull(), instanceOf(ServerApiError::class.java))
        assertThat(fipsComplianceError.exceptionOrNull(), instanceOf(ServerApiError::class.java))
        assertThat(enrollmentSuspendedError.exceptionOrNull(), instanceOf(ServerApiError::class.java))
    }
}
