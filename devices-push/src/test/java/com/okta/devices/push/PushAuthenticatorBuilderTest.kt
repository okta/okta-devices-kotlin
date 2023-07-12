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

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.okta.devices.api.model.ApplicationConfig
import com.okta.devices.fake.util.uuid
import com.okta.devices.push.utils.BaseTest
import com.okta.devices.storage.AuthenticatorDatabase
import com.okta.devices.storage.EncryptionOption
import kotlinx.coroutines.runBlocking
import org.hamcrest.CoreMatchers.`is`
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PushAuthenticatorBuilderTest : BaseTest() {
    private val context = ApplicationProvider.getApplicationContext<Application>()
    private val applicationInstallationId = uuid()
    private val inMemoryDataStore = AuthenticatorDatabase.instance(context, EncryptionOption.None, true)

    @Test
    fun `create push authenticator, expect push authenticator returned`() {
        // arrange
        val appConfig = ApplicationConfig(context, "MyApp", "1.0.0", applicationInstallationId)

        // act
        val pushAuthenticator = PushAuthenticatorBuilder.create(appConfig) {
            deviceStore = inMemoryDataStore
            passphrase = "testing passphrase".toByteArray()
        }

        // assert
        assertThat(runBlocking { pushAuthenticator.getOrThrow().allEnrollments() }.isSuccess, `is`(true))
        inMemoryDataStore.close()
    }
}
