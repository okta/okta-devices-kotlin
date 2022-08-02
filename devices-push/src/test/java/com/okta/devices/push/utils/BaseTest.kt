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
package com.okta.devices.push.utils

import androidx.annotation.CallSuper
import com.okta.devices.fake.util.isRobolectric
import io.mockk.MockKAnnotations
import io.mockk.unmockkAll
import org.junit.After
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.robolectric.shadows.ShadowLog
import java.security.Provider
import java.security.Security

open class BaseTest {
    init {
        if (isRobolectric()) ShadowLog.stream = System.out
    }

    companion object {

        @BeforeClass
        @JvmStatic
        fun beforeClass() {
            if (isRobolectric()) {
                Security.insertProviderAt(
                    object : Provider("AndroidKeyStore", 1.0, "Mock keystore") {
                        init {
                            this["KeyStore.AndroidKeyStore"] = "sun.security.provider.JavaKeyStore\$DualFormatJKS"
                            this["KeyPairGenerator.RSA"] = "sun.security.rsa.RSAKeyPairGenerator\$Legacy"
                        }
                    },
                    Security.getProviders().size
                )
            }
        }

        @AfterClass
        @JvmStatic
        fun afterClass() {
            if (isRobolectric()) Security.removeProvider("AndroidKeyStore")
        }
    }

    @Before
    @CallSuper
    open fun setUp() {
        MockKAnnotations.init(this)
    }

    @After
    @CallSuper
    open fun tearDown() {
        unmockkAll()
    }
}
