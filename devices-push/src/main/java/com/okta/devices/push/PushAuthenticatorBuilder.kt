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
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Build
import android.provider.Settings
import com.okta.devices.BuildConfig
import com.okta.devices.DeviceAuthenticatorCore
import com.okta.devices.api.device.DeviceInfoCollector
import com.okta.devices.api.device.DiskEncryptionType
import com.okta.devices.api.device.ScreenLockType
import com.okta.devices.api.log.DeviceLog
import com.okta.devices.api.model.ApplicationConfig
import com.okta.devices.api.security.EncryptionProvider
import com.okta.devices.api.security.SignatureProvider
import com.okta.devices.api.time.DeviceClock
import com.okta.devices.authenticator.Modules
import com.okta.devices.device.KeyInfoHint
import com.okta.devices.device.OrgInfoHint
import com.okta.devices.encrypt.AESEncryptionProvider
import com.okta.devices.encrypt.CryptoFactory
import com.okta.devices.encrypt.DeviceKeyStoreImpl
import com.okta.devices.encrypt.RsaSignature
import com.okta.devices.http.DeviceOkHttpClient
import com.okta.devices.http.UserAgentImpl
import com.okta.devices.push.api.PushAuthenticator
import com.okta.devices.storage.AuthenticatorDatabase
import com.okta.devices.storage.EncryptionOption
import com.okta.devices.storage.api.DeviceStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import okhttp3.OkHttpClient

/**
 * Builder class for configuring and instantiating PushAuthenticator instance.
 *
 * @constructor
 * Create a builder with the Android application context.
 *
 * @param context Android application context.
 */
class PushAuthenticatorBuilder internal constructor(context: Application) {
    internal var deviceStore: DeviceStore? = null
    internal var deviceClock: DeviceClock = DeviceClock { System.currentTimeMillis() }
    internal var coroutineScope: CoroutineScope = CoroutineScope(Job() + Dispatchers.IO)
    internal var deviceInfoCollector: DeviceInfoCollector = object : DeviceInfoCollector {
        private val keyguardManager = context.getSystemService(KeyguardManager::class.java)
        private val devicePolicyManager = context.getSystemService(DevicePolicyManager::class.java)
        private val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)

        override fun appVersion(): String = packageInfo?.versionName ?: Build.UNKNOWN
        override fun appBundleId(): String = packageInfo?.applicationInfo?.packageName ?: Build.UNKNOWN
        override fun userDefinedDeviceName(): String {
            // Settings.Global.device_name seems to have the most success among more recent devices.
            return Settings.Global.getString(context.contentResolver, "device_name")
                ?: Settings.Secure.getString(context.contentResolver, "device_name")
                // May work better for older devices.
                ?: Settings.System.getString(context.contentResolver, "bluetooth_name")
                ?: Settings.Secure.getString(context.contentResolver, "bluetooth_name")
                ?: Build.MODEL
        }

        override fun screenLockType(): ScreenLockType = when (keyguardManager?.isDeviceSecure) {
            true -> ScreenLockType.PASSCODE
            else -> ScreenLockType.NONE
        }

        override fun serialNumber(): String? = null

        override fun udid(): String? = null

        override fun diskEncryptionType(): DiskEncryptionType {
            val diskEncryptionStatus = devicePolicyManager?.storageEncryptionStatus
                ?: DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED
            return when (diskEncryptionStatus) {
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER -> DiskEncryptionType.USER
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE,
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY,
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVATING,
                -> DiskEncryptionType.FULL

                else -> DiskEncryptionType.NONE
            }
        }

        override fun managementHint(): String? = null
    }

    private val deviceKeyStore = lazy { DeviceKeyStoreImpl() }
    internal var signer: SignatureProvider = RsaSignature(deviceKeyStore.value)
    internal var encryptionProvider: EncryptionProvider = AESEncryptionProvider(deviceKeyStore.value)
    internal var useMyAccount = true

    /**
     * Set the okhttp client
     */
    var okHttpClient: OkHttpClient = OkHttpClient.Builder().build()

    /**
     * Sets the logging interface for the push authenticator
     */
    var deviceLog: DeviceLog = object : DeviceLog {}

    /**
     * UTF_8 encoding ByteArray format used for encrypting the database. If this is left as null then the database will not be encrypted.
     */
    var passphrase: ByteArray? = null

    companion object {
        /**
         * Create an instance of PushAuthenticator with default configuration and optionally modified with buildAction
         *
         * @param appConfig Application specific parameters such as version and app name.
         * @param buildAction Optional for modifying default parameters
         * @return [Result.success] of [PushAuthenticator] or [Result.failure] with the following exceptions:
         * KeyStoreException if no Provider supports a KeyStoreSpi implementation for the SignatureProvider or EncryptionProvider
         */
        fun create(appConfig: ApplicationConfig, buildAction: (PushAuthenticatorBuilder.() -> Unit)? = null): Result<PushAuthenticator> = runCatching {
            val builder = PushAuthenticatorBuilder(appConfig.context)
            buildAction?.invoke(builder)
            val modules = builder.build(appConfig.context)
            Result.success(PushAuthenticatorImpl(DeviceAuthenticatorCore(appConfig, modules), builder.useMyAccount))
        }.getOrElse { Result.failure(it) }
    }

    private fun build(context: Context): Modules {
        // transform to Devices SDK values
        val cryptoFactory: CryptoFactory = object : CryptoFactory {
            override fun getDigitalSignatureByKey(keyInfoHint: KeyInfoHint): SignatureProvider = signer
            override fun getDigitalSignatureByOrgInfo(orgInfoHint: OrgInfoHint): SignatureProvider = signer
            override fun getEncryptionProvideByOrgInfo(orgInfoHint: OrgInfoHint): EncryptionProvider = encryptionProvider
            override fun getEncryptionProviderByKey(keyInfoHint: KeyInfoHint): EncryptionProvider = encryptionProvider
        }

        if (deviceStore == null) {
            deviceStore = AuthenticatorDatabase.instance(context, passphrase?.let { EncryptionOption.SQLCipher.create(it).getOrThrow() } ?: EncryptionOption.None)
        }

        return Modules(
            checkNotNull(deviceStore),
            cryptoFactory,
            DeviceOkHttpClient(UserAgentImpl(context, BuildConfig.VERSION_NAME), okHttpClient),
            deviceClock,
            deviceLog,
            deviceInfoCollector,
            coroutineScope
        )
    }
}
