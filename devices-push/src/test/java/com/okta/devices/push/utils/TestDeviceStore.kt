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

import com.okta.devices.storage.api.AccountInformationStore
import com.okta.devices.storage.api.DeviceStore
import com.okta.devices.storage.api.MethodInformationStore
import com.okta.devices.storage.model.AccountInformation

/**
 * This is used for tests that require InstantTaskExecutorRule to run architecture component (Room) tasks synchronously for immediate results.
 * The observation is that the room annotation @Transaction causes a deadlock for the save method but not the query transactions.
 * The instant task rule seems to conflict with the transaction and causes a deadlock. We can't use set setTransactionExecutor because this won't
 * trigger the flow/live data updates. The only way is to override the save method that uses @Transaction and perform the transactions separately.
 *
 * @property roomDeviceStorage
 */
class TestDeviceStore(private val roomDeviceStorage: DeviceStore) : DeviceStore by roomDeviceStorage {
    override fun accountInformationStore(): AccountInformationStore {
        val accountStore = roomDeviceStorage.accountInformationStore()
        return object : AccountInformationStore by accountStore {
            override suspend fun save(accountInformation: AccountInformation) {
                accountStore.insert(accountInformation.deviceInformation)
                accountStore.insert(accountInformation.organizationInformation)
                if (accountStore.insert(accountInformation.enrollmentInformation) == -1L) {
                    accountStore.update(accountInformation.enrollmentInformation)
                }
                accountStore.insert(*accountInformation.methodInformation.toTypedArray())
            }
        }
    }

    override fun methodInformationStore(): MethodInformationStore {
        val methodStore = roomDeviceStorage.methodInformationStore()
        return object : MethodInformationStore by methodStore {
            override suspend fun updateStatus(statusMap: Map<String, String>) {
                statusMap.forEach { methodStore.updateStatus(it.key, it.value) }
            }
        }
    }
}
