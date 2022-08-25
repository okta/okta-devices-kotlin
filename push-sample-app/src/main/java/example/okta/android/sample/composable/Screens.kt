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
package example.okta.android.sample.composable

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.Checkbox
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight.Companion.W400
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.tooling.preview.PreviewParameter
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.okta.devices.push.PushRemediation
import example.okta.android.sample.Constants
import example.okta.android.sample.R
import example.okta.android.sample.app.MainActivity
import example.okta.android.sample.model.UserStatus
import example.okta.android.sample.model.UserStatusPreview

@Composable
@Preview
fun SignInScreen(signInAction: () -> Unit = {}) {
    MagentaBankScaffold(stringResource(id = R.string.app_name)) {
        Column(
            modifier = Modifier
                .padding(16.dp)
                .fillMaxWidth()
                .fillMaxHeight(),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                fontWeight = W400,
                text = stringResource(id = R.string.welcome),
                fontSize = 24.sp
            )
            CommonButton(
                modifier = Modifier,
                signInAction,
                stringResource(id = R.string.sign_in)
            )
        }
    }
}

@Composable
@Preview
fun SetupPushScreen(notNow: () -> Unit = {}, setUp: (enableUv: Boolean) -> Unit = { _ -> }) {
    val (initialState, showDialog) = remember { mutableStateOf(false) }
    val context = LocalContext.current as MainActivity
    val launcher = rememberLauncherForActivityResult(contract = ActivityResultContracts.RequestPermission(), onResult = { isGranted: Boolean ->
        if (isGranted) showDialog(true) else notNow()
    })
    MagentaBankScaffold(stringResource(id = R.string.app_name)) {
        Column(
            modifier = Modifier
                .padding(16.dp)
                .fillMaxWidth()
                .fillMaxHeight(),
            verticalArrangement = Arrangement.SpaceBetween,
            horizontalAlignment = Alignment.Start
        ) {
            Column {
                Text(
                    fontWeight = W400,
                    fontSize = 32.sp,
                    text = stringResource(id = R.string.sign_in_faster)
                )
                Spacer(modifier = Modifier.padding(all = 8.dp))

                Text(
                    fontWeight = W400,
                    text = stringResource(id = R.string.sign_in_faster_body),
                    fontSize = 16.sp
                )
            }
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(all = 10.dp),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                CommonButton(
                    modifier = Modifier.weight(1f),
                    notNow,
                    stringResource(id = R.string.not_now),
                    false
                )
                Spacer(Modifier.size(24.dp))
                CommonButton(modifier = Modifier.weight(1f), {
                    when {
                        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU -> showDialog(true)
                        ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED -> showDialog(true)
                        context.shouldShowRequestPermissionRationale(Manifest.permission.POST_NOTIFICATIONS) -> notNow()
                        else -> launcher.launch(Manifest.permission.POST_NOTIFICATIONS)
                    }
                }, stringResource(id = R.string.set_up))
                // dialog
                CommonDialog(
                    summary = stringResource(id = R.string.enable_uv),
                    primaryText = stringResource(id = R.string.set_up),
                    primaryAction = { setUp(true) },
                    secondaryText = stringResource(id = R.string.not_now),
                    secondaryAction = { setUp(false) },
                    initialState = initialState,
                    showDialog = showDialog
                )
            }
        }
    }
}

@Composable
@Preview
fun HomeScreen(
    @PreviewParameter(UserStatusPreview::class) userStatus: UserStatus,
    enablePushAction: () -> Unit = {},
    updateUvAction: (enableUV: Boolean) -> Unit = {},
    disablePushAction: () -> Unit = {},
    signOutAction: () -> Unit = {},
    refreshAction: () -> Unit = {}
) {
    MagentaBankScaffold(stringResource(id = R.string.app_name)) {
        Column(
            modifier = Modifier
                .padding(16.dp)
        ) {
            Text(
                fontWeight = W400,
                fontSize = 24.sp,
                text = stringResource(id = R.string.welcome_back, userStatus.userName)
            )
            Spacer(modifier = Modifier.padding(all = 8.dp))

            Row(
                Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(fontSize = 14.sp, text = stringResource(id = R.string.enable_push))
                Checkbox(
                    checked = userStatus.pushEnabled,
                    onCheckedChange = { if (it) enablePushAction() else disablePushAction() }
                )
            }

            Row(
                Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(fontSize = 14.sp, text = stringResource(id = R.string.enable_uv))
                Checkbox(
                    checked = userStatus.userVerification,
                    onCheckedChange = { updateUvAction(it) }
                )
            }
            CommonButton(onClick = signOutAction, text = stringResource(id = R.string.sign_out))
            CommonButton(onClick = refreshAction, text = stringResource(id = R.string.check_pending_notification))

            // filler
            Canvas(modifier = Modifier.fillMaxSize()) {
                val canvasSize = size
                drawRect(
                    color = Color(Constants.FILLER_COLOR),
                    topLeft = Offset(x = 0f, y = 0f),
                    size = canvasSize
                )
            }
        }
    }
}

@Composable
@Preview
fun AcceptPushScreen(userConsent: PushRemediation.UserConsent? = null, primaryAction: () -> Unit = {}, secondaryAction: () -> Unit = {}) {
    CommonDialog(
        title = stringResource(id = R.string.dialog_sign_in_title),
        summary =
        """
        ${userConsent?.challenge?.appInstanceName ?: "AppName"}
        ${userConsent?.challenge?.clientLocation ?: "ClientLocation"}
        ${userConsent?.challenge?.clientOs ?: "ClientOS"}
        ${userConsent?.challenge?.originUrl ?: "OriginUrl"}
        ${userConsent?.challenge?.transactionTime ?: "TransactionTime"}
        """.trimIndent(),
        primaryText = stringResource(id = R.string.accept_text),
        primaryAction = primaryAction,
        secondaryText = stringResource(id = R.string.deny_text),
        secondaryAction = secondaryAction
    )
}
