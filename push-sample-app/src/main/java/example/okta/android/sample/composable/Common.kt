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

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.ClickableText
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.AlertDialog
import androidx.compose.material.Button
import androidx.compose.material.ButtonDefaults
import androidx.compose.material.CircularProgressIndicator
import androidx.compose.material.Scaffold
import androidx.compose.material.Text
import androidx.compose.material.TopAppBar
import androidx.compose.material.contentColorFor
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import example.okta.android.sample.Constants
import example.okta.android.sample.R
import kotlinx.coroutines.delay

@Composable
@Preview
fun MagentaBankScaffold(
    title: String = "MagentaBank",
    navigationIcon: @Composable (() -> Unit)? = null,
    content: @Composable (paddingValues: PaddingValues) -> Unit = {}
) {
    Scaffold(topBar = {
        TopAppBar(
            navigationIcon = navigationIcon,
            title = {
                Text(
                    modifier = Modifier.fillMaxWidth(),
                    text = title,
                    textAlign = TextAlign.Center
                )
            }
        )
    }) {
        content(it)
    }
}

@Composable
@Preview
fun ErrorState(errorSummary: String? = null, throwable: Throwable? = Exception(), doneAction: () -> Unit = {}) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .fillMaxHeight()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        throwable?.let { error ->
            Text(text = error.cause?.stackTraceToString() ?: error.stackTraceToString())
        } ?: Text(text = errorSummary ?: stringResource(id = R.string.unknown))
        CommonButton(modifier = Modifier, doneAction, stringResource(id = R.string.back))
    }
}

@Composable
fun LoadingState() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .fillMaxHeight(),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        CircularProgressIndicator()
    }
}

@Composable
@Preview
fun CommonButton(
    modifier: Modifier = Modifier,
    onClick: () -> Unit = {},
    text: String = "Button",
    positive: Boolean = true
) {
    Button(
        colors = if (positive) ButtonDefaults.buttonColors() else ButtonDefaults.buttonColors(backgroundColor = Color.White),
        onClick = { onClick() },
        modifier = modifier,
        border = BorderStroke(width = 1.dp, brush = if (positive) SolidColor(Color.Magenta) else SolidColor(Color.Black)),
        shape = RoundedCornerShape(18.dp)
    ) {
        Text(text = text, color = if (positive) Color.White else Color.Black)
    }
}

@Composable
@Preview
fun CommonDialog(
    modifier: Modifier = Modifier,
    title: String? = null,
    summary: String = "Dialog summary",
    primaryText: String = "PrimaryText",
    primaryAction: () -> Unit = {},
    secondaryText: String? = null,
    secondaryAction: () -> Unit = {},
    dismissAction: () -> Unit = {},
    initialState: Boolean = true,
    showDialog: (Boolean) -> Unit = { _ -> }
) {
    if (initialState) {
        AlertDialog(
            modifier = Modifier,
            backgroundColor = Color(0xFFFFFBFE),
            contentColor = contentColorFor(Color(0xFFFFFBFE)),
            shape = RoundedCornerShape(20.dp),
            onDismissRequest = { dismissAction() },
            title = title?.run {
                {
                    Text(
                        modifier = Modifier.fillMaxWidth(),
                        textAlign = TextAlign.Center,
                        text = this
                    )
                }
            },
            text = {
                Column(
                    Modifier
                        .verticalScroll(rememberScrollState())
                        .fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(textAlign = TextAlign.Center, text = summary)
                }
            },
            buttons = {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .padding(all = 15.dp),
                    horizontalArrangement = Arrangement.End
                ) {
                    secondaryText?.let {
                        ClickableText(
                            style = TextStyle(color = Color(0xFF6750A4)),
                            text = AnnotatedString(secondaryText),
                            onClick = {
                                secondaryAction()
                                showDialog(false)
                            }
                        )
                        Spacer(Modifier.size(24.dp))
                    }

                    ClickableText(
                        style = TextStyle(color = Color(0xFF6750A4)),
                        text = AnnotatedString(primaryText),
                        onClick = {
                            primaryAction()
                            showDialog(false)
                        }
                    )
                }
            }
        )
    }
}

@Composable
@Preview
fun ChallengeCompleted(finishAction: () -> Unit = {}) {
    val currentFinishAction by rememberUpdatedState(finishAction)
    CommonDialog(
        title = stringResource(id = R.string.verify_success_title),
        summary = stringResource(id = R.string.verify_success_summary),
        primaryText = stringResource(id = R.string.close),
        primaryAction = finishAction
    )
    LaunchedEffect(true) {
        delay(Constants.DISMISS_DELAY_MS)
        currentFinishAction()
    }
}
