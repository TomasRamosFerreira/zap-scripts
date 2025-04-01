/*
 * HTTP Sender script for ZAP to handle Bearer token authentication and automatic refresh
 * Author: Ice Fox
 * Date: 2025-04-01
 * Version: 1.7
 */

const ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");
const HttpSender = Java.type("org.parosproxy.paros.network.HttpSender");
const HttpMessage = Java.type("org.parosproxy.paros.network.HttpMessage");
const HttpRequestHeader = Java.type(
	"org.parosproxy.paros.network.HttpRequestHeader"
);
const HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
const URI = Java.type("org.apache.commons.httpclient.URI");

const sender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);

function sendingRequest(msg, initiator, helper) {
	try {
		print("🚀 [sendingRequest] Starting Bearer token setup...\n");

		const accessToken = ScriptVars.getGlobalVar("accessToken");

		if (accessToken) {
			msg
				.getRequestHeader()
				.setHeader("Authorization", "Bearer " + accessToken);
			print("✅ [sendingRequest] Bearer token added to request.\n");
		} else {
			print("⚠️ [sendingRequest] No Bearer token available.\n");
		}

		print("✅ [sendingRequest] Finished Bearer token setup.\n\n");
	} catch (error) {
		print("❌ [sendingRequest] Error: " + error.message + "\n");
	}
}

function responseReceived(msg, initiator, helper) {
	try {
		const statusCode = msg.getResponseHeader().getStatusCode();
		const requestUrl = msg.getRequestHeader().getURI().toString();
		const requestMethod = msg.getRequestHeader().getMethod();

		print(
			`📬 [responseReceived] ${requestMethod} ${requestUrl} responded with status ${statusCode}\n`
		);

		const refreshUrl = ScriptVars.getGlobalVar("refreshUrl");
		const refreshTokenAccessor =
			ScriptVars.getGlobalVar("refreshTokenAccessor") ?? "refresh_token";
		const accessTokenAccessor =
			ScriptVars.getGlobalVar("tokenAccessor") ?? "access_token";

		if (statusCode == 511) {
			print("⚠️ [511] Network Authentication Required detected.\n");

			const accessToken = ScriptVars.getGlobalVar("accessToken");
			if (accessToken) {
				print("♻️ [511] Retrying request with existing token...\n");
				msg
					.getRequestHeader()
					.setHeader("Authorization", "Bearer " + accessToken);
				try {
					sender.sendAndReceive(msg, false);
					print("✅ [511] Request successfully resent with existing token.\n");
				} catch (retryError) {
					print(
						"❌ [511] Error resending request: " + retryError.message + "\n"
					);
				}
			} else {
				print(
					"🔐 [511] No access token found, clearing tokens to force re-authentication.\n"
				);

				// Clearing token forces the next request (initiated by ZAP authentication context)
				// to trigger the authentication script again
				ScriptVars.setGlobalVar("accessToken", null);
			}
		}

		// Refresh token logic only if 401 Unauthorized and x-token-expired header is set
		if (
			statusCode === 401 &&
			msg.getResponseHeader().getHeader("x-token-expired")
		) {
			print("🔄 [401] Token expired, attempting refresh...\n");

			const refreshToken = ScriptVars.getGlobalVar("refreshToken");
			if (!refreshUrl || !refreshToken) {
				print("⚠️ [401] Refresh URL or refresh token missing.\n");
				return;
			}

			const refreshBody = JSON.stringify({
				[refreshTokenAccessor]: refreshToken,
			});
			const requestHeader = new HttpRequestHeader(
				HttpRequestHeader.POST,
				new URI(refreshUrl, false),
				HttpHeader.HTTP11
			);
			requestHeader.setHeader(HttpHeader.CONTENT_TYPE, "application/json");
			requestHeader.setContentLength(refreshBody.length);

			const refreshMsg = new HttpMessage(requestHeader);
			refreshMsg.setRequestBody(refreshBody);

			try {
				sender.sendAndReceive(refreshMsg, false);
				print("📨 [401] Refresh token request sent.\n");
			} catch (refreshError) {
				print(
					"❌ [401] Failed sending refresh request: " +
						refreshError.message +
						"\n"
				);
				return;
			}

			const refreshStatus = refreshMsg.getResponseHeader().getStatusCode();
			print("📩 [401] Refresh token response status: " + refreshStatus + "\n");

			if (refreshStatus === 200) {
				const response = JSON.parse(refreshMsg.getResponseBody().toString());
				const newAccessToken = response[accessTokenAccessor];
				const newRefreshToken = response[refreshTokenAccessor];

				if (newAccessToken) {
					ScriptVars.setGlobalVar("accessToken", newAccessToken);
					msg
						.getRequestHeader()
						.setHeader("Authorization", "Bearer " + newAccessToken);
					print("🎉 [401] Access token refreshed successfully!\n");

					try {
						sender.sendAndReceive(msg, false);
						print("🔁 [401] Original request successfully resent.\n");
					} catch (resendError) {
						print(
							"❌ [401] Error resending original request: " +
								resendError.message +
								"\n"
						);
					}
				} else {
					print("⚠️ [401] New access token not found in refresh response.\n");
				}
			} else {
				print("❌ [401] Refresh failed with status: " + refreshStatus + "\n");
			}
		}
	} catch (error) {
		print("🔥 [responseReceived] Exception: " + error.message + "\n");
	}
}
