/*
 * HTTP Sender script for ZAP to handle Bearer token authentication and automatic refresh
 * Author: Ice Fox
 * Date: 2025-03-17
 * Version: 1.6
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

		const accessToken = ScriptVars.getGlobalVar("access_token");

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
		// Extract response details
		const statusCode = msg.getResponseHeader().getStatusCode();
		const requestUrl = msg.getRequestHeader().getURI().toString();
		const requestMethod = msg.getRequestHeader().getMethod();

		print(
			`📬 [responseReceived] ${requestMethod} ${requestUrl} responded with status ${statusCode}\n`
		);

		// Retrieve global variables
		const refreshUrl = ScriptVars.getGlobalVar("refreshUrl");
		const refreshTokenAccessor =
			ScriptVars.getGlobalVar("refreshTokenAccessor") || "refresh_token";
		const accessTokenAccessor =
			ScriptVars.getGlobalVar("tokenAccessor") || "access_token";

		// If 511 Network Authentication Required, attempt to resend request with existing token
		if (statusCode == 511) {
			print("⚠️ [511] Network Authentication Required detected.\n");

			const accessToken = ScriptVars.getGlobalVar("access_token");
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
				ScriptVars.setGlobalVar("access_token", null);
			}
		}

		// If 401 Unauthorized and token expired, attempt to refresh token
		if (
			statusCode === 401 &&
			msg.getResponseHeader().getHeader("x-token-expired")
		) {
			print("🔄 [401] Token expired, attempting refresh...\n");

			const refreshToken = ScriptVars.getGlobalVar("refresh_token");
			if (!refreshUrl || !refreshToken) {
				print("⚠️ [401] Refresh URL or refresh token missing.\n");
				return;
			}

			const refreshBody = JSON.stringify({ refresh_token: refreshToken });
			const requestHeader = new HttpRequestHeader(
				HttpRequestHeader.POST,
				new URI(refreshUrl, false),
				HttpHeader.HTTP11
			);
			requestHeader.setHeader(HttpHeader.CONTENT_TYPE, "application/json");
			requestHeader.setContentLength(refreshBody.length);

			const refreshMsg = new HttpMessage(requestHeader);
			refreshMsg.setRequestBody(refreshBody);

			// Try to refresh the token
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

			// If refresh was successful, update the access token
			if (refreshStatus === 200) {
				const response = JSON.parse(refreshMsg.getResponseBody().toString());
				const newAccessToken = response[accessTokenAccessor];
				const newRefreshToken = response[refreshTokenAccessor];

				// If new access token found, update the global variable and resend the original request
				if (newAccessToken) {
					ScriptVars.setGlobalVar("access_token", newAccessToken);
					msg
						.getRequestHeader()
						.setHeader("Authorization", "Bearer " + newAccessToken);
					print("🎉 [401] Access token refreshed successfully!\n");

					// If new refresh token found, update the global variable, otherwise clear it
					if (newRefreshToken) {
						ScriptVars.setGlobalVar("refresh_token", newRefreshToken);
						print("♻️ [401] Refresh token updated.\n");
					} else {
						ScriptVars.setGlobalVar("refresh_token", null);
						print("⚠️ [401] No new refresh token found in response.\n");
					}

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
					// If new access token not found, clear the tokens to force re-authentication
					ScriptVars.setGlobalVar("access_token", null);
					ScriptVars.setGlobalVar("refresh_token", null);
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
