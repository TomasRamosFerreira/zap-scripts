/*
 * HTTP Sender script for ZAP to handle Bearer token authentication and automatic refresh
 * Author: Tomás Ferreira
 * Date: 2025-03-17
 * Version: 1.5
 */

const ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");
const HttpSender = Java.type("org.parosproxy.paros.network.HttpSender");
const HttpMessage = Java.type("org.parosproxy.paros.network.HttpMessage");
const HttpRequestHeader = Java.type("org.parosproxy.paros.network.HttpRequestHeader");
const HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
const URI = Java.type("org.apache.commons.httpclient.URI");

const sender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);

function sendingRequest(msg, initiator, helper) {
    try {
        print("[sendingRequest] Setting Authorization header.");

        const accessToken = ScriptVars.getGlobalVar("access_token");
        
        if (accessToken) {
            msg.getRequestHeader().setHeader("Authorization", "Bearer " + accessToken);
            print("✅ Access token successfully added to request.");
        } else {
            print("⚠️ No access token available to add to request.");
        }
    } catch (error) {
        print("❌ Error in sendingRequest: " + error.message);
    }
}

function responseReceived(msg, initiator, helper) {
    try {
        const statusCode = msg.getResponseHeader().getStatusCode();
        const requestUrl = msg.getRequestHeader().getURI().toString();
        const requestMethod = msg.getRequestHeader().getMethod();

        print(`📩 Response received (${requestMethod} ${requestUrl}), Status: ${statusCode}`);

        // Only attempt refresh on 401 Unauthorized or 511 Network Authentication Required
        if (statusCode === 401 || statusCode === 511) {
            print("🔄 Token expired detected, attempting refresh...");

            const refreshUrl = ScriptVars.getGlobalVar("refreshUrl");
            const refreshToken = ScriptVars.getGlobalVar("refresh_token");
            const accessTokenAccessor = ScriptVars.getGlobalVar("tokenAccessor") || "access_token";
            const refreshTokenAccessor = ScriptVars.getGlobalVar("refreshTokenAccessor") || "refresh_token";

            if (!refreshUrl || !refreshToken) {
                print("⚠️ Refresh URL or refresh token not set. Aborting refresh attempt.");
                return;
            }

            // Prepare refresh token request
            const refreshRequestBody = JSON.stringify({ refreshToken: refreshToken });

            const requestHeader = new HttpRequestHeader(
                HttpRequestHeader.POST,
                new URI(refreshUrl, false),
                HttpHeader.HTTP11
            );
            requestHeader.setHeader(HttpHeader.CONTENT_TYPE, "application/json");
            requestHeader.setContentLength(refreshRequestBody.length);

            const refreshMsg = new HttpMessage(requestHeader);
            refreshMsg.setRequestBody(refreshRequestBody);

            // Send refresh token request safely wrapped in try-catch
            try {
                sender.sendAndReceive(refreshMsg, false);
            } catch (refreshError) {
                print("❌ Failed sending refresh token request: " + refreshError.message);
                return;
            }

            const refreshStatus = refreshMsg.getResponseHeader().getStatusCode();
            print("🔄 Refresh request response status: " + refreshStatus);

            if (refreshStatus === 200) {
                const refreshResponse = JSON.parse(refreshMsg.getResponseBody().toString());
                const newAccessToken = refreshResponse[accessTokenAccessor];
                const newRefreshToken = refreshResponse[refreshTokenAccessor];

                if (newAccessToken) {
                    ScriptVars.setGlobalVar("access_token", newAccessToken);
                    print("✅ New access token obtained and saved.");

                    // Set new access token to original request header
                    msg.getRequestHeader().setHeader("Authorization", "Bearer " + newAccessToken);

                    // Retry original request with new token
                    try {
                        sender.sendAndReceive(msg, false);
                        print("🔄 Original request successfully resent with refreshed access token.");
                    } catch (retryError) {
                        print("❌ Error resending request with new access token: " + retryError.message);
                    }
                } else {
                    print("⚠️ Access token not found in refresh response.");
                }

                if (newRefreshToken) {
                    ScriptVars.setGlobalVar("refresh_token", newRefreshToken);
                    print("🔄 Refresh token updated globally.");
                } else {
                    print("⚠️ Refresh token not updated in refresh response.");
                }
            } else {
                print("❌ Refresh token request failed, response status: " + refreshMsg.getResponseHeader().getStatusCode());
                print("📦 Response body: " + refreshMsg.getResponseBody().toString());
            }
        }
    } catch (error) {
        print("❌ Exception caught in responseReceived: " + error.message);
    }
}
