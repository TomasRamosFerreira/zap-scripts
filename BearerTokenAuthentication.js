/*
 * Authentication script for ZAP to retrieve Bearer and Refresh tokens
 * @Author: Ice Fox
 * @Date: 03/10/2025
 * @Version: 1.0
 */

// Import ZAP utility to store global script variables
const ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");
const HttpRequestHeader = Java.type(
  "org.parosproxy.paros.network.HttpRequestHeader"
);
const HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
const URI = Java.type("org.apache.commons.httpclient.URI");

// Main authentication function
function authenticate(helper, paramsValues, credentials) {
    print("---- Authentication script starting ----\n");

    // Retrieve login URL from script parameters
    const loginUrl = paramsValues.get("loginUrl");
    
    // How to access the tokens
    const tokenAccessor = paramsValues.get("tokenAccessor");
    const refreshTokenAccessor = paramsValues.get("refreshTokenAccessor");
    const refreshUrl = paramsValues.get("refreshUrl")

    // Retrieve username and password from credentials
    const username = credentials.getParam("username");
    const password = credentials.getParam("password");

    const loginUri = new URI(loginUrl, false);

    const loginMsg = helper.prepareMessage();

    // Prepare request body with credentials
    const requestBody = JSON.stringify({
        username: username,
        password: password
    });

    // Prepare HTTP message with required headers and body
    loginMsg.setRequestBody(requestBody);

    const requestHeader = new HttpRequestHeader(
        HttpRequestHeader.POST,
        loginUri,
        HttpHeader.HTTP11
    );
    loginMsg.setRequestHeader(requestHeader);

    // Build the POST request header
    loginMsg
        .getRequestHeader()
        .setHeader(HttpHeader.CONTENT_TYPE, "application/json");
    loginMsg
        .getRequestHeader()
        .setContentLength(loginMsg.getRequestBody().length());

    // Send authentication request
    helper.sendAndReceive(loginMsg, false);

    // Check HTTP response status code
    const responseStatusCode = loginMsg.getResponseHeader().getStatusCode();
    if (responseStatusCode != 200) {
        throw new Error("Authentication failed with status code: " + responseStatusCode);
    }

    // Parse response to extract tokens
    var responseBody = JSON.parse(loginMsg.getResponseBody().toString());
    var accessToken = responseBody[tokenAccessor];
    var refreshToken = responseBody[refreshTokenAccessor];

    // Validate tokens
    if (!accessToken) {
        throw new Error("Authentication response missing tokens.");
    }

    // Store tokens globally for reuse by other scripts
    ScriptVars.setGlobalVar("access_token", accessToken);
    print("Access Token: " + accessToken + "\n");

    // Store variables globally
    ScriptVars.setGlobalVar("refreshUrl", refreshUrl);
    ScriptVars.setGlobalVar("tokenAccessor", tokenAccessor);
    ScriptVars.setGlobalVar("refreshTokenAccessor", refreshTokenAccessor);
    
    // Optional field
    if (refreshTokenAccessor && refreshToken) {
        ScriptVars.setGlobalVar("refresh_token", refreshToken);
        print("Refresh Token: " + refreshToken + "\n");
    }

    print("\n---- Authentication script has finished ----\n\n");

    // Return the message for further processing if needed
    return loginMsg;
}

// Define required parameters (mandatory)
function getRequiredParamsNames() {
    return ["loginUrl", "refreshUrl", "tokenAccessor"];
}

// Define optional parameters (none required)
function getOptionalParamsNames() {
    return ["refreshTokenAccessor"];
}

// Define credential parameters
function getCredentialsParamsNames() {
    return ["username", "password"];
}
