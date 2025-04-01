# Bearer Token Authentication and Automatic Refresh Scripts for OWASP ZAP

## 📌 Overview

These scripts automate the authentication process and management of sessions for applications utilizing Bearer tokens with refresh tokens. They ensure continuous and seamless authenticated security scanning within OWASP ZAP.

---

## 📜 Scripts Included

### ✅ **BearerTokenAuthentication.js**

- Automates initial authentication to retrieve Bearer (access) and Refresh tokens.
- Sends authentication requests with credentials to the specified login endpoint.
- Stores tokens as global variables accessible by other scripts within ZAP.

### ✅ **AutomaticBearerTokenSenderAndRefresher.js**

- Automatically adds Bearer tokens to outgoing requests.
- Detects and automatically handles token expiration by refreshing tokens.
- Ensures continuous authenticated requests during automated scans.

---

## ⚙️ Setup Instructions

### Step 1: Prerequisites

- OWASP ZAP (≥ 2.16.0)
- Java JDK 21
- GraalVM (compatible with Java JDK 21)

### Step 2: Configuring Authentication Context in ZAP

Configure these parameters within the authentication context of OWASP ZAP:

**Required:**

- `loginUrl`: URL endpoint for authentication.

**Optional (default values provided):**

- `refreshUrl`: URL endpoint for token refresh.
- `tokenAccessor`: JSON field name for Bearer Token (default: `"access_token"`).
- `refreshTokenAccessor`: JSON field name for Refresh Token (default: `"refresh_token"`).
- `usernameAccessor`: JSON field name for Bearer Token (default: `"username"`).
- `passwordAccessor`: JSON field name for Refresh Token (default: `"password"`).

**Credential Parameters:**

- `username`: Authentication username.
- `password`: Authentication password.

### Step 3: Adding Scripts to ZAP

- Open OWASP ZAP, navigate to `Scripts > New Script`.
- Choose:
  - Type: `Authentication` for `BearerTokenAuthentication.js`.
  - Type: `HTTP Sender` for `AutomaticBearerTokenSenderAndRefresher.js`.
- Paste the script content and save.

---

## 🚀 Usage

- Ensure scripts are properly configured and activated in ZAP.
- Run scans; authentication and token management will be handled automatically.
- Monitor script logs for debugging and verification.

---

## 🌐 Public Availability

These scripts are publicly available in this repository and will soon be submitted for review and inclusion in the official [OWASP ZAP Community Scripts Repository](https://github.com/zaproxy/community-scripts).

---

## 🤝 Contributing

Feedback and contributions are welcome! Please open an issue or submit a pull request for improvements and suggestions.

---

## 👤 Author

- **Ice Fox** _(2025-03-17)_

---
