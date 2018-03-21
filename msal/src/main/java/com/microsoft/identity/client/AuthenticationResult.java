//  Copyright (c) Microsoft Corporation.
//  All rights reserved.
//
//  This code is licensed under the MIT License.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files(the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions :
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

package com.microsoft.identity.client;

/**
 * MSAL successful authentication result. When auth succeeds, token will be wrapped into the
 * {@link AuthenticationResult} and passed back through the {@link AuthenticationCallback}.
 */
public final class AuthenticationResult {

    private final String mAuthCode;
    private final String mRawIdToken;
    private final IdToken mIdToken;

    AuthenticationResult(final String authCode, final String rawIdToken) throws MsalClientException {
        mAuthCode = authCode;
        mRawIdToken = rawIdToken;
        mIdToken = new IdToken(rawIdToken);
    }

    public String getTenantId() {
        return mIdToken.getTenantId();
    }

    /**
     * @return The id token returned by the service or null if no id token is returned.
     */
    public String getRawIdToken() {
        return mRawIdToken;
    }

    /**
     * @return The auth code in the redirect uri.
     */
    public String getAuthCode() {
        return mAuthCode;
    }

}