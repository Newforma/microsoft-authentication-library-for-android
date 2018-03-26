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

import android.content.Context;
import android.util.Base64;
import android.webkit.CookieManager;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Request handling silent flow. Silent flow will try to find a valid RT, if no valid AT exists, it will
 * try to find a RT(all the RTs are multi-scoped), there will only be one entry per authority, clientid and user.
 */
final class SilentRequest extends BaseRequest {
    private static final String TAG = SilentRequest.class.getSimpleName();

    private RefreshTokenCacheItem mRefreshTokenCacheItem;
    private final boolean mForceRefresh;
    private final User mUser;
    private AuthenticationResult mAuthResult;
    private boolean mIsAuthorityProvided = true;

    SilentRequest(final Context appContext, final AuthenticationRequestParameters authRequestParams,
                  final boolean forceRefresh, final User user) {
        super(appContext, authRequestParams);

        mForceRefresh = forceRefresh;
        mUser = user;
    }

    @Override
    void preTokenRequest() throws MsalClientException, MsalUiRequiredException, MsalServiceException, MsalUserCancelException {
        super.preTokenRequest();
        if(mUser != null) {
            final TokenCache tokenCache = mAuthRequestParameters.getTokenCache();

            final AccessTokenCacheItem tokenCacheItemAuthorityNotProvided = mIsAuthorityProvided ? null : tokenCache.findAccessTokenItemAuthorityNotProvided(
                    mAuthRequestParameters, mUser);
            // lookup AT first.
            if (!mForceRefresh) {
                final AccessTokenCacheItem accessTokenCacheItem = mIsAuthorityProvided ? tokenCache.findAccessToken(mAuthRequestParameters, mUser)
                        : tokenCacheItemAuthorityNotProvided;

                if (accessTokenCacheItem != null) {
                    Logger.info(TAG, mAuthRequestParameters.getRequestContext(), "Access token is found, returning cached AT.");
                    mAuthResult = new AuthenticationResult(mAuthCode, mIdToken);
                    return;
                }
            } else {
                Logger.info(TAG, mAuthRequestParameters.getRequestContext(), "ForceRefresh is set to true, skipping AT lookup.");
            }

            mRefreshTokenCacheItem = tokenCache.findRefreshToken(mAuthRequestParameters, mUser);
            if (mRefreshTokenCacheItem == null) {
                Logger.info(TAG, mAuthRequestParameters.getRequestContext(), "No refresh token item is found.");
                throw new MsalUiRequiredException(MsalUiRequiredException.NO_TOKENS_FOUND, "No refresh token was found. ");
            }
        } else {
            refreshUrl();
        }
    }

    private void refreshUrl() throws MsalClientException, MsalServiceException {
        try {
            String url = appendQueryStringToAuthorizeEndpoint();
            HttpResponse response = HttpRequest.sendGet(new URL(url), getCookieHeader(url), mAuthRequestParameters.getRequestContext());

            url = getLocation(response);
            response = HttpRequest.sendGet(new URL(url), getCookieHeader(url), mAuthRequestParameters.getRequestContext());

            String authorizationUrl = getLocation(response);
            AuthorizationResult authorizationResult = AuthorizationResult.parseAuthorizationResponse(authorizationUrl);

            mAuthCode = authorizationResult.getAuthCode();
            mIdToken = authorizationResult.getIdToken();
            mAuthResult = new AuthenticationResult(mAuthCode, mIdToken);
        } catch (MalformedURLException e) {
            throw new MsalClientException(MsalClientException.MALFORMED_URL, e.getMessage(), e);
        } catch (UnsupportedEncodingException e) {
            throw new MsalClientException(MsalClientException.UNSUPPORTED_ENCODING, e.getMessage(), e);
        } catch (IOException e) {
            throw new MsalClientException(MsalClientException.IO_ERROR, e.getMessage(), e);
        }
    }

    private Map<String,String> getCookieHeader(String url) {
        Map<String,String> headers = new HashMap<>();

        CookieManager manager = CookieManager.getInstance();
        if(manager.hasCookies()) {
            headers.put("Cookie", manager.getCookie(url));
        }

        return headers;
    }

    private String getLocation(HttpResponse response) {
        Map<String, List<String>> headers = response.getHeaders();

        if(headers.containsKey("Location")) {
            List<String> values = headers.get("Location");

            if(!values.isEmpty()) {
                return values.get(0);
            }
        }

        return null;
    }

    String appendQueryStringToAuthorizeEndpoint() throws UnsupportedEncodingException, MsalClientException {
        String authorizationUrl = MsalUtils.appendQueryParameterToUrl(
                mAuthRequestParameters.getAuthority().getAuthorizeEndpoint(),
                createAuthorizationRequestParameters());

        Logger.infoPII(TAG, mAuthRequestParameters.getRequestContext(), "Request uri to authorize endpoint is: " + authorizationUrl);
        return authorizationUrl;
    }

    private Map<String, String> createAuthorizationRequestParameters() throws UnsupportedEncodingException, MsalClientException {
        final Map<String, String> requestParameters = new HashMap<>();

        final Set<String> scopes = new HashSet<>(mAuthRequestParameters.getScope());
        final Set<String> requestedScopes = getDecoratedScope(scopes);
        requestParameters.put(OauthConstants.Oauth2Parameters.SCOPE,
                MsalUtils.convertSetToString(requestedScopes, " "));
        requestParameters.put(OauthConstants.Oauth2Parameters.CLIENT_ID, mAuthRequestParameters.getClientId());
        requestParameters.put(OauthConstants.Oauth2Parameters.REDIRECT_URI, mAuthRequestParameters.getRedirectUri());
        requestParameters.put(OauthConstants.Oauth2Parameters.RESPONSE_TYPE, OauthConstants.Oauth2ResponseType.ID_TOKEN_CODE);
        requestParameters.put(OauthConstants.OauthHeader.CORRELATION_ID,
                mAuthRequestParameters.getRequestContext().getCorrelationId().toString());
        requestParameters.putAll(PlatformIdHelper.getPlatformIdParameters());

        // append state in the query parameters
        requestParameters.put(OauthConstants.Oauth2Parameters.STATE, encodeProtocolState());

        // adding extra qp
        if (!MsalUtils.isEmpty(mAuthRequestParameters.getExtraQueryParam())) {
            appendExtraQueryParameters(mAuthRequestParameters.getExtraQueryParam(), requestParameters);
        }

        if (!MsalUtils.isEmpty(mAuthRequestParameters.getSliceParameters())) {
            appendExtraQueryParameters(mAuthRequestParameters.getSliceParameters(), requestParameters);
        }

        return requestParameters;
    }

    private String encodeProtocolState() throws UnsupportedEncodingException {
        final String state = String.format("a=%s&r=%s", MsalUtils.urlFormEncode(
                mAuthRequestParameters.getAuthority().getAuthority()),
                MsalUtils.urlFormEncode(MsalUtils.convertSetToString(
                        mAuthRequestParameters.getScope(), " ")));
        return Base64.encodeToString(state.getBytes("UTF-8"), Base64.NO_PADDING | Base64.URL_SAFE);
    }

    private void appendExtraQueryParameters(final String queryParams, final Map<String, String> requestParams) throws MsalClientException {
        final Map<String, String> extraQps = MsalUtils.decodeUrlToMap(queryParams, "&");
        final Set<Map.Entry<String, String>> extraQpEntries = extraQps.entrySet();
        for (final Map.Entry<String, String> extraQpEntry : extraQpEntries) {
            if (requestParams.containsKey(extraQpEntry.getKey())) {
                throw new MsalClientException(MsalClientException.DUPLICATE_QUERY_PARAMETER, "Extra query parameter " + extraQpEntry.getKey() + " is already sent by "
                        + "the SDK. ");
            }

            requestParams.put(extraQpEntry.getKey(), extraQpEntry.getValue());
        }
    }

    @Override
    void setAdditionalOauthParameters(final Oauth2Client oauth2Client) {
        oauth2Client.addBodyParameter(OauthConstants.Oauth2Parameters.GRANT_TYPE,
                OauthConstants.Oauth2GrantType.REFRESH_TOKEN);
        oauth2Client.addBodyParameter(OauthConstants.Oauth2Parameters.REFRESH_TOKEN, mRefreshTokenCacheItem.getRefreshToken());
    }

    /**
     * For silent request, we check if there is an valid access token first. If there is an valid AT in the cache, no actual
     * perform token request. Otherwise, use the base performTokenRequest. Resiliency feather will be enabled here, if we
     * get the SERVICE_NOT_AVAILABLE, check for the extended_expires_on and if the token is still valid with extended expires on,
     * return the token.
     *
     * @throws MsalServiceException
     * @throws MsalClientException
     */
    @Override
    void performTokenRequest() throws MsalServiceException, MsalClientException {
        // There is an access token returned, don't perform any token request. PostTokenRequest will the stored valid
        // access token.
        if (mAuthResult != null) {
            return;
        }

        // TODO: Support resilency. No need for #BUILD
        super.performTokenRequest();
    }

    /**
     * Return the valid AT. If error happens for request sent to token endpoint, remove the stored refresh token if
     * receiving invalid_grant, and re-wrap the exception with high level error as Interaction_required.
     *
     * @return {@link AuthenticationResult} containing the auth token.
     */
    @Override
    AuthenticationResult postTokenRequest() throws MsalServiceException, MsalUiRequiredException, MsalClientException {
        // if there is an valid access token returned, mAuthResult will already be set
        if (mAuthResult != null) {
            return mAuthResult;
        }

        return super.postTokenRequest();
    }

    void setIsAuthorityProvided(final boolean isAuthorityProvided) {
        mIsAuthorityProvided = isAuthorityProvided;
    }
}
