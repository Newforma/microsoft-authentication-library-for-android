package com.microsoft.identity.client;

import android.app.Activity;
import android.content.Intent;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

class NewAccountInteractiveRequest extends InteractiveRequest {
    private static final String TAG = NewAccountInteractiveRequest.class.getSimpleName();

    private final String mSignUpUrl;
    private final String mRedirectUri;
    private final String mAuthority;
    private final String mScopes;

    NewAccountInteractiveRequest(Activity activity, final String signUpUrl, final String redirectUri,
                                 final String authority, final String scopes) {
        super(activity, AuthenticationRequestParameters.create(), null);
        mSignUpUrl = signUpUrl;
        mRedirectUri = redirectUri;
        mAuthority = authority;
        mScopes = scopes;
    }

    @Override
    synchronized void preTokenRequest() throws MsalUserCancelException, MsalClientException, MsalServiceException, MsalUiRequiredException {
        final Intent intentToLaunch = new Intent(mContext, WebAuthenticationActivity.class);
        intentToLaunch.putExtra(Constants.REQUEST_URL_KEY, mSignUpUrl);
        intentToLaunch.putExtra(Constants.REQUEST_REDIRECT, mRedirectUri);

        if (!resolveIntent(intentToLaunch)) {
            throw new MsalClientException(MsalClientException.UNRESOLVABLE_INTENT, "The intent is not resolvable");
        }

        throwIfNetworkNotAvailable();

        mActivityWrapper.startActivityForResult(intentToLaunch, BROWSER_FLOW);
        // lock the thread until onActivityResult release the lock.
        try {
            if (sResultLock.getCount() == 0) {
                sResultLock = new CountDownLatch(1);
            }

            sResultLock.await();
        } catch (final InterruptedException e) {
            Logger.error(TAG, mAuthRequestParameters.getRequestContext(), "Fail to lock the thread for waiting for authorize"
                    + " request to return.", e);
        }

        mAuthCode = sAuthorizationResult.getAuthCode();
        mIdToken = sAuthorizationResult.getIdToken();

        processAuthorizationResult(sAuthorizationResult);
    }

    @Override
    void setAdditionalOauthParameters(Oauth2Client oauth2Client) {}

    @Override
    protected void verifyStateInResponse(String stateInResponse) throws MsalClientException {
        final String decodeState = decodeState(stateInResponse);
        final Map<String, String> stateMap = MsalUtils.decodeUrlToMap(decodeState, "&");

        if (stateMap.size() != 2
                || !mAuthority.equals(stateMap.get("a"))) {
            throw new MsalClientException(MsalClientException.STATE_MISMATCH, Constants.MsalErrorMessage.STATE_NOT_THE_SAME);
        }

        final Set<String> scopesInState = MsalUtils.getScopesAsSet(stateMap.get("r"));
        final Set<String> scopesInRequest = MsalUtils.getScopesAsSet(mScopes);
        if (scopesInState.size() != scopesInRequest.size() && !scopesInState.containsAll(scopesInRequest)) {
            throw new MsalClientException(MsalClientException.STATE_MISMATCH, Constants.MsalErrorMessage.STATE_NOT_THE_SAME);
        }
    }
}
