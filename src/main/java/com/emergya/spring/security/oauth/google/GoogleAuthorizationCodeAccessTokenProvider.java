/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 /*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.emergya.spring.security.oauth.google;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.filter.state.DefaultStateKeyGenerator;
import org.springframework.security.oauth2.client.filter.state.StateKeyGenerator;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserApprovalRequiredException;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultRequestEnhancer;
import org.springframework.security.oauth2.client.token.OAuth2AccessTokenSupport;
import org.springframework.security.oauth2.client.token.RequestEnhancer;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.ResponseExtractor;

/**
 * Modified AuthorizationCodeAccessTokenProvider for obtaining an oauth2 access token by using an authorization code, using google
 * custom resource details.
 *
 * @author Ryan Heaton
 * @author Dave Syer
 * @author lroman
 */
public class GoogleAuthorizationCodeAccessTokenProvider extends OAuth2AccessTokenSupport implements AccessTokenProvider {

    private StateKeyGenerator stateKeyGenerator = new DefaultStateKeyGenerator();

    private String scopePrefix = OAuth2Utils.SCOPE_PREFIX;

    private RequestEnhancer authorizationRequestEnhancer = new DefaultRequestEnhancer();

    /**
     * A custom enhancer for the authorization request.
     *
     * @param authorizationRequestEnhancer the authorization request enhancer to set.
     */
    public final void setAuthorizationRequestEnhancer(final RequestEnhancer authorizationRequestEnhancer) {
        this.authorizationRequestEnhancer = authorizationRequestEnhancer;
    }

    /**
     * Prefix for scope approval parameters.
     *
     * @param scopePrefix the scope prefix to set.
     */
    public final void setScopePrefix(final String scopePrefix) {
        this.scopePrefix = scopePrefix;
    }

    /**
     * @param stateKeyGenerator the stateKeyGenerator to set
     */
    public final void setStateKeyGenerator(final StateKeyGenerator stateKeyGenerator) {
        this.stateKeyGenerator = stateKeyGenerator;
    }

    @Override
    public final boolean supportsResource(final OAuth2ProtectedResourceDetails resource) {
        return resource instanceof AuthorizationCodeResourceDetails
                && "authorization_code".equals(resource.getGrantType());
    }

    @Override
    public final boolean supportsRefresh(final OAuth2ProtectedResourceDetails resource) {
        return supportsResource(resource);
    }

    /**
     * Obtains the authorization code from the access token request.
     *
     * @param details the authenticatoin details
     * @param request the access token request
     * @return the authorization code
     * @throws UserRedirectRequiredException when redirection is required
     * @throws UserApprovalRequiredException when the user requires approval
     * @throws AccessDeniedException when the user is denied access
     * @throws OAuth2AccessDeniedException when the user is denied access but we dont want the default Spring Security handling
     */
    public final String obtainAuthorizationCode(final OAuth2ProtectedResourceDetails details, final AccessTokenRequest request)
            throws UserRedirectRequiredException, UserApprovalRequiredException, AccessDeniedException,
            OAuth2AccessDeniedException {

        GoogleAuthCodeResourceDetails resource;

        try {
            resource = (GoogleAuthCodeResourceDetails) details;
        } catch (ClassCastException ex) {
            throw new IllegalArgumentException("details is not an instance of class GoogleAuthCodeResourceDetails");
        }

        HttpHeaders headers = getHeadersForAuthorizationRequest(request);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        if (request.containsKey(OAuth2Utils.USER_OAUTH_APPROVAL)) {
            form.set(OAuth2Utils.USER_OAUTH_APPROVAL, request.getFirst(OAuth2Utils.USER_OAUTH_APPROVAL));
            for (String scope : details.getScope()) {
                form.set(scopePrefix + scope, request.getFirst(OAuth2Utils.USER_OAUTH_APPROVAL));
            }
        } else {
            form.putAll(getParametersForAuthorizeRequest(resource, request));
        }
        authorizationRequestEnhancer.enhance(request, resource, form, headers);
        final AccessTokenRequest copy = request;

        final ResponseExtractor<ResponseEntity<Void>> delegate = getAuthorizationResponseExtractor();
        ResponseExtractor<ResponseEntity<Void>> extractor = new CookieResponseExtractor(copy, delegate);
        // Instead of using restTemplate.exchange we use an explicit response extractor here so it can be overridden by
        // subclasses
        ResponseEntity<Void> response = getRestTemplate().execute(resource.getUserAuthorizationUri(), HttpMethod.POST,
                getRequestCallback(resource, form, headers), extractor, form.toSingleValueMap());

        if (response.getStatusCode() == HttpStatus.OK) {
            // Need to re-submit with approval...
            throw getUserApprovalSignal(resource, request);
        }

        URI location = response.getHeaders().getLocation();
        String query = location.getQuery();
        Map<String, String> map = OAuth2Utils.extractMap(query);
        if (map.containsKey("state")) {
            request.setStateKey(map.get("state"));
            if (request.getPreservedState() == null) {
                String redirectUri = resource.getRedirectUri(request);
                if (redirectUri != null) {
                    request.setPreservedState(redirectUri);
                } else {
                    request.setPreservedState(new Object());
                }
            }
        }

        String code = map.get("code");
        if (code == null) {
            throw new UserRedirectRequiredException(location.toString(), form.toSingleValueMap());
        }
        request.set("code", code);
        return code;

    }

    /**
     * Gets the authorization response extractor object.
     *
     * @return the authorizatoin response extractor.
     */
    protected final ResponseExtractor<ResponseEntity<Void>> getAuthorizationResponseExtractor() {
        return new AuthResponseExtractor();
    }

    @Override
    public final OAuth2AccessToken obtainAccessToken(final OAuth2ProtectedResourceDetails details, final AccessTokenRequest request)
            throws UserRedirectRequiredException, UserApprovalRequiredException, AccessDeniedException,
            OAuth2AccessDeniedException {

        GoogleAuthCodeResourceDetails resource;

        try {
            resource = (GoogleAuthCodeResourceDetails) details;
        } catch (ClassCastException ex) {
            throw new IllegalArgumentException("details is not an instance of class GoogleAuthCodeResourceDetails");
        }

        if (request.getAuthorizationCode() == null) {
            if (request.getStateKey() == null) {
                throw getRedirectForAuthorization(resource, request);
            }
            obtainAuthorizationCode(resource, request);
        }
        return retrieveToken(request, resource, getParametersForTokenRequest(resource, request), getHeadersForTokenRequest());

    }

    @Override
    public final OAuth2AccessToken refreshAccessToken(
            final OAuth2ProtectedResourceDetails resource, final OAuth2RefreshToken refreshToken, final AccessTokenRequest request)
            throws UserRedirectRequiredException, OAuth2AccessDeniedException {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "refresh_token");
        form.add("refresh_token", refreshToken.getValue());
        try {
            return retrieveToken(request, resource, form, getHeadersForTokenRequest());
        } catch (OAuth2AccessDeniedException e) {
            try {
                throw getRedirectForAuthorization((GoogleAuthCodeResourceDetails) resource, request);
            } catch (ClassCastException ex) {
                throw new IllegalArgumentException("details is not an instance of class GoogleAuthCodeResourceDetails");
            }
        }
    }

    private HttpHeaders getHeadersForTokenRequest() {
        HttpHeaders headers = new HttpHeaders();
        // No cookie for token request
        return headers;
    }

    private HttpHeaders getHeadersForAuthorizationRequest(final AccessTokenRequest request) {
        HttpHeaders headers = new HttpHeaders();
        headers.putAll(request.getHeaders());
        if (request.getCookie() != null) {
            headers.set("Cookie", request.getCookie());
        }
        return headers;
    }

    private MultiValueMap<String, String> getParametersForTokenRequest(
            final AuthorizationCodeResourceDetails resource, final AccessTokenRequest request) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.set("grant_type", "authorization_code");
        form.set("code", request.getAuthorizationCode());

        Object preservedState = request.getPreservedState();
        if (request.getStateKey() != null) {
            // The token endpoint has no use for the state so we don't send it back, but we are using it
            // for CSRF detection client side...
            if (preservedState == null) {
                throw new InvalidRequestException(
                        "Possible CSRF detected - state parameter was present but no state could be found");
            }
        }

        // Extracting the redirect URI from a saved request should ignore the current URI, so it's not simply a call to
        // resource.getRedirectUri()
        String redirectUri;
        // Get the redirect uri from the stored state
        if (preservedState instanceof String) {
            // Use the preserved state in preference if it is there
            // TODO: treat redirect URI as a special kind of state (this is a historical mini hack)
            redirectUri = String.valueOf(preservedState);
        } else {
            redirectUri = resource.getRedirectUri(request);
        }

        if (redirectUri != null && !"NONE".equals(redirectUri)) {
            form.set("redirect_uri", redirectUri);
        }

        return form;

    }

    private MultiValueMap<String, String> getParametersForAuthorizeRequest(GoogleAuthCodeResourceDetails resource,
            AccessTokenRequest request) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.set("response_type", "code");
        form.set("client_id", resource.getClientId());

        if (request.get("scope") != null) {
            form.set("scope", request.getFirst("scope"));
        } else {
            form.set("scope", OAuth2Utils.formatParameterList(resource.getScope()));
        }

        // Extracting the redirect URI from a saved request should ignore the current URI, so it's not simply a call to
        // resource.getRedirectUri()
        String redirectUri = resource.getPreEstablishedRedirectUri();

        Object preservedState = request.getPreservedState();
        if (redirectUri == null && preservedState != null) {
            // no pre-established redirect uri: use the preserved state
            // TODO: treat redirect URI as a special kind of state (this is a historical mini hack)
            redirectUri = String.valueOf(preservedState);
        } else {
            redirectUri = request.getCurrentUri();
        }

        String stateKey = request.getStateKey();
        if (stateKey != null) {
            form.set("state", stateKey);
            if (preservedState == null) {
                throw new InvalidRequestException(
                        "Possible CSRF detected - state parameter was present but no state could be found");
            }
        }

        form.set("approval_prompt", resource.getApprovalPrompt());

        if (StringUtils.isEmpty(resource.getLoginHint())) {
            form.set("login_hint", resource.getLoginHint());
        }

        if (redirectUri != null) {
            form.set("redirect_uri", redirectUri);
        }

        return form;

    }

    private UserRedirectRequiredException getRedirectForAuthorization(GoogleAuthCodeResourceDetails resource,
            AccessTokenRequest request) {

        // we don't have an authorization code yet. So first get that.
        TreeMap<String, String> requestParameters = new TreeMap<>();
        requestParameters.put("response_type", "code"); // oauth2 spec, section 3
        requestParameters.put("client_id", resource.getClientId());
        // Client secret is not required in the initial authorization request

        String redirectUri = resource.getRedirectUri(request);
        if (redirectUri != null) {
            requestParameters.put("redirect_uri", redirectUri);
        }

        if (resource.isScoped()) {

            StringBuilder builder = new StringBuilder();
            List<String> scope = resource.getScope();

            if (scope != null) {
                Iterator<String> scopeIt = scope.iterator();
                while (scopeIt.hasNext()) {
                    builder.append(scopeIt.next());
                    if (scopeIt.hasNext()) {
                        builder.append(' ');
                    }
                }
            }

            requestParameters.put("scope", builder.toString());
        }

        requestParameters.put("approval_prompt", resource.getApprovalPrompt());

        if (StringUtils.isEmpty(resource.getLoginHint())) {
            requestParameters.put("login_hint", resource.getLoginHint());
        }

        requestParameters.put("access_type", "online");

        UserRedirectRequiredException redirectException = new UserRedirectRequiredException(
                resource.getUserAuthorizationUri(), requestParameters);

        String stateKey = stateKeyGenerator.generateKey(resource);
        redirectException.setStateKey(stateKey);
        request.setStateKey(stateKey);
        redirectException.setStateToPreserve(redirectUri);
        request.setPreservedState(redirectUri);

        return redirectException;

    }

    /**
     * Gets the content for the UserApprovalRequire exeption.
     *
     * @param resource the resource details objet
     * @param request the access toke request
     * @return the exception to be thrown
     */
    protected final UserApprovalRequiredException getUserApprovalSignal(AuthorizationCodeResourceDetails resource,
            AccessTokenRequest request) {
        String message = String.format("Do you approve the client '%s' to access your resources with scope=%s",
                resource.getClientId(), resource.getScope());
        return new UserApprovalRequiredException(resource.getUserAuthorizationUri(), Collections.singletonMap(
                OAuth2Utils.USER_OAUTH_APPROVAL, message), resource.getClientId(), resource.getScope());
    }

    private static class CookieResponseExtractor implements ResponseExtractor<ResponseEntity<Void>> {

        private final AccessTokenRequest copy;
        private final ResponseExtractor<ResponseEntity<Void>> delegate;

        CookieResponseExtractor(AccessTokenRequest copy, ResponseExtractor<ResponseEntity<Void>> delegate) {
            this.copy = copy;
            this.delegate = delegate;
        }

        @Override
        public ResponseEntity<Void> extractData(ClientHttpResponse response) throws IOException {
            if (response.getHeaders().containsKey("Set-Cookie")) {
                copy.setCookie(response.getHeaders().getFirst("Set-Cookie"));
            }
            return delegate.extractData(response);
        }
    }

    private static class AuthResponseExtractor implements ResponseExtractor<ResponseEntity<Void>> {

        AuthResponseExtractor() {
        }

        @Override
        public ResponseEntity<Void> extractData(ClientHttpResponse response) throws IOException {
            return new ResponseEntity<>(response.getHeaders(), response.getStatusCode());
        }
    }

}
