package com.emergya.spring.security.oauth.google;

import java.io.Serializable;
import java.util.Arrays;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;

/**
 * Extends OAuth2RestTemplate to change the access token provider chain to include <c>GoogleAuthorizationCodeAccessTokenProvider</c>
 * insted of <c>AuthorizationCodeAccessTokenProvider</c> so we support some custom parameters that Google supports.
 *
 * @author lroman
 */
public class GoogleOAuth2RestTemplateImpl extends OAuth2RestTemplate implements GoogleOAuth2RestTemplate, Serializable {

    public GoogleOAuth2RestTemplateImpl() {
        super(null);
    }

    public GoogleOAuth2RestTemplateImpl(GoogleAuthCodeResourceDetails resource, OAuth2ClientContext context) {
        super(resource, context);

        setAccessTokenProvider(
                new AccessTokenProviderChain(Arrays.<AccessTokenProvider>asList(
                                new GoogleAuthorizationCodeAccessTokenProvider(), new ImplicitAccessTokenProvider(),
                                new ResourceOwnerPasswordAccessTokenProvider(), new ClientCredentialsAccessTokenProvider())));

    }

}
