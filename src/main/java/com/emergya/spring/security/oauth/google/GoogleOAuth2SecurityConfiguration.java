package com.emergya.spring.security.oauth.google;

import java.util.ArrayList;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;

import java.util.Collections;
import java.util.List;
import javax.annotation.Resource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;

@Configuration
@EnableOAuth2Client
public class GoogleOAuth2SecurityConfiguration {

    @Value("${google.client.id}")
    private String CLIENT_ID;

    @Value("${google.client.secret}")
    private String CLIENT_SECRET;

    @Value("${google.accessTokenUri}")
    private String ACCESS_TOKEN_URI;

    @Value("${google.userAuthorizationUri}")
    private String USER_AUTH_URI;

    @Value("${google.authorization.code}")
    private String AUTH_NAME;

    @Value("${google.auth.scope}")
    private String AUTH_SCOPES;

    @Value("${google.preestablished.redirect.url}")
    private String REDIRECT_URI;

    @Resource
    @Qualifier("accessTokenRequest")
    private AccessTokenRequest accessTokenRequest;

    /**
     * Establishes Google API Credentials properties for OAuth Filters
     *
     * @return Google API Credentials
     */
    @Bean
    public GoogleAuthCodeResourceDetails googleResource() {
        GoogleAuthCodeResourceDetails details = new GoogleAuthCodeResourceDetails();
        details.setId("google-oauth-client");
        details.setClientId(CLIENT_ID);
        details.setClientSecret(CLIENT_SECRET);
        details.setAccessTokenUri(ACCESS_TOKEN_URI);
        details.setUserAuthorizationUri(USER_AUTH_URI);
        details.setTokenName(AUTH_NAME);
        details.setScope(parseScopes(AUTH_SCOPES));
        details.setPreEstablishedRedirectUri(REDIRECT_URI);
        details.setUseCurrentUri(false);
        details.setAuthenticationScheme(AuthenticationScheme.query);
        details.setClientAuthenticationScheme(AuthenticationScheme.form);
        details.setApprovalPrompt("force");
        return details;
    }

    private List<String> parseScopes(String commaSeparatedScopes) {
        List<String> scopes = new ArrayList<>();
        Collections.addAll(scopes, commaSeparatedScopes.split(","));
        return scopes;
    }

    @Bean()
    @Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)
    @Lazy
    public GoogleOAuth2RestTemplate googleRestTemplate() {
        return new GoogleOAuth2RestTemplateImpl(googleResource(), new DefaultOAuth2ClientContext(accessTokenRequest));
    }

}
