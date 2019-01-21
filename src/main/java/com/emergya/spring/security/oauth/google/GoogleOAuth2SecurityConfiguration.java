package com.emergya.spring.security.oauth.google;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.annotation.Resource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;

@Configuration
@EnableOAuth2Client
public class GoogleOAuth2SecurityConfiguration {

    @Value("${google.client.id}")
    private String clientId;

    @Value("${google.client.secret}")
    private String clientSecret;

    @Value("${google.accessTokenUri}")
    private String accessTokenUri;

    @Value("${google.userAuthorizationUri}")
    private String userAuthUri;

    @Value("${google.authorization.code}")
    private String authName;

    @Value("${google.auth.scope}")
    private String authScopes;

    @Value("${google.preestablished.redirect.url}")
    private String redirectUri;

    @Value("${google.approvalPrompt}")
    private String approvalPrompt;

    @Resource
    @Qualifier("accessTokenRequest")
    private AccessTokenRequest accessTokenRequest;

    /**
     * Establishes Google API Credentials properties for OAuth Filters.
     *
     * @return Google API Credentials
     */
    @Bean
    public GoogleAuthCodeResourceDetails googleResource() {
        GoogleAuthCodeResourceDetails details = new GoogleAuthCodeResourceDetails();
        details.setId("google-oauth-client");
        details.setClientId(clientId);
        details.setClientSecret(clientSecret);
        details.setAccessTokenUri(accessTokenUri);
        details.setUserAuthorizationUri(userAuthUri);
        details.setTokenName(authName);
        details.setScope(parseScopes(authScopes));
        details.setPreEstablishedRedirectUri(redirectUri);
        details.setUseCurrentUri(false);
        details.setAuthenticationScheme(AuthenticationScheme.query);
        details.setClientAuthenticationScheme(AuthenticationScheme.form);
        details.setApprovalPrompt(approvalPrompt);

        return details;
    }

    private List<String> parseScopes(String commaSeparatedScopes) {
        List<String> scopes = new ArrayList<>();
        Collections.addAll(scopes, commaSeparatedScopes.split(","));
        return scopes;
    }

    /**
     * Returns the google rest template used for requests against Google OAuth service.
     *
     * @return the rest template instance
     */
    @Bean()
    public GoogleOAuth2RestTemplate googleRestTemplate() {
        return new GoogleOAuth2RestTemplate(googleResource(), getContext());
    }

    /**
     * Returns the session's OAuth client context so authorization details can be injected in the user's session.
     *
     * @return the client context for the session
     */
    @Bean()
    @Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)
    @Lazy
    protected OAuth2ClientContext getContext() {
        return new DefaultOAuth2ClientContext(accessTokenRequest);
    }

}
