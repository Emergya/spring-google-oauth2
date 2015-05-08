package com.emergya.spring.security.oauth.google;

import org.springframework.security.oauth2.client.OAuth2RestOperations;

/**
 * Interface for the GoogleOAuth2RestTemplate so Spring is able to create an proxy, as we need the template to be a session bean as
 * it will contain info about the user (google's auth token, etc.).
 *
 * @author lroman
 */
public interface GoogleOAuth2RestTemplate extends OAuth2RestOperations {

}
