package com.emergya.spring.security.oauth.google;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * Copied from Spring Security OAuth2 to support the custom format for a Google Token which is different from what Spring supports.
 */
@Component
public class GoogleTokenServices extends RemoteTokenServices {

    private static final Logger LOGGER = Logger.getLogger(GoogleTokenServices.class.getName());

    private RestOperations restTemplate;

    @Value("${google.checkTokenEndpointUrl}")
    private String checkTokenEndpointUrl;

    @Value("${google.client.id}")
    private String clientId;

    @Value("${google.client.secret}")
    private String clientSecret;

    @Autowired
    private AccessTokenConverter tokenConverter;

    /**
     * Constructor.
     */
    public GoogleTokenServices() {
        restTemplate = new RestTemplate();
        ((RestTemplate) restTemplate).setErrorHandler(new ResponseErrorHandler());
    }

    @Override
    public final void setRestTemplate(RestOperations restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public final void setCheckTokenEndpointUrl(String checkTokenEndpointUrl) {
        this.checkTokenEndpointUrl = checkTokenEndpointUrl;
    }

    @Override
    public final void setClientId(String clientId) {
        this.clientId = clientId;
    }

    @Override
    public final void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    @Override
    public final void setAccessTokenConverter(AccessTokenConverter accessTokenConverter) {
        this.tokenConverter = accessTokenConverter;
    }

    @Override
    public final OAuth2Authentication loadAuthentication(String accessToken)
            throws AuthenticationException, InvalidTokenException {

        Map<String, Object> checkTokenResponse = checkToken(accessToken);

        if (checkTokenResponse.containsKey("error")) {
            LOGGER.log(Level.FINER, "check_token returned error: {0}", checkTokenResponse.get("error"));
            throw new InvalidTokenException(accessToken);
        }

        transformNonStandardValuesToStandardValues(checkTokenResponse);

        Assert.state(checkTokenResponse.containsKey("client_id"), "Client id must be present in response from auth server");
        return tokenConverter.extractAuthentication(checkTokenResponse);
    }

    private Map<String, Object> checkToken(String accessToken) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("token", accessToken);
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", getAuthorizationHeader());
        String accessTokenUrl = new StringBuilder(checkTokenEndpointUrl).append("?access_token=").append(accessToken).toString();
        return postForMap(accessTokenUrl, formData, headers);
    }

    private void transformNonStandardValuesToStandardValues(Map<String, Object> map) {
        LOGGER.log(Level.FINE, "Original map = {0}", map);
        map.put("client_id", map.get("issued_to")); // Google sends 'client_id' as 'issued_to'
        map.put("user_name", map.get("user_id")); // Google sends 'user_name' as 'user_id'
        LOGGER.log(Level.FINE, "Transformed = " + map);
    }

    private String getAuthorizationHeader() {
        String creds = String.format("%s:%s", clientId, clientSecret);
        try {
            return "Basic " + new String(Base64.encode(creds.getBytes("UTF-8")), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Could not convert String");
        }
    }

    private Map<String, Object> postForMap(String path, MultiValueMap<String, String> formData, HttpHeaders headers) {
        if (headers.getContentType() == null) {
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        }
        ParameterizedTypeReference<Map<String, Object>> map = new ParameterizedTypeReferenceImpl();
        return restTemplate.exchange(path, HttpMethod.POST, new HttpEntity<>(formData, headers), map).getBody();
    }

    private static class ResponseErrorHandler extends DefaultResponseErrorHandler {

        ResponseErrorHandler() {
        }

        @Override
        // Ignore 400
        public void handleError(ClientHttpResponse response) throws IOException {
            if (response.getRawStatusCode() != HttpStatus.BAD_REQUEST.value()) {
                super.handleError(response);
            }
        }
    }

    private static class ParameterizedTypeReferenceImpl extends ParameterizedTypeReference<Map<String, Object>> {

        ParameterizedTypeReferenceImpl() {
        }
    }
}
