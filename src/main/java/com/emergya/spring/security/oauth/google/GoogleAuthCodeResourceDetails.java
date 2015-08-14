package com.emergya.spring.security.oauth.google;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;

/**
 * This class contains config details for authentication against google oauth
 * services, including custom request parameters.
 *
 * See https://developers.google.com/youtube/v3/guides/authentication for more
 * info.
 *
 * @author lroman
 */
public class GoogleAuthCodeResourceDetails extends AuthorizationCodeResourceDetails {

    @Value("${google.approvalPrompt}")
    private String approvalPrompt;

    private String loginHint;

    /**
     * @return the approvalPrompt
     */
    public String getApprovalPrompt() {
        return approvalPrompt;
    }

    /**
     * @param approvalPrompt the approvalPrompt to set
     */
    public void setApprovalPrompt(String approvalPrompt) {
        this.approvalPrompt = approvalPrompt;
    }

    /**
     * @return the loginHint
     */
    public String getLoginHint() {
        return loginHint;
    }

    /**
     * @param loginHint the loginHint to set
     */
    public void setLoginHint(String loginHint) {
        this.loginHint = loginHint;
    }

}
