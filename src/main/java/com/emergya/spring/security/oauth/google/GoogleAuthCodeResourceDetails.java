package com.emergya.spring.security.oauth.google;

import java.util.Objects;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;

/**
 * This class contains config details for authentication against google oauth services, including custom request parameters.
 *
 * See https://developers.google.com/youtube/v3/guides/authentication for more info.
 *
 * @author lroman
 */
public class GoogleAuthCodeResourceDetails extends AuthorizationCodeResourceDetails {

    private String approvalPrompt;

    private String loginHint;

    /**
     * @return the approvalPrompt
     */
    public final String getApprovalPrompt() {
        return approvalPrompt;
    }

    /**
     * @param approvalPrompt the approvalPrompt to set
     */
    public final void setApprovalPrompt(String approvalPrompt) {
        this.approvalPrompt = approvalPrompt;
    }

    /**
     * @return the loginHint
     */
    public final String getLoginHint() {
        return loginHint;
    }

    /**
     * @param loginHint the loginHint to set
     */
    public final void setLoginHint(String loginHint) {
        this.loginHint = loginHint;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof GoogleAuthCodeResourceDetails)) {
            return false;
        }

        GoogleAuthCodeResourceDetails that = (GoogleAuthCodeResourceDetails) o;
        return !(getId() != null ? !getId().equals(that.getId()) : that.getId() != null);

    }

    @Override
    public final int hashCode() {
        int hash = 3;
        hash = 73 * hash + Objects.hashCode(this.getId());
        return hash;
    }

}
