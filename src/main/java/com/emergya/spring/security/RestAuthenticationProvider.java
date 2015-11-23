package com.emergya.spring.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

/**
 * Authentication Provider uses two params: 1.- timestamp 2.- pass (combination of md5{timestamp + predefined token}).
 *
 * @author ajrodriguez
 *
 */
@Component
public class RestAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    private UserDetailsService userDetailsService;

    /**
     * Sets the user details service.
     *
     * @param userDetailsService the user details service to set
     */
    @Autowired
    public final void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public final Authentication authenticate(Authentication authentication) {
        Assert.isInstanceOf(
                UsernamePasswordAuthenticationToken.class,
                authentication, "Only UsernamePasswordAuthenticationToken is supported");

        // Determine username
        String username = authentication.getName();
        UserDetails user = null;

        try {
            user = retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication);
        } catch (ClassCastException | UsernameNotFoundException ex) {
            throw new BadCredentialsException("Bad credentials");
        }

        Assert.notNull(user, "retrieveUser returned null - a violation of the interface contract");

        return createSuccessAuthentication(user, authentication, user);
    }

    @Override
    protected final UserDetails retrieveUser(final String username, final UsernamePasswordAuthenticationToken authentication) {
        UserDetails loadedUser;

        if (userDetailsService == null) {
            throw new IllegalStateException("userDetailsService must be set before using this!");
        }

        loadedUser = userDetailsService.loadUserByUsername(username);

        if (loadedUser == null) {
            throw new AuthenticationServiceException("User not valid");
        }

        return loadedUser;
    }

    @Override
    protected void additionalAuthenticationChecks(final UserDetails arg0, final UsernamePasswordAuthenticationToken arg1)
            throws AuthenticationException {

    }
}
