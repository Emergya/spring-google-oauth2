/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package com.emergya.spring.security.oauth;

import com.emergya.spring.security.Role;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import static org.springframework.security.core.authority.AuthorityUtils.commaSeparatedStringToAuthorityList;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import static org.springframework.util.StringUtils.arrayToCommaDelimitedString;
import static org.springframework.util.StringUtils.collectionToCommaDelimitedString;

/**
 * Copied from the original implementation of the <code>DefaultUserAuthenticationConverter</code> to fix a bug in the
 * <code>getAuthorities</code> method. Rest all unchanged. Class with the original bug
 * <code>org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter</code>
 */
@Component
public class UserServiceAuthenticationConverter
        extends org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter {

    private static final String EMAIL = "email";

    private Collection<? extends GrantedAuthority> defaultAuthorities;

    private AuthorityGranter authorityGranter;

    private UserDetailsService detailsService;

    @Autowired
    @Override
    public final void setUserDetailsService(final UserDetailsService userDetailsService) {
        this.detailsService = userDetailsService;
    }

    /**
     * Default value for authorities if an Authentication is being created and the input has no data for authorities. Note that
     * unless this property is set, the default Authentication created by {@link #extractAuthentication(java.util.Map)} will be
     * unauthenticated.
     *
     * @param newDefaultAuthorities the defaultAuthorities to set. Default null.
     */
    @Override
    public final void setDefaultAuthorities(final String[] newDefaultAuthorities) {
        this.defaultAuthorities = commaSeparatedStringToAuthorityList(arrayToCommaDelimitedString(newDefaultAuthorities));
    }

    /**
     * Authority granter which can grant additional authority to the user based on custom rules.
     *
     * @param newAuthorityGranter new authority granter instance to be used by the authentication converter.
     */
    public final void setAuthorityGranter(final AuthorityGranter newAuthorityGranter) {
        this.authorityGranter = newAuthorityGranter;
    }

    /**
     * Converts the user info provided by the OAuth endpoint into a Spring Security Authentication object.
     *
     * @param map A map containing the authentication info provided by the OAuth service.
     * @return An Authentication object instance containg the data extracted from the de details service.
     */
    @Override
    public final Authentication extractAuthentication(final Map<String, ?> map) {
        if (detailsService == null) {
            throw new IllegalStateException("userDetailsService must have been set before.");
        }

        UserDetails userDetails = null;
        if (map.containsKey(EMAIL)) {
            userDetails = detailsService.loadUserByUsername((String) map.get(EMAIL));
        } else if (map.containsKey(USERNAME)) {
            userDetails = detailsService.loadUserByUsername((String) map.get(USERNAME));
        }

        if (userDetails != null) {
            return new UsernamePasswordAuthenticationToken(userDetails, "N/A", getAuthorities(map, userDetails.getAuthorities()));
        }
        return null;
    }

    private Collection<? extends GrantedAuthority> getAuthorities(
            final Map<String, ?> map, final Collection<? extends GrantedAuthority> auths) {

        List<GrantedAuthority> authorityList;
        try {
            authorityList = (List<GrantedAuthority>) auths;
        } catch (ClassCastException ex) {
            throw new IllegalArgumentException("Unexpected auths parameter");
        }
        if (!map.containsKey(AUTHORITIES)) {
            assignDefaultAuthorities(authorityList);
        } else {
            grantAuthoritiesBasedOnValuesInMap(map, authorityList);
        }
        grantAdditionalAuthorities(map, authorityList);
        return authorityList;
    }

    private void grantAuthoritiesBasedOnValuesInMap(final Map<String, ?> map, final List<GrantedAuthority> authorityList) {
        List<GrantedAuthority> parsedAuthorities = parseAuthorities(map);
        authorityList.addAll(parsedAuthorities);
    }

    private void grantAdditionalAuthorities(final Map<String, ?> map, final List<GrantedAuthority> authorityList) {
        if (authorityGranter != null) {
            authorityList.addAll(authorityGranter.getAuthorities(map));
        }
        //Added ROLE_GOOGLE to the authorities
        authorityList.add(new SimpleGrantedAuthority(Role.ROLE_GOOGLE.name()));
    }

    private void assignDefaultAuthorities(final List<GrantedAuthority> authorityList) {
        if (defaultAuthorities != null) {
            authorityList.addAll(defaultAuthorities);
        }
    }

    private List<GrantedAuthority> parseAuthorities(final Map<String, ?> map) {
        Object authorities = map.get(AUTHORITIES);
        List<GrantedAuthority> parsedAuthorities;
        if (authorities instanceof String) {
            // Bugfix for Spring OAuth codebase
            parsedAuthorities = commaSeparatedStringToAuthorityList((String) authorities);
        } else if (authorities instanceof Collection) {
            parsedAuthorities = commaSeparatedStringToAuthorityList(collectionToCommaDelimitedString((Collection<?>) authorities));
        } else {
            throw new IllegalArgumentException("Authorities must be either a String or a Collection");
        }
        return parsedAuthorities;
    }
}
