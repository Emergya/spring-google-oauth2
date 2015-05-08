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

import static org.springframework.security.core.authority.AuthorityUtils.commaSeparatedStringToAuthorityList;
import static org.springframework.util.StringUtils.arrayToCommaDelimitedString;
import static org.springframework.util.StringUtils.collectionToCommaDelimitedString;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import com.emergya.spring.security.Role;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Copied from the original implementation of the <code>DefaultUserAuthenticationConverter</code> to fix a bug in the
 * <code>getAuthorities</code> method. Rest all unchanged. Class with the original bug
 * <code>org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter</code>
 */
@Component
public class DefaultUserAuthenticationConverter extends org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter {

    private Collection<? extends GrantedAuthority> defaultAuthorities;

    private AuthorityGranter authorityGranter;

    private UserDetailsService userDetailsService;

    @Autowired
    @Override
    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /**
     * Default value for authorities if an Authentication is being created and the input has no data for authorities. Note that
     * unless this property is set, the default Authentication created by {@link #extractAuthentication(java.util.Map)} will be
     * unauthenticated.
     *
     * @param defaultAuthorities the defaultAuthorities to set. Default null.
     */
    @Override
    public void setDefaultAuthorities(String[] defaultAuthorities) {
        this.defaultAuthorities = commaSeparatedStringToAuthorityList(arrayToCommaDelimitedString(defaultAuthorities));
    }

    /**
     * Authority granter which can grant additional authority to the user based on custom rules.
     *
     * @param authorityGranter
     */
    public void setAuthorityGranter(AuthorityGranter authorityGranter) {
        this.authorityGranter = authorityGranter;
    }

    private static final String EMAIL = "email";

    @Override
    public Authentication extractAuthentication(Map<String, ?> map) {
        UserDetails userDetails = null;
        if (map.containsKey(EMAIL)) {
            userDetails = userDetailsService.loadUserByUsername((String) map.get(EMAIL));
        } else if (map.containsKey(USERNAME)) {
            userDetails = userDetailsService.loadUserByUsername((String) map.get(USERNAME));
        }

        if (userDetails != null) {
            return new UsernamePasswordAuthenticationToken(userDetails, "N/A", getAuthorities(map, userDetails.getAuthorities()));
        }
        return null;
    }

    private Collection<? extends GrantedAuthority> getAuthorities(Map<String, ?> map, Collection<? extends GrantedAuthority> auths) {
        List<GrantedAuthority> authorityList = (List<GrantedAuthority>) auths;
        if (!map.containsKey(AUTHORITIES)) {
            assignDefaultAuthorities(authorityList);
        } else {
            grantAuthoritiesBasedOnValuesInMap(map, authorityList);
        }
        grantAdditionalAuthorities(map, authorityList);
        return authorityList;
    }

    private void grantAuthoritiesBasedOnValuesInMap(Map<String, ?> map, List<GrantedAuthority> authorityList) {
        List<GrantedAuthority> parsedAuthorities = parseAuthorities(map);
        authorityList.addAll(parsedAuthorities);
    }

    private void grantAdditionalAuthorities(Map<String, ?> map, List<GrantedAuthority> authorityList) {
        if (authorityGranter != null) {
            authorityList.addAll(authorityGranter.getAuthorities(map));
        }
        //Added ROLE_GOOGLE to the authorities
        authorityList.add(new SimpleGrantedAuthority(Role.ROLE_GOOGLE.getName()));
    }

    private void assignDefaultAuthorities(List<GrantedAuthority> authorityList) {
        if (defaultAuthorities != null) {
            authorityList.addAll(defaultAuthorities);
        }
    }

    private List<GrantedAuthority> parseAuthorities(Map<String, ?> map) {
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
