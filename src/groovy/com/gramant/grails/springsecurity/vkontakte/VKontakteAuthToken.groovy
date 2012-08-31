package com.gramant.grails.springsecurity.vkontakte

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.Authentication
import org.springframework.security.authentication.AbstractAuthenticationToken

/**
 * Initially we only know user id (uid).
 */
public class VKontakteAuthToken extends AbstractAuthenticationToken implements Authentication {
	
	long uid
    VKontakteAccessToken accessToken
    String code

    Object principal
	
	Collection<GrantedAuthority> authorities
	
	def VKontakteAuthToken() {
		super([] as Collection<GrantedAuthority>);
	}	

	public Object getCredentials() {
		return uid;
	}

    String toString() {
        return "Principal: $principal, uid: $uid, roles: ${authorities.collect { it.authority}}"
    }

}