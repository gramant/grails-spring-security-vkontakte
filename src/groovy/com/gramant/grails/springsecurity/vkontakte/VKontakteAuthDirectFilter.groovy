package com.gramant.grails.springsecurity.vkontakte

import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpServletRequest
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.core.Authentication

import org.apache.log4j.Logger

/**
 * unused!
 */
public class VKontakteAuthDirectFilter extends AbstractAuthenticationProcessingFilter {

    private static def log = Logger.getLogger(this)

    VKontakteAuthUtils vkontakteAuthUtils

    def VKontakteAuthDirectFilter(String url) {
        super(url)
    }

    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        VKontakteAuthToken token = vkontakteAuthUtils.build(request.getParameter('signedRequest'))
        if (token != null) {
            Authentication authentication = getAuthenticationManager().authenticate(token);
            return authentication
        }
        return null
    }
	
}