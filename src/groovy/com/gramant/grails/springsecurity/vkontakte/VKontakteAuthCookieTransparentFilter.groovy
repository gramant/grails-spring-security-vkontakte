package com.gramant.grails.springsecurity.vkontakte

import org.springframework.web.filter.GenericFilterBean
import org.springframework.context.ApplicationEventPublisherAware
import org.springframework.context.ApplicationEventPublisher
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import org.springframework.security.core.context.SecurityContextHolder
import javax.servlet.http.HttpServletRequest
import org.springframework.security.core.Authentication
import org.springframework.security.authentication.AuthenticationManager
import javax.servlet.http.HttpServletResponse
import org.springframework.security.authentication.BadCredentialsException

/**
 * TODO
 *
 * @since 14.10.11
 * @author Igor Artamonov (http://igorartamonov.com)
 */
class VKontakteAuthCookieTransparentFilter extends GenericFilterBean implements ApplicationEventPublisherAware {

    ApplicationEventPublisher applicationEventPublisher
    VKontakteAuthUtils vkontakteAuthUtils
    AuthenticationManager authenticationManager
    String logoutUrl = '/j_spring_security_logout'
    String forceLoginParameter = null
    String filterProcessUrl

    void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, javax.servlet.FilterChain chain) {
        HttpServletRequest request = servletRequest
        HttpServletResponse response = servletResponse
        String url = request.requestURI.substring(request.contextPath.length())
        logger.debug("Processing url: $url")
        if (url != logoutUrl
            && (SecurityContextHolder.context.authentication == null
                || (forceLoginParameter
                    && servletRequest.getParameter(forceLoginParameter) == 'true'))) {
            logger.debug("Applying vkontakte auth filter")
            assert vkontakteAuthUtils != null
            String cookie = vkontakteAuthUtils.getAuthCookie(request)
            if (cookie != null) {
                try {
                    VKontakteAuthToken token = vkontakteAuthUtils.build(cookie)
                    if (token != null) {

                        // Two cases:
                        // 1. We have cookie and accessToken, therefore should authenticate OK.
                        // 2. We have cookie and code, therefore need to request an acess token.
                        Authentication authentication = authenticationManager.authenticate(token)

                        if (!authentication.authenticated && !token.code) {
                            // Make OAuth request when auth code is present.
                            logger.debug "OAuth endpoint ${request.queryString}"
                            String code = request.getParameter('code')
                            if (code) {
                                // give a second chance to authenticate
                                token.code = code
                                token.authenticated = true      // have to reset...
                                authentication = authenticationManager.authenticate(token)
                            }
                        }

                        if (authentication.authenticated) {
                            // Store to SecurityContextHolder
                            SecurityContextHolder.context.authentication = authentication

                            if (logger.isDebugEnabled()) {
                                logger.debug("SecurityContextHolder populated with VKontakteAuthToken: '"
                                    + SecurityContextHolder.context.authentication + "'")
                            }
                            try {
                                chain.doFilter(request, response)
                            } finally {
                                SecurityContextHolder.context.authentication = null
                            }
                            return
                        }
                    }
                } catch (BadCredentialsException e) {
                    logger.info("Invalid cookie, skip. Message was: $e.message")
                }
            } else {
                logger.debug("No auth cookie")
            }
        } else {
            logger.debug("SecurityContextHolder not populated with VKontakteAuthToken token, as it already contained: $SecurityContextHolder.context.authentication");
        }

        //when not authenticated, dont have auth cookie or bad credentials
        chain.doFilter(request, response)
    }


}
