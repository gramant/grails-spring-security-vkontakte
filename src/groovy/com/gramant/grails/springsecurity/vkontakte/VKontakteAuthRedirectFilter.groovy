/**
 */
package com.gramant.grails.springsecurity.vkontakte

import org.codehaus.groovy.grails.web.mapping.LinkGenerator
import org.springframework.security.core.Authentication
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.core.AuthenticationException

class VKontakteAuthRedirectFilter extends AbstractAuthenticationProcessingFilter {

    VKontakteAuthUtils vkontakteAuthUtils

    String redirectFromUrl

    LinkGenerator linkGenerator

    VKontakteAuthRedirectFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl)
    }

    @Override
    Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String code = request.getParameter('code')
        if (code) {
            VKontakteAuthToken token = new VKontakteAuthToken(
                    code: code,
                    uid: -1,
                    redirectUri: getAbsoluteRedirectUrl()
            )
            return authenticationManager.authenticate(token)
        }
        throw new AuthenticationException("Request is empty") {};
    }

    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String uri = request.getRequestURI();

        int pathParamIndex = uri.indexOf(';');

        if (pathParamIndex > 0) {
            // strip everything after the first semi-colon
            uri = uri.substring(0, pathParamIndex);
        }

        uri = uri.substring(request.contextPath.length())

        if (uri.equals(redirectFromUrl)) {
            response.sendRedirect(vkontakteAuthUtils.prepareRedirectUrl(getAbsoluteRedirectUrl(), vkontakteAuthUtils.requiredPermissions))
            return false
        }

        return uri.equals(filterProcessesUrl)
    }

    String getAbsoluteRedirectUrl() {
        String path = getFilterProcessesUrl()
        linkGenerator.link(uri: path, absolute: true)
    }
}
