package com.gramant.grails.springsecurity.vkontakte

import org.springframework.security.web.authentication.logout.LogoutHandler
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.security.core.Authentication
import javax.servlet.http.Cookie
import org.apache.log4j.Logger
import java.util.regex.Matcher
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

/**
 *
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 04.11.11
 */
class VKontakteAuthCookieLogoutHandler implements LogoutHandler {

    private static final Logger logger = Logger.getLogger(this)

    VKontakteAuthUtils vkontakteAuthUtils

    void logout(HttpServletRequest httpServletRequest,
                HttpServletResponse httpServletResponse,
                Authentication authentication) {

        String baseDomain = null

        List<Cookie> cookies = httpServletRequest.cookies.findAll { Cookie it ->
            //VKontakteAuthUtils.log.debug("Cookier $it.name, expected $cookieName")
            return it.name == "vk_app_${vkontakteAuthUtils.applicationId}"
        }

        baseDomain = cookies.find {
            return it.name == "vk_app_${vkontakteAuthUtils.applicationId}" && it.value ==~ /base_domain=.+/
        }?.value?.split('=')?.last()

        if (!baseDomain) {
            //Facebook uses invalid cookie format, so sometimes we need to parse it manually
            String rawCookie = httpServletRequest.getHeader('Cookie')
            logger.info("raw cookie: $rawCookie")
            if (rawCookie) {
                Matcher m = rawCookie =~ /vk_app_$vkontakteAuthUtils.applicationId=base_domain=(.+?);/
                if (m.find()) {
                    baseDomain = m.group(1)
                }
            }
        }

        if (!baseDomain) {
            def conf = SpringSecurityUtils.securityConfig.facebook
            if (conf.host && conf.host.length > 0) {
                baseDomain = conf.host
            }
            logger.debug("Can't find base domain for VK cookie. Use '$baseDomain'")
        }

        cookies.each { cookie ->
            cookie.maxAge = 0
            cookie.path = '/'
            if (baseDomain) {
                cookie.domain = baseDomain
            }
            httpServletResponse.addCookie(cookie)
        }
    }
}
