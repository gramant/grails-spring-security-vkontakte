package com.gramant.grails.springsecurity.vkontakte

import org.springframework.security.core.Authentication
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.GrantedAuthority

import org.springframework.security.core.userdetails.User
import org.apache.log4j.Logger
import org.springframework.context.ApplicationContext
import org.springframework.beans.factory.InitializingBean
import org.springframework.context.ApplicationContextAware

public class VKontakteAuthProvider implements AuthenticationProvider, InitializingBean, ApplicationContextAware {

    private static def log = Logger.getLogger(this)

    VKontakteAuthDao vkontakteAuthDao
    VKontakteAuthUtils vkontakteAuthUtils
    def vkontakteAuthService
    ApplicationContext applicationContext

    boolean createNew = true

    /**
     * What we get at this point could be:
     * <ol>
     *     <li>Just uid - when we come from OpenAPI</li>
     *     <li>uid + code - when we passed through an OAuth Dialog (http://vk.com/developers.php?oid=-1&p=%D0%94%D0%B8%D0%B0%D0%BB%D0%BE%D0%B3_%D0%B0%D0%B2%D1%82%D0%BE%D1%80%D0%B8%D0%B7%D0%B0%D1%86%D0%B8%D0%B8_OAuth)
     *  </ol>
     * @param authentication
     * @return
     */
    public Authentication authenticate(Authentication authentication) {
        VKontakteAuthToken token = authentication

        if (token.uid <= 0) {
            if (!token.code) {
                log.error("Token should contain 'code' to get used access_token and uid")
                token.authenticated = false
                return token
            }

            VKontakteAccessToken accessToken = vkontakteAuthUtils.getAccessToken(token.code, token.redirectUri)
            token.accessToken = accessToken
            token.uid = accessToken.uid

            if (token.accessToken == null) {
                log.error("Can't fetch access_token for code '$token.code'")
                token.authenticated = false
                return token
            }

        }

        def user = vkontakteAuthDao.findUser(token.uid as Long)
        boolean justCreated = false

        if (user == null) {
            //log.debug "New person $token.uid"
            if (createNew) {
                log.info "Create new vkontakte user with uid $token.uid"
                if (token.accessToken == null) {
                    //untested
                    token.accessToken = vkontakteAuthUtils.getAccessToken(token.code, token.redirectUri)
                }
                if (token.accessToken == null) {
                    log.error("Creating user w/o access_token")
                }
                user = vkontakteAuthDao.create(token)
                justCreated = true
            } else {
                log.error "User $token.uid not exists - not authenticated"
            }
        }

        if (user != null) {
            if (!justCreated && !vkontakteAuthDao.hasValidToken(user)) {

                vkontakteAuthDao.updateToken(user, token)
            }

            UserDetails userDetails = createUserDetails(user, token.accessToken.accessToken)

            token.details = userDetails
            token.principal = vkontakteAuthDao.getPrincipal(user)
            token.authorities = userDetails.getAuthorities()
            token.authenticated
        } else {
            token.authenticated = false
        }

        return token
    }

    public boolean supports(Class<? extends Object> authentication) {
        return VKontakteAuthToken.isAssignableFrom(authentication);
    }

    protected UserDetails createUserDetails(Object vkUserUser, String secret) {
        if (vkontakteAuthService && vkontakteAuthService.respondsTo('createUserDetails', vkUserUser.class)) {
            return vkontakteAuthService.createUserDetails(vkUserUser)
        }
        Collection<GrantedAuthority> roles = vkontakteAuthDao.getRoles(vkontakteAuthDao.getPrincipal(vkUserUser))
        new User(vkUserUser.uid.toString(), secret, true,
             true, true, true, roles)
    }

    void afterPropertiesSet() {
        if (!vkontakteAuthService) {
            if (applicationContext.containsBean('vkontakteAuthService')) {
                log.debug("Use provided vkontakteAuthService")
                vkontakteAuthService = applicationContext.getBean('vkontakteAuthService')
            }
        }
    }
}