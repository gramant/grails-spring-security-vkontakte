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

        def user = vkontakteAuthDao.findUser(token.uid as Long)
        boolean justCreated = false


        if (user == null) {

            // If we don't have OAuth code, cannot authenticate.
            if (!token.code) {
                token.authenticated = false
                return token
            }

            //log.debug "New person $token.uid"
            if (createNew) {
                log.info "Create new VKontakte user with uid $token.uid"
                token.accessToken = vkontakteAuthUtils.getAccessToken(token.code)
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
            if (!justCreated) {
                if (!vkontakteAuthDao.hasValidToken(user)) {
                    String currentAccessToken = vkontakteAuthDao.getAccessToken(user)
                    VKontakteAccessToken freshToken = null
                    if (currentAccessToken) {
                        try {
                            freshToken = vkontakteAuthUtils.refreshAccessToken(currentAccessToken)
                            if (!freshToken) {
                                log.warn("Can't refresh access token")
                            }
                        } catch (IOException e) {
                            log.warn("Can't refresh access token")
                        }
                    }

                    if (!freshToken) {
                        freshToken =  vkontakteAuthUtils.getAccessToken(token.code)
                    }

                    if (freshToken) {
                        if (freshToken.accessToken != currentAccessToken) {
                            token.accessToken = freshToken
                            vkontakteAuthDao.updateToken(user, token)
                        } else {
                            log.debug("User already have same access token")
                        }
                    }
                } else {
                    token.accessToken = new VKontakteAccessToken(accessToken: vkontakteAuthDao.getAccessToken(user))
                }
            }

            assert token.accessToken?.accessToken
            UserDetails userDetails = createUserDetails(user, token.accessToken.accessToken)

            token.details = userDetails
            token.principal = vkontakteAuthDao.getPrincipal(user)
            token.authorities = userDetails.getAuthorities()
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