package com.gramant.grails.springsecurity.vkontakte

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.GrantedAuthorityImpl
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import org.springframework.beans.factory.InitializingBean
import org.springframework.context.ApplicationContextAware
import org.springframework.context.ApplicationContext
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.codehaus.groovy.grails.plugins.support.aware.GrailsApplicationAware
import org.apache.log4j.Logger
import org.springframework.security.core.userdetails.UserDetails
import java.util.concurrent.TimeUnit

/**
 * TODO
 *
 * @since 28.10.11
 * @author Igor Artamonov (http://igorartamonov.com)
 */
class DefaultVKontakteAuthDao implements VKontakteAuthDao<Object>, InitializingBean, ApplicationContextAware, GrailsApplicationAware {

    private static def log = Logger.getLogger(this)

    GrailsApplication grailsApplication
    ApplicationContext applicationContext

    String domainClassName

    String connectionPropertyName
    String userDomainClassName
    String rolesPropertyName
    List<String> defaultRoleNames = ['ROLE_USER', 'ROLE_VKONTAKTE']

    def vkontakteAuthService
    DomainsRelation domainsRelation = DomainsRelation.JoinedUser

    Object getVKontakteUser(Object user) {
        if (vkontakteAuthService && vkontakteAuthService.respondsTo('getVKontakteUser', user.class)) {
            return vkontakteAuthService.getVKontakteUser(user)
        }
        if (domainsRelation == DomainsRelation.JoinedUser) {
            return user?.getAt(connectionPropertyName)// load the User object to memory prevent LazyInitializationException
        }
        if (domainsRelation == DomainsRelation.SameObject) {
            return user
        }
        log.error("Invalid domainsRelation value: $domainsRelation")
        return user
    }

    Object findUser(long uid) {
        if (vkontakteAuthService && vkontakteAuthService.respondsTo('findUser', Long)) {
            return vkontakteAuthService.findUser(uid)
        }
		Class<?> User = grailsApplication.getDomainClass(domainClassName)?.clazz
        if (!User) {
            log.error("Can't find domain: $domainClassName")
            return null
        }
        def user = null
        User.withTransaction { status ->
            user = User.findWhere(uid: uid)
            if (user
                    && !(vkontakteAuthService && vkontakteAuthService.respondsTo('getVKontakteUser', user.class))
                    && domainsRelation == DomainsRelation.JoinedUser) {
                getVKontakteUser(user) // load the User object to memory prevent LazyInitializationException
            }
        }
        return user
    }

    Object create(VKontakteAuthToken token) {
        if (vkontakteAuthService && vkontakteAuthService.respondsTo('create', VKontakteAuthToken)) {
            return vkontakteAuthService.create(token)
        }

        def securityConf = SpringSecurityUtils.securityConfig

        Class<?> UserClass = grailsApplication.getDomainClass(domainClassName)?.clazz
        if (!UserClass) {
            log.error("Can't find domain: $domainClassName")
            return null
        }

        def user = grailsApplication.getDomainClass(domainClassName).newInstance()
        user.uid = token.uid
        if (user.properties.containsKey('accessToken')) {
            user.accessToken = token.accessToken?.accessToken
        }
        if (user.properties.containsKey('accessTokenExpires')) {
            user.accessTokenExpires = token.accessToken?.expireAt
        }

        def appUser
        if (domainsRelation == DomainsRelation.JoinedUser) {
            if (vkontakteAuthService && vkontakteAuthService.respondsTo('createAppUser', UserClass, VKontakteAuthToken)) {
                appUser = vkontakteAuthService.createAppUser(user, token)
            } else {
                Class<?> UserDomainClass = grailsApplication.getDomainClass(userDomainClassName).clazz
                if (!UserDomainClass) {
                    log.error("Can't find user domain: $userDomainClassName")
                    return null
                }
                appUser = UserDomainClass.newInstance()
                if (vkontakteAuthService && vkontakteAuthService.respondsTo('prepopulateAppUser', UserDomainClass, VKontakteAuthToken)) {
                    vkontakteAuthService.prepopulateAppUser(appUser, token)
                } else {
                    appUser[securityConf.userLookup.usernamePropertyName] = "vkontakte_$token.uid"
                    appUser[securityConf.userLookup.passwordPropertyName] = token.accessToken.accessToken
                    appUser[securityConf.userLookup.enabledPropertyName] = true
                    appUser[securityConf.userLookup.accountExpiredPropertyName] = false
                    appUser[securityConf.userLookup.accountLockedPropertyName] = false
                    appUser[securityConf.userLookup.passwordExpiredPropertyName] = false
                }
                UserDomainClass.withTransaction {
                    appUser.save(flush: true, failOnError: true)
                }
            }
            user[connectionPropertyName] = appUser
        }

        if (vkontakteAuthService && vkontakteAuthService.respondsTo('onCreate', UserClass, token)) {
            vkontakteAuthService.onCreate(user, token)
        }

        UserClass.withTransaction {
            user.save(flush: true, failOnError: true)
        }

        if (vkontakteAuthService && vkontakteAuthService.respondsTo('afterCreate', UserClass, token)) {
            vkontakteAuthService.afterCreate(user, token)
        }

        if (vkontakteAuthService && vkontakteAuthService.respondsTo('createRoles', UserClass)) {
            vkontakteAuthService.createRoles(user)
        } else {
            Class<?> PersonRole = grailsApplication.getDomainClass(securityConf.userLookup.authorityJoinClassName).clazz
            Class<?> Authority = grailsApplication.getDomainClass(securityConf.authority.className).clazz
            PersonRole.withTransaction { status ->
                defaultRoleNames.each { String roleName ->
                    String findByField = securityConf.authority.nameField[0].toUpperCase() + securityConf.authority.nameField.substring(1)
                    def auth = Authority."findBy${findByField}"(roleName)
                    if (auth) {
                        PersonRole.create(appUser, auth)
                    } else {
                        log.error("Can't find authority for name '$roleName'")
                    }
                }
            }

        }

        return user
    }

    Object getPrincipal(Object user) {
        if (vkontakteAuthService && vkontakteAuthService.respondsTo('getPrincipal', user.class)) {
            return vkontakteAuthService.getPrincipal(user)
        }
        if (domainsRelation == DomainsRelation.JoinedUser) {
            return user[connectionPropertyName]
        }
        return user
    }

    Collection<GrantedAuthority> getRoles(Object user) {
        if (vkontakteAuthService && vkontakteAuthService.respondsTo('getRoles', user.class)) {
            return vkontakteAuthService.getRoles(user)
        }

        if (UserDetails.isAssignableFrom(user.class)) {
            return ((UserDetails)user).getAuthorities()
        }

        def conf = SpringSecurityUtils.securityConfig
        Class<?> PersonRole = grailsApplication.getDomainClass(conf.userLookup.authorityJoinClassName)?.clazz
        if (!PersonRole) {
            log.error("Can't load roles for user $user. Reason: can't find ${conf.userLookup.authorityJoinClassName} class")
            return []
        }
        Collection roles = []
        PersonRole.withTransaction { status ->
            roles = user?.getAt(rolesPropertyName)
        }
        if (!roles) {
            roles = []
        }
        if (roles.empty) {
            return roles
        }
        return roles.collect {
            if (it instanceof String) {
                return new GrantedAuthorityImpl(it.toString())
            } else {
                new GrantedAuthorityImpl(it[conf.authority.nameField])
            }
        }
    }

    /**
     * @param user VK user
     * @return
     */
    Boolean hasValidToken(Object user) {
        if (vkontakteAuthService && vkontakteAuthService.respondsTo('hasValidToken', user.class)) {
            return vkontakteAuthService.hasValidToken(user)
        }
        def vkUser = user //getVKontakteUser(user)
        if (vkUser.properties.containsKey('accessToken')) {
            if (vkUser.accessToken == null) {
                return false
            }
        }
        if (vkUser.properties.containsKey('accessTokenExpires')) {
            if (vkUser.accessTokenExpires == null) {
                return false
            }
            Date goodExpiration = new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(4))
            if (goodExpiration.after(vkUser.accessTokenExpires)) {
                return false
            }
        } else {
            log.warn("Domain ${vkUser.class} don't have 'acccessTokenExpires' field, can't check accessToken expiration")
        }
        return true //not supported currently
    }

    void updateToken(Object user, VKontakteAuthToken token) {
        if (vkontakteAuthService && vkontakteAuthService.respondsTo('updateToken', user.class, token.class)) {
            vkontakteAuthService.updateToken(user, token)
            return
        }
        log.debug("Update access token to $token")
        def vkUser = getVKontakteUser(user)
        if (vkUser.properties.containsKey('accessToken')) {
            vkUser.accessToken = token.accessToken.accessToken
        }
        if (vkUser.properties.containsKey('accessTokenExpires')) {
            vkUser.accessTokenExpires = token.accessToken.expireAt
        }
        Class<?> UserClass = grailsApplication.getDomainClass(domainClassName)?.clazz
        if (!UserClass) {
            log.error("Can't find domain: $domainClassName")
            return
        }
        UserClass.withTransaction {
            vkUser.save()
        }
    }

    String getAccessToken(Object user) {
        if (vkontakteAuthService && vkontakteAuthService.respondsTo('getAccessToken', user.class)) {
            return vkontakteAuthService.getAccessToken(user)
        }
        def vkUser = user //getVKontakteUser(user)
        if (vkUser.properties.containsKey('accessToken')) {
            return vkUser.accessToken
        }
        return null
    }

    void afterPropertiesSet() {
        if (!vkontakteAuthService) {
            if (applicationContext.containsBean('vkontakteAuthService')) {
                log.debug("Use provided vkontakteAuthService")
                vkontakteAuthService = applicationContext.getBean('vkontakteAuthService')
            }
        }

        //validate configuration

        List serviceMethods = []
        if (vkontakteAuthService) {
            vkontakteAuthService.metaClass.methods.each {
                serviceMethods<< it.name
            }
        }

        def conf = SpringSecurityUtils.securityConfig
        if (!serviceMethods.contains('getRoles')) {
            Class<?> UserDomainClass = grailsApplication.getDomainClass(userDomainClassName)?.clazz
            if (UserDomainClass == null || !UserDetails.isAssignableFrom(UserDomainClass)) {
                if (!conf.userLookup.authorityJoinClassName) {
                    log.error("Don't have authority join class configuration. Please configure 'grails.plugins.springsecurity.userLookup.authorityJoinClassName' value")
                } else if (!grailsApplication.getDomainClass(conf.userLookup.authorityJoinClassName)) {
                    log.error("Can't find authority join class (${conf.userLookup.authorityJoinClassName}). Please configure 'grails.plugins.springsecurity.userLookup.authorityJoinClassName' value, or create your own 'List<GrantedAuthority> vkontakteAuthService.getRoles(user)'")
                }
            }
        }
        if (!serviceMethods.contains('findUser')) {
            if (!domainClassName) {
                log.error("Don't have VKontakte user class configuration. Please configure 'grails.plugins.springsecurity.vkontakte.domain.classname' value")
            } else {
                Class<?> User = grailsApplication.getDomainClass(domainClassName)?.clazz
                if (!User) {
                    log.error("Can't find VKontakte user class ($domainClassName). Please configure 'grails.plugins.springsecurity.vkontakte.domain.classname' value, or create your own 'Object vkontakteAuthService.findUser(long)'")
                }
            }
        }
    }
}
