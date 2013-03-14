/* Copyright 2006-2010 the original author or authors.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

import com.gramant.grails.springsecurity.vkontakte.VKontakteAuthUtils
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import com.gramant.grails.springsecurity.vkontakte.VKontakteAuthCookieDirectFilter
import com.gramant.grails.springsecurity.vkontakte.DefaultVKontakteAuthDao
import com.gramant.grails.springsecurity.vkontakte.VKontakteAuthProvider
import com.gramant.grails.springsecurity.vkontakte.VKontakteAuthCookieLogoutHandler
import com.gramant.grails.springsecurity.vkontakte.VKontakteAuthCookieTransparentFilter
import com.gramant.grails.springsecurity.vkontakte.VKontakteAuthRedirectFilter

class SpringSecurityVkontakteGrailsPlugin {

    String version = '0.1.45'
    String grailsVersion = '2.0 > *'
    Map dependsOn = [springSecurityCore: '1.2.7.2 > *']

//    def loadBefore = ['springSecurityCore']

    def license = 'APACHE'

    def developers = [
            //extra developers
    ]
    def issueManagement = [system: "GitHub", url: "https://github.com/spn/grails-spring-security-vkontakte/issues"]
    def scm = [url: "git@github.com:spn/grails-spring-security-vkontakte.git"]

    String author = 'Serge Nekoval'
    String authorEmail = 'nekoval@yandex.ru'
    String title = 'VKontakte Authentication'
    String description = 'VKontakte authentication support for the Spring Security plugin, basically a copy of grails-spring-security-facebook plugin.'

    String documentation = 'http://grails.org/plugin/spring-security-vkontakte'

    def doWithSpring = {

        def conf = SpringSecurityUtils.securityConfig
        if (!conf) {
            println 'ERROR: There is no Spring Security configuration'
            println 'ERROR: Stop configuring Spring Security VKontakte'
            return
        }

        println 'Configuring Spring Security VKontakte ...'
        SpringSecurityUtils.loadSecondaryConfig 'DefaultVKontakteSecurityConfig'
        // have to get again after overlaying DefaultVKontakteSecurityConfig
        conf = SpringSecurityUtils.securityConfig

        if (!conf.vkontakte.bean.dao) {
            conf.vkontakte.bean.dao = 'vkontakteAuthDao'
            vkontakteAuthDao(DefaultVKontakteAuthDao) {
                domainClassName = conf.vkontakte.domain.classname
                connectionPropertyName = conf.vkontakte.domain.connectionPropertyName
                userDomainClassName = conf.userLookup.userDomainClassName
                rolesPropertyName = conf.userLookup.authoritiesPropertyName
            }
        }

        List<String> _requiredPermissions = getAsStringList(conf.vkontakte.permissions, 'Required Permissions', 'vkontakte.permissions')

        vkontakteAuthUtils(VKontakteAuthUtils) {
            apiKey = conf.vkontakte.apiKey
            secret = conf.vkontakte.secret
            applicationId = conf.vkontakte.appId
            requiredPermissions = _requiredPermissions
        }

        if (!('vkontakteAuthProvider' in SpringSecurityUtils.providerNames)) {
            SpringSecurityUtils.registerProvider 'vkontakteAuthProvider'
            vkontakteAuthProvider(VKontakteAuthProvider) {
                vkontakteAuthDao = ref(conf.vkontakte.bean.dao)
                vkontakteAuthUtils = ref('vkontakteAuthUtils')
            }

            addFilters(conf, delegate)
        } else {
            println 'Already registered.'
        }

    }

    private List<String> getAsStringList(def conf, String paramHumanName, String paramName) {
        def raw = conf

        if (raw == null) {
            log.error("Invalid $paramHumanName filters configuration: '$raw'")
        } else if (raw instanceof Collection) {
            return raw.collect { it.toString() }
        } else if (raw instanceof String) {
            return raw.split(',').collect { it.trim() }
        } else {
            log.error("Invalid $paramHumanName filters configuration, invalid value type: '${raw.getClass()}'. Value should be defined as a Collection or String (comma separated, if you need few filters)")
        }
        return null
    }

    private void addFilters(def conf, def delegate) {
        def typesRaw = conf.vkontakte.filter.types
        List<String> types = null
        if (!typesRaw) {
            typesRaw = conf.vkontakte.filter.type
        }

        String defaultType = 'transparent'
        List validTypes = ['transparent', 'cookieDirect', 'redirect']

        if (!typesRaw) {
            log.error("Invalid VKontakte Authentication filters configuration: '$typesRaw'. Should be used on of: $validTypes. Current value will be ignored, and type '$defaultType' will be used instead.")
            types = [defaultType]
        } else if (typesRaw instanceof Collection) {
            types = typesRaw.collect { it.toString() }.findAll { it in validTypes }
        } else if (typesRaw instanceof String) {
            types = typesRaw.split(',').collect { it.trim() }.findAll { it in validTypes }
        }

        if (!types || types.empty) {
            log.error("VKontakte Authentication filter is not configured. Should be used on of: $validTypes, and '$defaultType' will be used by default.")
            log.error("To configure VKontakte Authentication filters you should add to Config.groovy:")
            log.error("grails.plugins.springsecurity.vkontakte.filter.types='transparent'")
            log.error("or")
            log.error("grails.plugins.springsecurity.vkontakte.filter.types='transparent,cookieDirect'")

            types = [defaultType]
        }

        int basePosition = conf.vkontakte.filter.position

        addFilter.delegate = delegate
        types.eachWithIndex { name, idx ->
            addFilter(conf, name, basePosition + 1 + idx)
        }
    }

    private addFilter = { def conf, String name, int position ->

        if (name == 'transparent') {

            SpringSecurityUtils.registerFilter 'vkontakteAuthCookieTransparentFilter', position
            vkontakteAuthCookieTransparentFilter(VKontakteAuthCookieTransparentFilter) {
                authenticationManager = ref('authenticationManager')
                vkontakteAuthUtils = ref('vkontakteAuthUtils')
                logoutUrl = conf.logout.filterProcessesUrl
                forceLoginParameter = conf.vkontakte.filter.forceLoginParameter
            }
            vkontakteAuthCookieLogout(VKontakteAuthCookieLogoutHandler) {
                vkontakteAuthUtils = ref('vkontakteAuthUtils')
            }
            SpringSecurityUtils.registerLogoutHandler('vkontakteAuthCookieLogout')
//        } else if (name == 'cookieDirect') {
//            SpringSecurityUtils.registerFilter 'vkontakteAuthCookieDirectFilter', position
//            vkontakteAuthCookieDirectFilter(VKontakteAuthCookieDirectFilter, conf.vkontakte.filter.processUrl) {
//                authenticationManager = ref('authenticationManager')
//                vkontakteAuthUtils = ref('vkontakteAuthUtils')
//            }
        } else if (name == 'redirect') {
            SpringSecurityUtils.registerFilter 'vkontakteAuthRedirectFilter', position
            vkontakteAuthRedirectFilter(VKontakteAuthRedirectFilter, conf.vkontakte.filter.processUrl) {
                authenticationManager = ref('authenticationManager')
                vkontakteAuthUtils = ref('vkontakteAuthUtils')
                redirectFromUrl = conf.vkontakte.filter.redirectFromUrl
                linkGenerator = ref('grailsLinkGenerator')
            }
        } else {
            log.error("Invalid filter type: $name")
        }
    }

    def doWithApplicationContext = { ctx ->
    }
}
