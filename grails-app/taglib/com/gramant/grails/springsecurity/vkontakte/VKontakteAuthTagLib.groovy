package com.gramant.grails.springsecurity.vkontakte

import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

/**
 * TODO
 *
 * @since 31.03.11
 * @author Igor Artamonov (http://igorartamonov.com)
 */

class VKontakteAuthTagLib {

	static namespace = 'vkontakteAuth'

    static final String MARKER = 'com.gramant.grails.springsecurity.vkontakte.VKontakteAuthTagLib#init'

	/** Dependency injection for springSecurityService. */
	def springSecurityService

    def init = { attrs, body ->
        Boolean init = request.getAttribute(MARKER)
        if (init == null) {
            init = false
        }

        def conf = SpringSecurityUtils.securityConfig.vkontakte
        if (conf.taglib?.initvk == false) {
            log.debug("VK Init is disabled. Skip")
            return
        }

        // Use async? Currently async does not work with auth button
        boolean async = false

        if (!init || attrs.force == 'true') {
            String lang = conf.taglib.language
            def appId = conf.appId

            if (async) {

                out << '<div id="vk_api_transport"></div>\n'

                out << '<script type="text/javascript">\n'

                out << "window.vkAsyncInit = function() {\n"

            } else {
                out << "<script src=\"http://vk.com/js/api/openapi.js\" type=\"text/javascript\"></script>"
                out << '<script type="text/javascript">\n'
            }

            out << "  VK.init({\n"
            out << "    apiId  : '${appId}'\n"
            out << "  });\n"

            out << body.call()

            if (async) {
                out << "};\n"

                out << """setTimeout(function() {
                    var el = document.createElement("script");
                    el.type = "text/javascript";
                    el.src = "http://vk.com/js/api/openapi.js";
                    el.async = true;
                    document.getElementById("vk_api_transport").appendChild(el);
                  }, 0);
                  """
            }

            out << '</script>\n'

            request.setAttribute(MARKER, true)
        }
    }

	def connect = { attrs, body ->
        def conf = SpringSecurityUtils.securityConfig.vkontakte

        if (attrs.skipInit != 'false') {
            out << init(attrs, body)
        }

        String buttonText = conf.taglib.button.text
        if (attrs.text) {
            buttonText = attrs.text
        }

        List permissions = []
        def rawPermissions
        if (attrs.permissions) {
            rawPermissions = attrs.permissions
        } else {
            rawPermissions = conf.taglib.permissions
        }
        if (rawPermissions) {
            if (rawPermissions instanceof Collection) {
                permissions = rawPermissions.findAll {
                    it != null
                }.collect {
                    it.toString().trim()
                }.findAll {
                    it.length() > 0
                }
            } else {
                permissions = rawPermissions.toString().split(',').collect { it.trim() }
            }
        } else {
            log.debug("Permissions aren't configured")
        }

        boolean showFaces = false
        String redirectUri = attrs.redirectUri ?: g.createLink(absolute: true, uri: '/')
        redirectUri += (redirectUri.contains('&') ? '&' : '?')
        redirectUri += conf.filter.forceLoginParameter
        redirectUri += '=true'
        String vkOauth = "http://oauth.vk.com/authorize?client_id=${conf.appId}&scope=SETTINGS&${permissions.join(',')}&redirect_uri=${redirectUri.encodeAsURL()}&response_type=code"

        out << """<div id="vk_auth"></div>
        <script type="text/javascript">
        VK.Widgets.Auth("vk_auth", {width: "200px", onAuth: function(data) { window.location = '${vkOauth}'; }});
        </script>
        """

    }


}