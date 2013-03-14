package com.gramant.grails.springsecurity.vkontakte

import org.apache.log4j.Logger
import javax.servlet.http.HttpServletRequest
import org.springframework.security.authentication.BadCredentialsException
import java.util.concurrent.TimeUnit
import org.apache.http.client.utils.URLEncodedUtils
import java.nio.charset.Charset
import org.apache.http.NameValuePair
import grails.converters.JSON
import org.codehaus.groovy.grails.web.json.JSONObject

/**
 * TODO
 *
 * @since 14.10.11
 * @author Igor Artamonov (http://igorartamonov.com)
 */
class VKontakteAuthUtils {

    private static def log = Logger.getLogger(this)

    private static Random RND = new Random()
    private int seq = 0

    String apiKey
    String secret
    String applicationId

    List<String> requiredPermissions = []

    VKontakteAuthToken build(String signedRequest) {
        if (!signedRequest) {
            return null
        }

        def params = URLEncodedUtils.parse(signedRequest, Charset.forName('utf-8'))
        def knownParams = ['expire', 'mid', 'secret', 'sid']

        StringBuilder sig = new StringBuilder()
        knownParams.each { param ->
            NameValuePair nvp = params.find { it.name == param }
            if (nvp) {
                sig.append(nvp.name)
                sig.append('=')
                sig.append(nvp.value)
            }
        }

        def signature = params.find { it.name == 'sig' }?.value

        if (!signature) {
            throw new BadCredentialsException('Malformed signature')
        }

        if (!verifySign(signature, sig.toString())) {
            throw new BadCredentialsException("Malformed signature")
        } else {
            log.debug "Signature is ok"
        }

        def uid = params.find{it.name == 'mid'}?.value

        VKontakteAuthToken token = new VKontakteAuthToken(
                uid: Long.parseLong(uid)
        )
        token.authenticated = true
        return token
    }

    /**
     * VK OpenAPI uses cookies which are not recognized by servlets, so use custom parsing.
     * Based on {@see http://vk-java-login.googlecode.com/svn-history/r6/trunk/vk-java-login-vk-auth/src/main/java/org/zav/auth/VkAuthentificator.java}
     * @param request
     * @return cookie value
     */
    public String getAuthCookie(HttpServletRequest request) {
        String cookieName = "vk_app_" + applicationId
        String cookieHeader = request.getHeader("cookie")
        log.debug "cookieHeader = $cookieHeader"

        if (cookieHeader == null) {
            return null
        }

        // Get cookie header
        String vkAppValue = null
        // parse several cookies
        String[] cookiesArray = cookieHeader.split("; ")
        for (String cookie : cookiesArray) {
            if (cookie != null && cookie.startsWith(cookieName + "=")) {
                vkAppValue = cookie
            }
        }
        log.debug "vkAppValue = $vkAppValue"

        if (vkAppValue == null) {
            return null
        }

        // get the cookie value
        return vkAppValue.substring((cookieName + "=").length())
    }



    // unsupported
    //UNTESTED!!!!
    VKontakteAccessToken refreshAccessToken(String existingAccessToken) {
        String authUrl = "https://oauth.vk.com/access_token?client_id=$applicationId&client_secret=$secret"
        return requestAccessToken(authUrl)
    }

    VKontakteAccessToken getAccessToken(String code, String redirect_uri) {
        String authUrl = "https://oauth.vk.com/access_token?client_id=$applicationId&client_secret=$secret&code=$code&redirect_uri=$redirect_uri"
        return requestAccessToken(authUrl)
    }


    VKontakteAccessToken requestAccessToken(String authUrl) {
        try {
            URL url = new URL(authUrl)
            String response = url.text
            JSONObject data = JSON.parse(response) as JSONObject
            VKontakteAccessToken token = new VKontakteAccessToken()
            if (data.access_token) {
                token.accessToken = data.access_token
            } else {
                log.error("No access_token in response: $response")
            }
            // expires_in is 0 for offline_access
            if (data.expires_in >= 0) {
                token.expireAt = new Date(System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(data.expires_in as Long))
            } else {
                log.error("No expires in response: $response")
            }
            //user_id
            if (data.user_id) {
                token.uid = new Long(data.user_id)
            } else {
                log.error("No user_id in response: $response")
            }

            log.debug("Got AccessToken: $token")
            return token
        } catch (IOException e) {
            log.error("Can't read data from VK", e)
            return null
        }
    }

    public boolean verifySign(String sign, String payload) {
//        String signer = 'HmacMD5'
//        //log.debug("Secret $secret")
//        SecretKeySpec sks = new SecretKeySpec(secret.getBytes(), signer)
//        //log.debug("Payload1: `$payload`")
//        payload = payload.replaceAll("-", "+").replaceAll("_", "/").trim()
//        //log.debug("Payload2: `$payload`")
//        sign = sign.replaceAll("-", "+").replaceAll("_", "/")
//        try {
//            Mac mac = Mac.getInstance(signer)
//            mac.init(sks)
//            byte[] my = mac.doFinal(payload.getBytes('UTF-8'))
//            byte[] their = Base64.decodeBase64(sign.getBytes('UTF-8'))
//            //log.info("My: ${new String(Base64.encodeBase64(my, false))}, their: ${new String(Base64.encodeBase64(their))} / $sign")
//            return Arrays.equals(my, their)
//        } catch (Exception e) {
//            log.error("Can't validate signature", e);
//            return false;
//        }
        return payload.encodeAsMD5() == sign

    }

    String prepareRedirectUrl(String authPath, List scope = []) {
        if (seq >= Integer.MAX_VALUE - 10000) {
            seq = 0
        }
        Map data = [
                client_id: applicationId,
                redirect_uri:  authPath,
                scope: scope.join(','),
                response_type: 'code',
                state: [seq++, RND.nextInt(1000000)].collect {Integer.toHexString(it)}.join('-')
        ]
        log.debug("Redirect to ${data.redirect_uri}")
        String url = "https://oauth.vk.com/authorize?" + data.entrySet().collect {
            [it.key, it.value].join('=')
        }.join('&')
        return url
    }
}
