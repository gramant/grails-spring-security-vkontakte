package com.gramant.grails.springsecurity.vkontakte

import org.springframework.security.core.AuthenticationException

/**
 * 
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 05.07.12
 */
class InvalidCookieException extends AuthenticationException {

    InvalidCookieException(String msg) {
        super(msg)
    }

    InvalidCookieException(String msg, Object extraInformation) {
        super(msg, extraInformation)
    }
}
