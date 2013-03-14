package com.gramant.grails.springsecurity.vkontakte

/**
 * 
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 22.05.12
 */
class VKontakteAccessToken {

  String accessToken
  Date expireAt
  long uid

  String toString() {
      StringBuilder buf = new StringBuilder()
      buf.append('Access token: ').append(accessToken)
      buf.append(', expires at ').append(expireAt)
      return buf.toString()
  }

}
