package com.gramant.grails.springsecurity.vkontakte

public interface VKontakteUserDomain {
	
	String getAccessToken();
	void setAccessToken(String accessToken);
	
	long getUid();
	void setUid(long uid)
}