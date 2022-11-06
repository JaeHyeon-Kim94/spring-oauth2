package com.kjh.ex.springoauth2.security;

public enum SocialType {
    GOOGLE("google"),
    KAKAO("kakao"),
    NAVER("naver");

    private final String ROLE_PREFIX = "ROLE_";
    private String name;

    SocialType(String naver) {
        this.name = name;
    }

    public String getRoleType(){ return ROLE_PREFIX+name.toUpperCase(); }
    public String getValue() { return name; }

    public boolean isEqual(String authority) { return this.getRoleType().equals(authority); }


}
