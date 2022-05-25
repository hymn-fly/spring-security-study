package com.prgms.devcourse.springsecuritymasterclass.user;

class UserResponse {

    private String token;

    private String username;

    private String group;

    UserResponse(){ /* for object mapper deserialization */}

    UserResponse(String token, String username, String group) {
        this.token = token;
        this.username = username;
        this.group = group;
    }

    public String getToken() {
        return token;
    }

    public String getUsername() {
        return username;
    }

    public String getGroup() {
        return group;
    }
}
