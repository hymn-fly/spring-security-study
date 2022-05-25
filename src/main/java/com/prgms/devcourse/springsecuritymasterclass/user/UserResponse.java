package com.prgms.devcourse.springsecuritymasterclass.user;

class UserResponse {

    private final String token;

    private final String username;

    private final String group;

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
