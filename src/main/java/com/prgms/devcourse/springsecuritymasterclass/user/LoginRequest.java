package com.prgms.devcourse.springsecuritymasterclass.user;

class LoginRequest {
    public String user;

    public String password;

    /* For objectMapper mapping */
    public LoginRequest(){}

    public LoginRequest(String user, String password){
        this.user = user;
        this.password = password;
    }
}
