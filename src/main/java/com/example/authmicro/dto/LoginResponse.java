package com.example.authmicro.dto;

public class LoginResponse {
    
    private String token;
    private long expiresIn;
    private boolean requires2FA;
    private String message;

    public LoginResponse() {}

    public LoginResponse(String token, long expiresIn) {
        this.token = token;
        this.expiresIn = expiresIn;
        this.requires2FA = false;
    }

    public LoginResponse(boolean requires2FA, String message) {
        this.requires2FA = requires2FA;
        this.message = message;
    }

    public LoginResponse(String message) {
        this.message = message;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }

    public boolean isRequires2FA() {
        return requires2FA;
    }

    public void setRequires2FA(boolean requires2FA) {
        this.requires2FA = requires2FA;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
