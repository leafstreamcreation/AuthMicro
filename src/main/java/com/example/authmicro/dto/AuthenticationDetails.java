package com.example.authmicro.dto;

public class AuthenticationDetails {
    private Long userId;
    private String serviceName;
    private String token;

    public AuthenticationDetails(Long userId, String serviceName, String token) {
        this.userId = userId;
        this.serviceName = serviceName;
        this.token = token;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getServiceName() {
        return serviceName;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
};