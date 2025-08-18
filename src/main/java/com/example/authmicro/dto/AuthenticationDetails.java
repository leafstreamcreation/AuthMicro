package com.example.authmicro.dto;

public class AuthenticationDetails {
    private Long userId;
    private String serviceName;
    private String latest_JWT;

    public AuthenticationDetails(Long userId, String serviceName, String latest_JWT) {
        this.userId = userId;
        this.serviceName = serviceName;
        this.latest_JWT = latest_JWT;
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

    public String getLatest_JWT() {
        return latest_JWT;
    }

    public void setLatest_JWT(String latest_JWT) {
        this.latest_JWT = latest_JWT;
    }
};