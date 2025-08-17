package com.example.authmicro.dto;

public class AuthenticationDetails {
    private Long userId;
    private String serviceName;

    public AuthenticationDetails(Long userId, String serviceName) {
        this.userId = userId;
        this.serviceName = serviceName;
    }

    public Long getUserId() {
        return userId;
    }

    public String getServiceName() {
        return serviceName;
    }
    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }
};