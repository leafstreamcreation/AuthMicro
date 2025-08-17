package com.example.authmicro.dto;

public class RefreshAuthentication {
    private Long userId;
    private String serviceName;

    public RefreshAuthentication(Long userId, String serviceName) {
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