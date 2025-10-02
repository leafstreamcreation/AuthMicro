package com.example.authmicro.dto;

import jakarta.validation.constraints.NotNull;

public class TotpVerificationRequest {
    
    @NotNull
    private Integer code;

    @NotNull
    private String email;

    private String serviceName;

    public TotpVerificationRequest() {}

    public TotpVerificationRequest(Integer code, String email, String serviceName) {
        this.code = code;
        this.email = email;
        this.serviceName = serviceName;
    }

    public TotpVerificationRequest(Integer code, String email) {
        this.code = code;
        this.email = email;
    }

    public Integer getCode() {
        return code;
    }

    public String getEmail() {
        return email;
    }

    public String getServiceName() {
        return serviceName;
    }

    public void setCode(Integer code) {
        this.code = code;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }
}
