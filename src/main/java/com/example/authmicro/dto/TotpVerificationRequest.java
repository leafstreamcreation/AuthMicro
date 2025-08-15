package com.example.authmicro.dto;

import jakarta.validation.constraints.NotNull;

public class TotpVerificationRequest {
    
    @NotNull
    private Integer code;

    private String serviceName;

    public TotpVerificationRequest() {}

    public TotpVerificationRequest(Integer code, String serviceName) {
        this.code = code;
        this.serviceName = serviceName;
    }

    public TotpVerificationRequest(Integer code) {
        this.code = code;
    }

    public Integer getCode() {
        return code;
    }

    public String getServiceName() {
        return serviceName;
    }

    public void setCode(Integer code) {
        this.code = code;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }
}
