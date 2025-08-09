package com.example.authmicro.dto;

import javax.validation.constraints.NotNull;

public class TotpVerificationRequest {
    
    @NotNull
    private Integer code;

    public TotpVerificationRequest() {}

    public TotpVerificationRequest(Integer code) {
        this.code = code;
    }

    public Integer getCode() {
        return code;
    }

    public void setCode(Integer code) {
        this.code = code;
    }
}
