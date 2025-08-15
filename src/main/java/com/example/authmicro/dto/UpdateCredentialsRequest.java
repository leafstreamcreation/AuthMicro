package com.example.authmicro.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.List;

public class UpdateCredentialsRequest {
    
    private List<ServiceCredentialDto> serviceCredentials;

    public UpdateCredentialsRequest() {}

    public UpdateCredentialsRequest(List<ServiceCredentialDto> serviceCredentials) {
        this.serviceCredentials = serviceCredentials;
    }

    public List<ServiceCredentialDto> getServiceCredentials() {
        return serviceCredentials;
    }

    public void setServiceCredentials(List<ServiceCredentialDto> serviceCredentials) {
        this.serviceCredentials = serviceCredentials;
    }

    public static class ServiceCredentialDto {
        @NotBlank
        private String serviceName;
        
        @NotBlank
        private String password;

        public ServiceCredentialDto() {}

        public ServiceCredentialDto(String serviceName, String password) {
            this.serviceName = serviceName;
            this.password = password;
        }

        public String getServiceName() {
            return serviceName;
        }

        public void setServiceName(String serviceName) {
            this.serviceName = serviceName;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }
}
