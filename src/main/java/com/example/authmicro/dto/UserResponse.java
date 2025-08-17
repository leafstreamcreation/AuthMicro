package com.example.authmicro.dto;

import com.example.authmicro.entity.Role;
import com.example.authmicro.entity.ServiceCredential;

import java.util.List;


public class UserResponse extends Response {
    
    private Long id;
    private String email;
    private Role role;
    private boolean has2FA;
    private boolean enabled;
    private List<ServiceCredential> serviceCredentials;

    public UserResponse() {}

    public UserResponse(Long id, String email, Role role, boolean has2FA, boolean enabled, List<ServiceCredential> serviceCredentials) {
        this.id = id;
        this.email = email;
        this.role = role;
        this.has2FA = has2FA;
        this.enabled = enabled;
        this.serviceCredentials = serviceCredentials;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public boolean isHas2FA() {
        return has2FA;
    }

    public void setHas2FA(boolean has2FA) {
        this.has2FA = has2FA;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    public List<ServiceCredential> getServiceCredentials() {
        return serviceCredentials;
    }
    public void setServiceCredentials(List<ServiceCredential> serviceCredentials) {
        this.serviceCredentials = serviceCredentials;
    }
}
