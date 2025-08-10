package com.example.authmicro.dto;

import com.example.authmicro.entity.Role;

public class UserResponse {
    
    private Long id;
    private String email;
    private Role role;
    private boolean has2FA;
    private boolean enabled;
    private String message;

    public UserResponse() {}

    public UserResponse(Long id, String email, Role role, boolean has2FA, boolean enabled) {
        this.id = id;
        this.email = email;
        this.role = role;
        this.has2FA = has2FA;
        this.enabled = enabled;
    }

    public UserResponse(String message) {
        this.message = message;
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
}
