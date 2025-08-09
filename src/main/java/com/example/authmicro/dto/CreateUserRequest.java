package com.example.authmicro.dto;

import com.example.authmicro.entity.Role;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

public class CreateUserRequest {
    
    @Email
    @NotBlank
    private String email;
    
    @NotBlank
    @Size(min = 6, max = 100)
    private String password;
    
    private Role role = Role.USER;

    public CreateUserRequest() {}

    public CreateUserRequest(String email, String password, Role role) {
        this.email = email;
        this.password = password;
        this.role = role;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }
}
