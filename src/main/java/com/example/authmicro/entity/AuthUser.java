package com.example.authmicro.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "auth_users")
public class AuthUser {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "user_seq")
    @SequenceGenerator(name = "user_seq", sequenceName = "user_sequence", allocationSize = 1)
    private Long id;

    @Email
    @NotBlank
    @Column(unique = true, nullable = false)
    private String email;

    @Column(name = "totp_secret")
    private String totpSecret;

    @NotNull
    @Enumerated(EnumType.STRING)
    private Role role = Role.USER;

    @NotBlank
    @JsonIgnore
    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @ElementCollection
    @CollectionTable(name = "user_service_credentials", joinColumns = @JoinColumn(name = "user_id"))
    private List<ServiceCredential> serviceCredentials = new ArrayList<>();

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "enabled")
    private boolean enabled = true;

    @Column(name = "last_login")
    private String latest_login;

    public AuthUser() {}

    public AuthUser(String email, String passwordHash, Role role) {
        this.email = email;
        this.passwordHash = passwordHash;
        this.role = role;
        this.latest_login = null;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    // Getters and Setters
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

    public String getTotpSecret() {
        return totpSecret;
    }

    public void setTotpSecret(String totpSecret) {
        this.totpSecret = totpSecret;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public List<ServiceCredential> getServiceCredentials() {
        return serviceCredentials;
    }

    public void setServiceCredentials(List<ServiceCredential> serviceCredentials) {
        this.serviceCredentials = serviceCredentials;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean has2FAEnabled() {
        return totpSecret != null && !totpSecret.isEmpty();
    }

    public String getLatest_Login() {
        return latest_login;
    }

    public void setLatest_Login(String JWT) {
        this.latest_login = JWT;
    }

    @Override
    public String toString() {
        return "AuthUser{" +
                "id=" + id +
                ", email=" + email +
                ", role=" + role +
                ", enabled=" + enabled +
                ", has2FA=" + has2FAEnabled() +
                ", last_login=" + latest_login +
                '}';
    }
}
