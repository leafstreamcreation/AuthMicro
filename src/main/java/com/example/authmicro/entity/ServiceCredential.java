package com.example.authmicro.entity;

import javax.persistence.Embeddable;
import javax.persistence.Column;
import javax.validation.constraints.NotBlank;

@Embeddable
public class ServiceCredential {

    @NotBlank
    @Column(name = "service_name", nullable = false)
    private String serviceName;

    @NotBlank
    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    public ServiceCredential() {}

    public ServiceCredential(String serviceName, String passwordHash) {
        this.serviceName = serviceName;
        this.passwordHash = passwordHash;
    }

    public String getServiceName() {
        return serviceName;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ServiceCredential that = (ServiceCredential) o;

        if (!serviceName.equals(that.serviceName)) return false;
        return passwordHash.equals(that.passwordHash);
    }

    @Override
    public int hashCode() {
        int result = serviceName.hashCode();
        result = 31 * result + passwordHash.hashCode();
        return result;
    }

    @Override
    public String toString() {
        return "ServiceCredential{" +
                "serviceName='" + serviceName + '\'' +
                ", passwordHash='[REDACTED]'" +
                '}';
    }
}
