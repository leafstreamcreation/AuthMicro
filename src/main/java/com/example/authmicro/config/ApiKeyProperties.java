package com.example.authmicro.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "app.api-key")
public class ApiKeyProperties {
    private String secret;
    private String cipher;
    private int gcmTagLength = 128;
    private int saltLength = 16;
    private int nonceLength = 12;
    private int iterationCount = 10000;

    // Getters and Setters
    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getCipher() {
        return cipher;
    }

    public void setCipher(String cipher) {
        this.cipher = cipher;
    }

    public int getGcmTagLength() {
        return gcmTagLength;
    }

    public void setGcmTagLength(int gcmTagLength) {
        this.gcmTagLength = gcmTagLength;
    }

    public int getSaltLength() {
        return saltLength;
    }

    public void setSaltLength(int saltLength) {
        this.saltLength = saltLength;
    }

    public int getNonceLength() {
        return nonceLength;
    }

    public void setNonceLength(int nonceLength) {
        this.nonceLength = nonceLength;
    }

    public int getIterationCount() {
        return iterationCount;
    }

    public void setIterationCount(int iterationCount) {
        this.iterationCount = iterationCount;
    }
}
