package com.example.authmicro.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "app.cors")
public class CORSProperties {
    private String allowedOrigins;
    private boolean allowPrivateNetwork;

    public String getAllowedOrigins() {
        return allowedOrigins;
    }

    public void setAllowedOrigins(String allowedOrigins) {
        this.allowedOrigins = allowedOrigins;
    }

    public boolean isAllowPrivateNetwork() {
        return allowPrivateNetwork;
    }

    public void setAllowPrivateNetwork(boolean allowPrivateNetwork) {
        this.allowPrivateNetwork = allowPrivateNetwork;
    }
}