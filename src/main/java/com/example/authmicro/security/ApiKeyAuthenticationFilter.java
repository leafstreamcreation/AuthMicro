package com.example.authmicro.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.Base64;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class ApiKeyAuthenticationFilter implements Filter {

    private final String apiKeySecret;
    private final String apiDecryptionKey;
    private static final int GCM_TAG_LENGTH = 128;

    public ApiKeyAuthenticationFilter(@Value("${app.api-key.secret}") String apiKeySecret,
                                       @Value("${app.api-key.decryption}") String apiDecryptionKey) {
        this.apiKeySecret = apiKeySecret;
        this.apiDecryptionKey = apiDecryptionKey;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String apiKey = httpRequest.getHeader("X-API-Key");
        
        if (apiKey == null || !apiKeySecret.equals(apiKey)) {
            httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write("{\"error\":\"Invalid or missing API key\"}");
            return;
        }

        chain.doFilter(request, response);
    }
}
