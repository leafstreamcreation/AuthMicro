package com.example.authmicro.security;

import com.example.authmicro.dto.CachedBodyHttpServletRequest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Component
public class ApiKeyAuthenticationFilter implements Filter {

    private final String apiKeySecret;
    private final String apiKeyCipher;
    private final Integer gcmTagLength; // in bits

    public ApiKeyAuthenticationFilter(@Value("${app.api-key.secret}") String apiKeySecret,
                                       @Value("${app.api-key.cipher}") String apiKeyCipher,
                                       @Value("${app.api-key.gcm-tag-length}") Integer gcmTagLength) {
        this.apiKeySecret = apiKeySecret;
        this.apiKeyCipher = apiKeyCipher;
        this.gcmTagLength = gcmTagLength;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        try {

        CachedBodyHttpServletRequest httpRequest = new CachedBodyHttpServletRequest((HttpServletRequest) request);
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String inboundKey = httpRequest.getHeader("X-API-Key");
        byte[] nonceBytes = Arrays.copyOfRange(inboundKey.getBytes(), 0, 12);
        byte[] inboundCipherText = Arrays.copyOfRange(inboundKey.getBytes(), 12, inboundKey.length());

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(apiKeySecret.getBytes(), "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(gcmTagLength, nonceBytes);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
        byte[] decryptedKeyBytes = cipher.doFinal(inboundCipherText);
        String decryptedKeyText = new String(decryptedKeyBytes, StandardCharsets.UTF_8);
        if (inboundKey == null || !apiKeyCipher.equals(decryptedKeyText)) {
            httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write("{\"error\":\"Invalid or missing API key\"}");
            return;
        }
        chain.doFilter(request, response);
        } catch (NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Encryption error: " + e.getMessage() + "\"}");
        }
    }
}

