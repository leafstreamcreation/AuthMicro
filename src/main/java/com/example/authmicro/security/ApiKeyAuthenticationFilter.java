package com.example.authmicro.security;

import com.example.authmicro.config.ApiKeyProperties;

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
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Component
public class ApiKeyAuthenticationFilter implements Filter {

    private String apiKeySecret;
    private String apiKeyCipher;
    private Integer gcmTagLength; // in bits
    private Integer saltLength; // in bytes
    private Integer nonceLength; // in bytes
    private Integer iterationCount; // PBKDF2 iteration count
    
    public ApiKeyAuthenticationFilter(ApiKeyProperties apiKeyProperties) {
        this.apiKeySecret = apiKeyProperties.getSecret();
        this.apiKeyCipher = apiKeyProperties.getCipher();
        this.gcmTagLength = apiKeyProperties.getGcmTagLength();
        this.saltLength = apiKeyProperties.getSaltLength();
        this.nonceLength = apiKeyProperties.getNonceLength();
        this.iterationCount = apiKeyProperties.getIterationCount();
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        try {

        HttpServletResponse httpResponse = (HttpServletResponse) response;
        HttpServletRequest httpRequest = (HttpServletRequest) request;

        String base64KeyString = httpRequest.getHeader("X-API-Key");
        if (base64KeyString == null) {
            httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write("{\"error\":\"Invalid or missing API key\"}");
            return;
        }
        byte[] inboundKey = Base64.getDecoder().decode(base64KeyString);
        if (inboundKey.length <= saltLength + nonceLength) {
            httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write("{\"error\":\"Invalid or missing API key\"}");
            return;
        }
        int saltByteStart = inboundKey.length - saltLength;
        int nonceByteStart = saltByteStart - nonceLength;

        byte[] inboundCipherText = Arrays.copyOfRange(inboundKey, 0, nonceByteStart);
        byte[] nonceBytes = Arrays.copyOfRange(inboundKey, nonceByteStart, saltByteStart);
        byte[] saltBytes = Arrays.copyOfRange(inboundKey, saltByteStart, inboundKey.length);

        Cipher cipher = Cipher.getInstance("AES_256/GCM/NoPadding");
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // Derive key using PBKDF2
        PBEKeySpec keySpec = new PBEKeySpec(apiKeySecret.toCharArray(), saltBytes, iterationCount, 256);
        SecretKey key =  keyFactory.generateSecret(keySpec);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(gcmTagLength, nonceBytes);

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
        byte[] decryptedKeyBytes = cipher.doFinal(inboundCipherText);
        String decryptedKeyText = new String(decryptedKeyBytes, StandardCharsets.UTF_8);
        if (!apiKeyCipher.equals(decryptedKeyText)) {
            httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write("{\"error\":\"Invalid or missing API key\"}");
            return;
        }
        chain.doFilter(request, response);
        } catch ( InvalidKeySpecException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Encryption error: " + e.getMessage() + "\"}");
        }
    }
}

