package com.example.authmicro.service;

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;
import org.springframework.stereotype.Service;

import java.security.GeneralSecurityException;

@Service
public class TotpService {

    public String generateSecret() {
        return TimeBasedOneTimePasswordUtil.generateBase32Secret();
    }

    public boolean validateTotp(String secret, int code) {
        try {
            String calculatedCode = TimeBasedOneTimePasswordUtil.generateCurrentNumberString(secret);
            return String.format("%06d", code).equals(calculatedCode);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public String generateQrCodeUrl(String secret, String email, String issuer) {
        return String.format(
            "otpauth://totp/%s:%s?secret=%s&issuer=%s",
            issuer, email, secret, issuer
        );
    }
}
