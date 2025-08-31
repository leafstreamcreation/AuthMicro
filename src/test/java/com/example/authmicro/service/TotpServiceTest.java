package com.example.authmicro.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("TOTP Service Tests")
class TotpServiceTest {

    private TotpService totpService;

    @BeforeEach
    void setUp() {
        totpService = new TotpService();
    }

    @Test
    @DisplayName("Should generate valid base32 secret")
    void shouldGenerateValidBase32Secret() {
        // When
        String secret = totpService.generateSecret();

        // Then
        assertThat(secret).isNotNull();
        assertThat(secret).isNotEmpty();
        assertThat(secret).hasSize(32); // Base32 secret should be 32 characters
        assertThat(secret).matches("[A-Z2-7]+"); // Base32 alphabet
    }

    @Test
    @DisplayName("Should generate different secrets each time")
    void shouldGenerateDifferentSecretsEachTime() {
        // When
        String secret1 = totpService.generateSecret();
        String secret2 = totpService.generateSecret();

        // Then
        assertThat(secret1).isNotEqualTo(secret2);
    }

    @Test
    @DisplayName("Should generate QR code URL in correct format")
    void shouldGenerateQrCodeUrlInCorrectFormat() {
        // Given
        String secret = "TESTSECRET123456789012345678";
        String email = "test@example.com";
        String issuer = "AuthMicro";

        // When
        String qrCodeUrl = totpService.generateQrCodeUrl(secret, email, issuer);

        // Then
        assertThat(qrCodeUrl).startsWith("otpauth://totp/");
        assertThat(qrCodeUrl).contains("AuthMicro:test@example.com");
        assertThat(qrCodeUrl).contains("secret=" + secret);
        assertThat(qrCodeUrl).contains("issuer=" + issuer);
    }

    @Test
    @DisplayName("Should validate TOTP with correct timing window")
    void shouldValidateTotpWithCorrectTimingWindow() {
        // Given
        String secret = "TESTSECRET123456789012345678";
        
        // Generate current TOTP code manually
        try {
            String currentCode = com.j256.twofactorauth.TimeBasedOneTimePasswordUtil
                .generateCurrentNumberString(secret);
            int code = Integer.parseInt(currentCode);

            // When
            boolean isValid = totpService.validateTotp(secret, code);

            // Then
            assertThat(isValid).isTrue();
        } catch (Exception e) {
            fail("Should not throw exception during TOTP validation", e);
        }
    }

    @Test
    @DisplayName("Should reject invalid TOTP code")
    void shouldRejectInvalidTotpCode() {
        // Given
        String secret = "TESTSECRET123456789012345678";
        int invalidCode = 999999; // Obviously wrong code

        // When
        boolean isValid = totpService.validateTotp(secret, invalidCode);

        // Then
        assertThat(isValid).isFalse();
    }

    @Test
    @DisplayName("Should handle invalid secret gracefully")
    void shouldHandleInvalidSecretGracefully() {
        // Given
        String invalidSecret = "INVALID_SECRET";
        int code = 123456;

        // When
        boolean isValid = totpService.validateTotp(invalidSecret, code);

        // Then
        assertThat(isValid).isFalse();
    }

    @Test
    @DisplayName("Should handle null secret gracefully")
    void shouldHandleNullSecretGracefully() {
        // Given
        String nullSecret = null;
        int code = 123456;

        // When & Then
        assertThatThrownBy(() -> totpService.validateTotp(nullSecret, code))
            .isInstanceOf(Exception.class);
    }
}
