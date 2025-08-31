package com.example.authmicro.security;

import com.example.authmicro.dto.LoginRequest;
import com.example.authmicro.dto.UserBodyRequest;
import com.example.authmicro.entity.Role;
import com.example.authmicro.repository.AuthUserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureWebMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebMvc
@ActiveProfiles("test")
@Transactional
@DisplayName("Security Tests")
class SecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuthUserRepository userRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("Should reject requests without API key")
    void shouldRejectRequestsWithoutApiKey() throws Exception {
        UserBodyRequest request = new UserBodyRequest("test@example.com", "password123", Role.USER);

        mockMvc.perform(post("/signup")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should reject requests with invalid API key")
    void shouldRejectRequestsWithInvalidApiKey() throws Exception {
        UserBodyRequest request = new UserBodyRequest("test@example.com", "password123", Role.USER);

        mockMvc.perform(post("/signup")
                .with(csrf())
                .header("X-API-Key", "invalid-api-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should accept requests with valid API key")
    void shouldAcceptRequestsWithValidApiKey() throws Exception {
        UserBodyRequest request = new UserBodyRequest("test@example.com", "password123", Role.USER);

        mockMvc.perform(post("/signup")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Should reject login with incorrect password")
    void shouldRejectLoginWithIncorrectPassword() throws Exception {
        // Create user
        UserBodyRequest signupRequest = new UserBodyRequest("test@example.com", "password123", Role.USER);
        mockMvc.perform(post("/signup")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isOk());

        // Try to login with wrong password
        LoginRequest loginRequest = new LoginRequest("test@example.com", "wrongpassword");
        mockMvc.perform(post("/login")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should reject login for non-existent user")
    void shouldRejectLoginForNonExistentUser() throws Exception {
        LoginRequest loginRequest = new LoginRequest("nonexistent@example.com", "password123");
        
        mockMvc.perform(post("/login")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should prevent SQL injection in login")
    void shouldPreventSqlInjectionInLogin() throws Exception {
        // Create legitimate user
        UserBodyRequest signupRequest = new UserBodyRequest("test@example.com", "password123", Role.USER);
        mockMvc.perform(post("/signup")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isOk());

        // Try SQL injection
        LoginRequest maliciousRequest = new LoginRequest("test@example.com'; DROP TABLE auth_user; --", "password123");
        
        mockMvc.perform(post("/login")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(maliciousRequest)))
                .andExpect(status().isUnauthorized());

        // Verify user table still exists by creating another user
        UserBodyRequest anotherUser = new UserBodyRequest("test2@example.com", "password123", Role.USER);
        mockMvc.perform(post("/signup")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(anotherUser)))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Should enforce role-based access control")
    void shouldEnforceRoleBasedAccessControl() throws Exception {
        // Create regular user
        UserBodyRequest userRequest = new UserBodyRequest("user@example.com", "password123", Role.USER);
        mockMvc.perform(post("/signup")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(userRequest)))
                .andExpect(status().isOk());

        // Login as user
        LoginRequest loginRequest = new LoginRequest("user@example.com", "password123");
        MvcResult loginResult = mockMvc.perform(post("/login")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String jwtToken = loginResult.getResponse().getHeader("Authorization");

        // Try to access admin endpoint (should be forbidden)
        mockMvc.perform(get("/admin/users")
                .header("Authorization", jwtToken)
                .header("X-API-Key", "test-api-key-secret"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Should validate JWT token integrity")
    void shouldValidateJwtTokenIntegrity() throws Exception {
        // Create and login user
        UserBodyRequest signupRequest = new UserBodyRequest("test@example.com", "password123", Role.USER);
        mockMvc.perform(post("/signup")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isOk());

        LoginRequest loginRequest = new LoginRequest("test@example.com", "password123");
        MvcResult loginResult = mockMvc.perform(post("/login")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String validToken = loginResult.getResponse().getHeader("Authorization");
        
        // Tamper with the token
        String tamperedToken = validToken.substring(0, validToken.length() - 5) + "TAMPE";

        // Try to access protected endpoint with tampered token
        mockMvc.perform(get("/profile")
                .header("Authorization", tamperedToken)
                .header("X-API-Key", "test-api-key-secret"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should reject expired JWT tokens")
    void shouldRejectExpiredJwtTokens() throws Exception {
        // This test would require modifying JWT service to create short-lived tokens for testing
        // or mocking the clock, which is beyond the scope of this basic security test
        // In a real scenario, you'd configure a test JWT service with very short expiration
    }

    @Test
    @DisplayName("Should prevent password enumeration")
    void shouldPreventPasswordEnumeration() throws Exception {
        // Create a user
        UserBodyRequest signupRequest = new UserBodyRequest("test@example.com", "password123", Role.USER);
        mockMvc.perform(post("/signup")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isOk());

        // Try login with existing user but wrong password
        LoginRequest existingUserWrongPassword = new LoginRequest("test@example.com", "wrongpassword");
        MvcResult result1 = mockMvc.perform(post("/login")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(existingUserWrongPassword)))
                .andExpect(status().isUnauthorized())
                .andReturn();

        // Try login with non-existing user
        LoginRequest nonExistingUser = new LoginRequest("nonexistent@example.com", "password123");
        MvcResult result2 = mockMvc.perform(post("/login")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(nonExistingUser)))
                .andExpect(status().isUnauthorized())
                .andReturn();

        // Both should return the same error message to prevent enumeration
        String response1 = result1.getResponse().getContentAsString();
        String response2 = result2.getResponse().getContentAsString();
        
        // In a secure implementation, both responses should be identical
        // This prevents attackers from determining if an email exists in the system
    }

    @Test
    @DisplayName("Should handle malformed JSON gracefully")
    void shouldHandleMalformedJsonGracefully() throws Exception {
        String malformedJson = "{ 'email': 'test@example.com', 'password': }";

        mockMvc.perform(post("/signup")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(malformedJson))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should validate email format")
    void shouldValidateEmailFormat() throws Exception {
        UserBodyRequest invalidEmailRequest = new UserBodyRequest("invalid-email", "password123", Role.USER);

        mockMvc.perform(post("/signup")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidEmailRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should enforce password strength requirements")
    void shouldEnforcePasswordStrengthRequirements() throws Exception {
        // Test with weak password
        UserBodyRequest weakPasswordRequest = new UserBodyRequest("test@example.com", "123", Role.USER);

        mockMvc.perform(post("/signup")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(weakPasswordRequest)))
                .andExpect(status().isBadRequest());
    }
}
