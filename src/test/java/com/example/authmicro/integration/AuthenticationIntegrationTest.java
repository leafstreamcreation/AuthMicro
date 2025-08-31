package com.example.authmicro.integration;

import com.example.authmicro.dto.*;
import com.example.authmicro.entity.AuthUser;
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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebMvc
@Testcontainers
@ActiveProfiles("test")
@Transactional
@DisplayName("Authentication Integration Tests")
class AuthenticationIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("testdb")
            .withUsername("test")
            .withPassword("test");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuthUserRepository userRepository;

    @Autowired
    private ObjectMapper objectMapper;

    private BCryptPasswordEncoder passwordEncoder;
    private AuthUser testUser;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder(4); // Lower strength for tests
        userRepository.deleteAll();

        // Create test user
        testUser = new AuthUser();
        testUser.setEmail("integration@example.com");
        testUser.setPasswordHash(passwordEncoder.encode("password123"));
        testUser.setRole(Role.USER);
        testUser.setEnabled(true);
        testUser = userRepository.save(testUser);
    }

    @Test
    @DisplayName("Full authentication flow should work end-to-end")
    void fullAuthenticationFlowShouldWorkEndToEnd() throws Exception {
        // 1. Health check
        mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));

        // 2. Sign up new user
        UserBodyRequest signupRequest = new UserBodyRequest("newuser@example.com", "newpassword123", Role.USER);
        
        mockMvc.perform(post("/signup")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("newuser@example.com"))
                .andExpect(jsonPath("$.role").value("USER"));

        // 3. Login with new user
        LoginRequest loginRequest = new LoginRequest("newuser@example.com", "newpassword123");
        
        String loginResponseJson = mockMvc.perform(post("/login")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.expiresIn").value(3600))
                .andReturn().getResponse().getContentAsString();

        LoginResponse loginResponse = objectMapper.readValue(loginResponseJson, LoginResponse.class);
        String jwtToken = loginResponse.getToken();

        // 4. Access protected endpoint with JWT
        mockMvc.perform(get("/profile")
                .header("X-API-Key", "test-api-key-secret")
                .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("newuser@example.com"));

        // 5. Enable 2FA
        mockMvc.perform(post("/2fa/enable")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.qrCodeUrl").exists())
                .andExpect(jsonPath("$.message").value("2FA enabled successfully"));

        // Verify user now has 2FA enabled
        AuthUser updatedUser = userRepository.findByEmail("newuser@example.com").orElseThrow();
        assertThat(updatedUser.has2FAEnabled()).isTrue();
        assertThat(updatedUser.getTotpSecret()).isNotNull();
    }

    @Test
    @DisplayName("Login with service credentials should work")
    void loginWithServiceCredentialsShouldWork() throws Exception {
        // First, add service credentials to the test user
        UpdateCredentialsRequest.ServiceCredentialDto serviceDto = 
            new UpdateCredentialsRequest.ServiceCredentialDto("test-service", "service-password");
        UpdateCredentialsRequest credentialsRequest = new UpdateCredentialsRequest();
        credentialsRequest.setServiceCredentials(java.util.Arrays.asList(serviceDto));

        // Login as admin first to get JWT
        LoginRequest adminLogin = new LoginRequest("integration@example.com", "password123");
        String adminLoginResponse = mockMvc.perform(post("/login")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(adminLogin)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        LoginResponse adminResponse = objectMapper.readValue(adminLoginResponse, LoginResponse.class);
        String adminToken = adminResponse.getToken();

        // Update credentials
        mockMvc.perform(put("/users/" + testUser.getId() + "/credentials")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(credentialsRequest)))
                .andExpect(status().isOk());

        // Now login with service credentials
        LoginRequest serviceLogin = new LoginRequest("integration@example.com", "service-password", "test-service");
        
        mockMvc.perform(post("/login")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(serviceLogin)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists());
    }

    @Test
    @DisplayName("Invalid API key should be rejected")
    void invalidApiKeyShouldBeRejected() throws Exception {
        LoginRequest loginRequest = new LoginRequest("integration@example.com", "password123");
        
        mockMvc.perform(post("/login")
                .with(csrf())
                .header("X-API-Key", "invalid-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Missing API key should be rejected")
    void missingApiKeyShouldBeRejected() throws Exception {
        LoginRequest loginRequest = new LoginRequest("integration@example.com", "password123");
        
        mockMvc.perform(post("/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Invalid login credentials should be rejected")
    void invalidLoginCredentialsShouldBeRejected() throws Exception {
        LoginRequest loginRequest = new LoginRequest("integration@example.com", "wrongpassword");
        
        mockMvc.perform(post("/login")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Database transactions should be properly handled")
    void databaseTransactionsShouldBeProperlyHandled() throws Exception {
        long initialUserCount = userRepository.count();
        
        // Attempt to create user with duplicate email (should fail)
        UserBodyRequest duplicateRequest = new UserBodyRequest("integration@example.com", "password123", Role.USER);
        
        mockMvc.perform(post("/signup")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(duplicateRequest)))
                .andExpect(status().isBadRequest());

        // Verify user count hasn't changed
        assertThat(userRepository.count()).isEqualTo(initialUserCount);
    }
}
