package com.example.authmicro.controller;

import com.example.authmicro.dto.*;
import com.example.authmicro.entity.AuthUser;
import com.example.authmicro.entity.Role;
import com.example.authmicro.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@ActiveProfiles("test")
@DisplayName("Auth Controller Tests")
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthService authService;

    @Autowired
    private ObjectMapper objectMapper;

    private AuthUser testUser;
    private LoginRequest loginRequest;
    private UserBodyRequest signupRequest;

    @BeforeEach
    void setUp() {
        testUser = new AuthUser();
        testUser.setId(1L);
        testUser.setEmail("test@example.com");
        testUser.setRole(Role.USER);
        testUser.setEnabled(true);

        loginRequest = new LoginRequest("test@example.com", "password123");
        signupRequest = new UserBodyRequest("new@example.com", "password123", Role.USER);
    }

    @Test
    @DisplayName("Health endpoint should return OK status")
    void healthEndpointShouldReturnOkStatus() throws Exception {
        mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.service").value("auth-micro"));
    }

    @Test
    @DisplayName("Login with valid credentials should return JWT token")
    void loginWithValidCredentialsShouldReturnJwtToken() throws Exception {
        // Given
        LoginResponse response = new LoginResponse("jwt-token", 3600L);
        when(authService.login(any(LoginRequest.class))).thenReturn(response);

        // When & Then
        mockMvc.perform(post("/login")
                .with(csrf())
                .header("X-API-Key", "test-api-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.token").value("jwt-token"))
                .andExpect(jsonPath("$.expiresIn").value(3600))
                .andExpect(jsonPath("$.requires2FA").value(false));

        verify(authService).login(any(LoginRequest.class));
    }

    @Test
    @DisplayName("Login requiring 2FA should return appropriate response")
    void loginRequiring2FAShouldReturnAppropriateResponse() throws Exception {
        // Given
        LoginResponse response = new LoginResponse(true, "TOTP verification required");
        when(authService.login(any(LoginRequest.class))).thenReturn(response);

        // When & Then
        mockMvc.perform(post("/login")
                .with(csrf())
                .header("X-API-Key", "test-api-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.requires2FA").value(true))
                .andExpect(jsonPath("$.message").value("TOTP verification required"));

        verify(authService).login(any(LoginRequest.class));
    }

    @Test
    @DisplayName("Login with invalid credentials should return bad request")
    void loginWithInvalidCredentialsShouldReturnBadRequest() throws Exception {
        // Given
        when(authService.login(any(LoginRequest.class)))
                .thenThrow(new RuntimeException("Invalid credentials"));

        // When & Then
        mockMvc.perform(post("/login")
                .with(csrf())
                .header("X-API-Key", "test-api-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isBadRequest());

        verify(authService).login(any(LoginRequest.class));
    }

    @Test
    @DisplayName("Signup with valid data should create user")
    void signupWithValidDataShouldCreateUser() throws Exception {
        // Given
        when(authService.createUser(any(UserBodyRequest.class))).thenReturn(testUser);
        UserResponse userResponse = new UserResponse(1L, "new@example.com", Role.USER, false, true, null);
        when(authService.convertToUserResponse(testUser)).thenReturn(userResponse);

        // When & Then
        mockMvc.perform(post("/signup")
                .with(csrf())
                .header("X-API-Key", "test-api-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.email").value("new@example.com"))
                .andExpect(jsonPath("$.role").value("USER"));

        verify(authService).createUser(any(UserBodyRequest.class));
        verify(authService).convertToUserResponse(testUser);
    }

    @Test
    @DisplayName("Signup with existing email should return bad request")
    void signupWithExistingEmailShouldReturnBadRequest() throws Exception {
        // Given
        when(authService.createUser(any(UserBodyRequest.class)))
                .thenThrow(new RuntimeException("User with this email already exists"));

        // When & Then
        mockMvc.perform(post("/signup")
                .with(csrf())
                .header("X-API-Key", "test-api-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isBadRequest());

        verify(authService).createUser(any(UserBodyRequest.class));
    }

    @Test
    @DisplayName("2FA verification with valid code should return JWT")
    void twoFAVerificationWithValidCodeShouldReturnJWT() throws Exception {
        // Given
        TotpVerificationRequest request = new TotpVerificationRequest(123456, "test@example.com");
        LoginResponse response = new LoginResponse("jwt-token", 3600L);
        when(authService.verifyTotp(eq(request)))
                .thenReturn(response);

        // When & Then
        mockMvc.perform(post("/2fa/verify")
                .with(csrf())
                .header("X-API-Key", "test-api-key")
                .param("email", "test@example.com")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.token").value("jwt-token"))
                .andExpect(jsonPath("$.expiresIn").value(3600));

        verify(authService).verifyTotp(eq(request));
    }

    @Test
    @DisplayName("2FA verification with invalid code should return bad request")
    void twoFAVerificationWithInvalidCodeShouldReturnBadRequest() throws Exception {
        // Given
        TotpVerificationRequest request = new TotpVerificationRequest(999999, "test@example.com");
        when(authService.verifyTotp(eq(request)))
                .thenThrow(new RuntimeException("Invalid TOTP code"));

        // When & Then
        mockMvc.perform(post("/2fa/verify")
                .with(csrf())
                .header("X-API-Key", "test-api-key")
                .param("email", "test@example.com")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());

        verify(authService).verifyTotp(eq(request));
    }

    @Test
    @DisplayName("Enable 2FA should return QR code URL")
    @WithMockUser(roles = "USER")
    void enable2FAShouldReturnQrCodeUrl() throws Exception {
        // Given
        String qrCodeUrl = "otpauth://totp/AuthMicro:test@example.com?secret=SECRET&issuer=AuthMicro";
        when(authService.enable2FA(anyLong())).thenReturn(qrCodeUrl);

        // When & Then
        mockMvc.perform(post("/2fa/enable")
                .with(csrf())
                .header("X-API-Key", "test-api-key")
                .header("Authorization", "Bearer jwt-token"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.qrCodeUrl").value(qrCodeUrl))
                .andExpect(jsonPath("$.message").value("2FA enabled successfully"));

        verify(authService).enable2FA(anyLong());
    }

    @Test
    @DisplayName("Get profile should return user information")
    @WithMockUser(username = "test@example.com", roles = "USER")
    void getProfileShouldReturnUserInformation() throws Exception {
        // Given
        UserResponse userResponse = new UserResponse(1L, "test@example.com", Role.USER, false, true, null);
        when(authService.getUserByEmail("test@example.com")).thenReturn(testUser);
        when(authService.convertToUserResponse(testUser)).thenReturn(userResponse);

        // When & Then
        mockMvc.perform(get("/profile")
                .header("X-API-Key", "test-api-key")
                .header("Authorization", "Bearer jwt-token"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.email").value("test@example.com"))
                .andExpect(jsonPath("$.role").value("USER"));

        verify(authService).getUserByEmail("test@example.com");
        verify(authService).convertToUserResponse(testUser);
    }

    @Test
    @DisplayName("Missing API key should return unauthorized")
    void missingApiKeyShouldReturnUnauthorized() throws Exception {
        mockMvc.perform(post("/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Invalid request body should return bad request")
    void invalidRequestBodyShouldReturnBadRequest() throws Exception {
        // Given - invalid login request (missing email)
        LoginRequest invalidRequest = new LoginRequest();
        invalidRequest.setPassword("password123");

        // When & Then
        mockMvc.perform(post("/login")
                .with(csrf())
                .header("X-API-Key", "test-api-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }
}
