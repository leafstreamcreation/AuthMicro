package com.example.authmicro.service;

import com.example.authmicro.dto.*;
import com.example.authmicro.entity.AuthUser;
import com.example.authmicro.entity.Role;
import com.example.authmicro.repository.AuthUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Auth Service Tests")
class AuthServiceTest {

    @Mock
    private AuthUserRepository userRepository;

    @Mock
    private JwtService jwtService;

    @Mock
    private TotpService totpService;

    @InjectMocks
    private AuthService authService;

    private AuthUser testUser;
    private BCryptPasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder(4); // Use lower strength for tests
        
        testUser = new AuthUser();
        ReflectionTestUtils.setField(testUser, "id", 1L);
        testUser.setEmail("test@example.com");
        testUser.setPasswordHash(passwordEncoder.encode("password123"));
        testUser.setRole(Role.USER);
        testUser.setEnabled(true);

        // Inject the password encoder into the service
        ReflectionTestUtils.setField(authService, "passwordEncoder", passwordEncoder);
    }

    @Test
    @DisplayName("Should successfully login with valid credentials")
    void shouldSuccessfullyLoginWithValidCredentials() {
        // Given
        LoginRequest request = new LoginRequest("test@example.com", "password123");
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(jwtService.generateToken(testUser)).thenReturn("jwt-token");
        when(jwtService.getExpirationTime()).thenReturn(3600L);
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        LoginResponse response = authService.login(request);

        // Then
        assertThat(response.getToken()).isEqualTo("jwt-token");
        assertThat(response.getExpiresIn()).isEqualTo(3600L);
        assertThat(response.isRequires2FA()).isFalse();
        
        verify(userRepository).findByEmail("test@example.com");
        verify(jwtService).generateToken(testUser);
        verify(userRepository).save(testUser);
    }

    @Test
    @DisplayName("Should require 2FA when user has TOTP enabled")
    void shouldRequire2FAWhenUserHasTotpEnabled() {
        // Given
        testUser.setTotpSecret("TESTSECRET123456");
        LoginRequest request = new LoginRequest("test@example.com", "password123");
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));

        // When
        LoginResponse response = authService.login(request);

        // Then
        assertThat(response.isRequires2FA()).isTrue();
        assertThat(response.getMessage()).isEqualTo("TOTP verification required");
        assertThat(response.getToken()).isNull();
        
        verify(userRepository).findByEmail("test@example.com");
        verifyNoInteractions(jwtService);
    }

    @Test
    @DisplayName("Should throw exception for invalid credentials")
    void shouldThrowExceptionForInvalidCredentials() {
        // Given
        LoginRequest request = new LoginRequest("test@example.com", "wrongpassword");
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));

        // When & Then
        assertThatThrownBy(() -> authService.login(request))
            .isInstanceOf(RuntimeException.class)
            .hasMessage("Invalid auth credentials");
    }

    @Test
    @DisplayName("Should throw exception for non-existent user")
    void shouldThrowExceptionForNonExistentUser() {
        // Given
        LoginRequest request = new LoginRequest("nonexistent@example.com", "password123");
        when(userRepository.findByEmail("nonexistent@example.com")).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> authService.login(request))
            .isInstanceOf(RuntimeException.class)
            .hasMessage("Invalid credentials");
    }

    @Test
    @DisplayName("Should throw exception for disabled user")
    void shouldThrowExceptionForDisabledUser() {
        // Given
        testUser.setEnabled(false);
        LoginRequest request = new LoginRequest("test@example.com", "password123");
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));

        // When & Then
        assertThatThrownBy(() -> authService.login(request))
            .isInstanceOf(RuntimeException.class)
            .hasMessage("Invalid credentials");
    }

    @Test
    @DisplayName("Should successfully verify TOTP")
    void shouldSuccessfullyVerifyTotp() {
        // Given
        testUser.setTotpSecret("TESTSECRET123456");
        TotpVerificationRequest request = new TotpVerificationRequest(123456, "test@example.com");
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(totpService.validateTotp("TESTSECRET123456", 123456)).thenReturn(true);
        when(jwtService.generateToken(testUser)).thenReturn("jwt-token");
        when(jwtService.getExpirationTime()).thenReturn(3600L);
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        LoginResponse response = authService.verifyTotp(request);

        // Then
        assertThat(response.getToken()).isEqualTo("jwt-token");
        assertThat(response.getExpiresIn()).isEqualTo(3600L);
        
        verify(totpService).validateTotp("TESTSECRET123456", 123456);
        verify(jwtService).generateToken(testUser);
        verify(userRepository).save(testUser);
    }

    @Test
    @DisplayName("Should throw exception for invalid TOTP code")
    void shouldThrowExceptionForInvalidTotpCode() {
        // Given
        testUser.setTotpSecret("TESTSECRET123456");
        TotpVerificationRequest request = new TotpVerificationRequest(999999, "test@example.com");
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(totpService.validateTotp("TESTSECRET123456", 999999)).thenReturn(false);

        // When & Then
        assertThatThrownBy(() -> authService.verifyTotp(request))
            .isInstanceOf(RuntimeException.class)
            .hasMessage("Invalid TOTP code");
    }

    @Test
    @DisplayName("Should create new user successfully")
    void shouldCreateNewUserSuccessfully() {
        // Given
        UserBodyRequest request = new UserBodyRequest("new@example.com", "password123", Role.USER);
        when(userRepository.existsByEmail("new@example.com")).thenReturn(false);
        when(userRepository.countByRole(Role.ADMIN)).thenReturn(0L);
        when(userRepository.save(any(AuthUser.class))).thenAnswer(invocation -> {
            AuthUser user = invocation.getArgument(0);
            ReflectionTestUtils.setField(user, "id", 2L);
            return user;
        });

        // When
        AuthUser createdUser = authService.createUser(request);

        // Then
        assertThat(createdUser.getEmail()).isEqualTo("new@example.com");
        assertThat(createdUser.getRole()).isEqualTo(Role.USER);
        assertThat(passwordEncoder.matches("password123", createdUser.getPasswordHash())).isTrue();
        
        verify(userRepository).existsByEmail("new@example.com");
        verify(userRepository).save(any(AuthUser.class));
    }

    @Test
    @DisplayName("Should throw exception when creating user with existing email")
    void shouldThrowExceptionWhenCreatingUserWithExistingEmail() {
        // Given
        UserBodyRequest request = new UserBodyRequest("test@example.com", "password123", Role.USER);
        when(userRepository.existsByEmail("test@example.com")).thenReturn(true);

        // When & Then
        assertThatThrownBy(() -> authService.createUser(request))
            .isInstanceOf(RuntimeException.class)
            .hasMessage("User with this email already exists");
    }

    @Test
    @DisplayName("Should get all users")
    void shouldGetAllUsers() {
        // Given
        AuthUser user2 = new AuthUser();
        user2.setEmail("user2@example.com");
        user2.setRole(Role.ADMIN);
        
        List<AuthUser> users = Arrays.asList(testUser, user2);
        when(userRepository.findAll()).thenReturn(users);

        // When
        List<AuthUser> result = authService.getAllUsers();

        // Then
        assertThat(result).hasSize(2);
        assertThat(result).containsExactly(testUser, user2);
        
        verify(userRepository).findAll();
    }

    @Test
    @DisplayName("Should get user by ID")
    void shouldGetUserById() {
        // Given
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));

        // When
        AuthUser result = authService.getUserById(1L);

        // Then
        assertThat(result).isEqualTo(testUser);
        
        verify(userRepository).findById(1L);
    }

    @Test
    @DisplayName("Should throw exception when user not found by ID")
    void shouldThrowExceptionWhenUserNotFoundById() {
        // Given
        when(userRepository.findById(999L)).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> authService.getUserById(999L))
            .isInstanceOf(RuntimeException.class)
            .hasMessage("User not found");
    }

    @Test
    @DisplayName("Should update user successfully")
    void shouldUpdateUserSuccessfully() {
        // Given
        UserBodyRequest request = new UserBodyRequest();
        request.setRole(Role.ADMIN);
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        AuthUser result = authService.updateUser(1L, request);

        // Then
        assertThat(result.getRole()).isEqualTo(Role.ADMIN);
        
        verify(userRepository).findById(1L);
        verify(userRepository).save(testUser);
    }

    @Test
    @DisplayName("Should enable 2FA for user")
    void shouldEnable2FAForUser() {
        // Given
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        when(totpService.generateSecret()).thenReturn("NEWSECRET123456");
        when(totpService.generateQrCodeUrl("NEWSECRET123456", "test@example.com", "AuthMicro"))
            .thenReturn("otpauth://totp/AuthMicro:test@example.com?secret=NEWSECRET123456&issuer=AuthMicro");
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        String qrCodeUrl = authService.enable2FA(1L);

        // Then
        assertThat(qrCodeUrl).contains("otpauth://totp/AuthMicro:test@example.com");
        assertThat(testUser.getTotpSecret()).isEqualTo("NEWSECRET123456");
        
        verify(totpService).generateSecret();
        verify(totpService).generateQrCodeUrl("NEWSECRET123456", "test@example.com", "AuthMicro");
        verify(userRepository).save(testUser);
    }

    @Test
    @DisplayName("Should throw exception when enabling 2FA for user who already has it")
    void shouldThrowExceptionWhenEnabling2FAForUserWhoAlreadyHasIt() {
        // Given
        testUser.setTotpSecret("EXISTINGSECRET123");
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));

        // When & Then
        assertThatThrownBy(() -> authService.enable2FA(1L))
            .isInstanceOf(RuntimeException.class)
            .hasMessage("2FA is already enabled for this user");
    }

    @Test
    @DisplayName("Should convert AuthUser to UserResponse")
    void shouldConvertAuthUserToUserResponse() {
        // Given
        testUser.setTotpSecret("SECRET123");

        // When
        UserResponse response = authService.convertToUserResponse(testUser);

        // Then
        assertThat(response.getId()).isEqualTo(1L);
        assertThat(response.getEmail()).isEqualTo("test@example.com");
        assertThat(response.getRole()).isEqualTo(Role.USER);
        assertThat(response.isHas2FA()).isTrue();
        assertThat(response.isEnabled()).isTrue();
    }

    @Test
    @DisplayName("Should update user credentials")
    void shouldUpdateUserCredentials() {
        // Given
        UpdateCredentialsRequest.ServiceCredentialDto dto = new UpdateCredentialsRequest.ServiceCredentialDto();
        dto.setServiceName("test-service");
        dto.setPassword("service-password");
        
        UpdateCredentialsRequest request = new UpdateCredentialsRequest();
        request.setServiceCredentials(Arrays.asList(dto));
        
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        AuthUser result = authService.updateUserCredentials(1L, request);

        // Then
        assertThat(result.getServiceCredentials()).hasSize(1);
        assertThat(result.getServiceCredentials().get(0).getServiceName()).isEqualTo("test-service");
        assertThat(passwordEncoder.matches("service-password", 
            result.getServiceCredentials().get(0).getPasswordHash())).isTrue();
        
        verify(userRepository).findById(1L);
        verify(userRepository).save(testUser);
    }
}
