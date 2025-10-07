package com.example.authmicro.service;

import com.example.authmicro.dto.*;
import com.example.authmicro.entity.AuthUser;
import com.example.authmicro.entity.Role;
import com.example.authmicro.entity.ServiceCredential;
import com.example.authmicro.repository.AuthUserRepository;


import com.example.authmicro.config.ApiKeyProperties;
import com.example.authmicro.config.EmailProperties;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.UUID;
import java.util.Base64;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;

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
import java.security.SecureRandom;

@Service
@Transactional
public class AuthService {

    private final AuthUserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TotpService totpService;
    private final EmailProperties emailProperties;
    private final ApiKeyProperties apiKeyProperties;

    public AuthService(AuthUserRepository userRepository, 
                      JwtService jwtService, 
                      TotpService totpService,
                      EmailProperties emailProperties,
                      ApiKeyProperties apiKeyProperties) {
        this.userRepository = userRepository;
        this.passwordEncoder = new BCryptPasswordEncoder(12);
        this.jwtService = jwtService;
        this.totpService = totpService;
        this.emailProperties = emailProperties;
        this.apiKeyProperties = apiKeyProperties;
    }

    public LoginResponse login(LoginRequest request) {
        String serviceName = request.getServiceName();
        Boolean isAdminLogin = serviceName.isEmpty() || serviceName == null;

        Optional<AuthUser> userOptional = userRepository.findByEmail(request.getEmail());
        
        if (userOptional.isEmpty() || !userOptional.get().isEnabled()) {
            throw new RuntimeException("Invalid credentials");
        }

        AuthUser user = userOptional.get();

        if (isAdminLogin && !passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new RuntimeException("Invalid auth credentials");
        }
        else if (!isAdminLogin) {
            user.getServiceCredentials()
                    .stream()
                    .filter(cred -> cred.getServiceName().equals(serviceName))
                    .findFirst()
                    .ifPresentOrElse(
                        cred -> {
                            if (!passwordEncoder.matches(request.getPassword(), cred.getPasswordHash())) {
                                throw new RuntimeException("Invalid credentials for service: " + request.getServiceName());
                            }
                        },
                        () -> { throw new RuntimeException("Not registered for service: " + request.getServiceName()); }
                    );
        }

        if (user.has2FAEnabled()) {
            return new LoginResponse(true, "TOTP verification required");
        }
        String token = isAdminLogin
                ? jwtService.generateToken(user)
                : jwtService.generateToken(user, serviceName);
        user.setLatest_Login(token);
        userRepository.save(user);
        return new LoginResponse(token, jwtService.getExpirationTime());
    }

    public LoginResponse refreshToken(Long id, String name, String token) {
        AuthUser user = getUserById(id);
        if (!user.isEnabled()) {
            throw new RuntimeException("User is disabled");
        }
        if (!user.getLatest_Login().equals(token)) {
            throw new RuntimeException("Invalid token");
        }
        String serviceName = name;
        Boolean isAuthLogin = serviceName == null || serviceName.isEmpty();

        String newToken = isAuthLogin
                ? jwtService.generateToken(user)
                : jwtService.generateToken(user, serviceName);
        user.setLatest_Login(newToken);
        userRepository.save(user);
        return new LoginResponse(newToken, jwtService.getExpirationTime());
    }

    public LoginResponse verifyTotp(TotpVerificationRequest request) {
        String serviceName = request.getServiceName();
        Optional<AuthUser> userOptional = userRepository.findByEmail(request.getEmail());

        if (userOptional.isEmpty() || !userOptional.get().isEnabled()) {
            throw new RuntimeException("User not found");
        }

        AuthUser user = userOptional.get();
        
        if (!user.has2FAEnabled()) {
            throw new RuntimeException("2FA not enabled for this user");
        }

        if (!totpService.validateTotp(user.getTotpSecret(), request.getCode())) {
            throw new RuntimeException("Invalid TOTP code");
        }

        String token = serviceName.isEmpty()
                ? jwtService.generateToken(user)
                : jwtService.generateToken(user, serviceName);
        user.setLatest_Login(token);
        userRepository.save(user);
        return new LoginResponse(token, jwtService.getExpirationTime());
    }

    public AuthUser createUser(UserBodyRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("User with this email already exists");
        }
        if (request.getRole() == Role.ADMIN && userRepository.countByRole(Role.ADMIN) >= 1) {
            throw new RuntimeException("Administrator already exists");
        }

        String hashedPassword = passwordEncoder.encode(request.getPassword());
        AuthUser user = new AuthUser(request.getEmail(), hashedPassword, request.getRole());
        
        return userRepository.save(user);
    }

    public AuthUser updateUser(Long id, UserBodyRequest request) {
        AuthUser user = getUserById(id);

        if (request.getEmail() != null && !request.getEmail().isEmpty()) {
            if (!user.getEmail().equals(request.getEmail()) && userRepository.existsByEmail(request.getEmail())) {
                throw new RuntimeException("Email already in use");
            }
            user.setEmail(request.getEmail());
        }

        if (request.getRole() != null) {
            user.setRole(request.getRole());
        }

        if (request.getPassword() != null && !request.getPassword().isEmpty()) {
            user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        }

        return userRepository.save(user);
    }

    public List<AuthUser> getAllUsers() {
        return userRepository.findAll();
    }

    public AuthUser getUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    public AuthUser getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    public AuthUser updateUserCredentials(Long id, UpdateCredentialsRequest request) {
        AuthUser user = getUserById(id);
        if (user.getRole() == Role.USER) {
            List<ServiceCredential> credentials = request.getServiceCredentials().stream()
                    .map(dto -> new ServiceCredential(
                            dto.getServiceName(),
                            passwordEncoder.encode(dto.getPassword())
                    ))
                    .collect(Collectors.toList());
            
            user.setServiceCredentials(credentials);
            return userRepository.save(user);
        }
        return user;
    }

    public String enable2FA(Long userId) {
        AuthUser user = getUserById(userId);
        
        if (user.has2FAEnabled()) {
            throw new RuntimeException("2FA is already enabled for this user");
        }

        String secret = totpService.generateSecret();
        user.setTotpSecret(secret);
        userRepository.save(user);
        
        return totpService.generateQrCodeUrl(secret, user.getEmail(), "AuthMicro");
    }

    public void disable2FA(Long userId) {
        AuthUser user = getUserById(userId);
        
        if (!user.has2FAEnabled()) {
            throw new RuntimeException("2FA is not enabled for this user");
        }

        user.setTotpSecret(null);
        userRepository.save(user);
    }

    public void toggleUserEnabled(Long userId) {
        AuthUser user = getUserById(userId);
        user.setEnabled(!user.isEnabled());
        userRepository.save(user);
    }

    public void recoverUserAccount(String email) {
        AuthUser user = getUserByEmail(email);
        
        if (!user.isEnabled()) {
            throw new RuntimeException("User account is disabled");
        }
        
        String XAPIKey = createXAPIKey();
        String token = UUID.randomUUID().toString();
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create("${RECOVERY_URL:http://localhost:8080/recover}"))
        .header("Content-Type", "application/json")
        .header("X-API-Key", XAPIKey)
        .POST(HttpRequest.BodyPublishers.ofString(
            String.format("""
                {
                    "destination":"%s", 
                    "senderEmail":"%s", 
                    "replyTo":"%s", 
                    "subject":"Recover your account", 
                    "text":"Please navigate to the recovery page and provide your email and code %d to recover your account", 
                    "html":"Please navigate to the recovery page and provide your email and code %4$d to recover your account"
                }
                """, email, emailProperties.getFrom(), emailProperties.getReplyTo(), token)))
            .build();
            
            client.sendAsync(request, HttpResponse.BodyHandlers.ofString())
            .thenAccept(response -> {
                if (response.statusCode() != 200) {
                    throw new RuntimeException("Failed to send recovery email: " + response.body());
                } else {
                        user.setRecoveryToken(token);
                        userRepository.save(user);
                    }
                });
    }

    public LoginResponse confirmUserRecovery(String email, String recoveryToken, String newPassword) {
        AuthUser user = getUserByEmail(email);
        
        if (!user.isEnabled()) {
            throw new RuntimeException("User account is disabled");
        }
        if (user.getRecoveryToken() == null || !user.getRecoveryToken().equals(recoveryToken)) {
            throw new RuntimeException("Invalid recovery token");
        }

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setRecoveryToken(null);
        String token = jwtService.generateToken(user);
        user.setLatest_Login(token);
        userRepository.save(user);
        
        return new LoginResponse(token, jwtService.getExpirationTime());
    }

    public UserResponse convertToUserResponse(AuthUser user) {
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getRole(),
                user.has2FAEnabled(),
                user.isEnabled(),
                user.getServiceCredentials()
        );
    }

    private String createXAPIKey() {
        //create nonce
        byte[] nonce = new byte[apiKeyProperties.getNonceLength()];
        new SecureRandom().nextBytes(nonce);

        //create salt
        byte[] salt = new byte[apiKeyProperties.getSaltLength()];
        new SecureRandom().nextBytes(salt);

        try {
        //create pbkdf2 key from apiKeySecret, salt and iterationCount
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec keySpec = new PBEKeySpec(apiKeyProperties.getSecret().toCharArray(), salt, apiKeyProperties.getIterationCount(), 256);
        SecretKey pbkdf2Key = keyFactory.generateSecret(keySpec);

        //generate AES key from pbkdf2 key
        SecretKeySpec secretKeySpec = new SecretKeySpec(pbkdf2Key.getEncoded(), "AES");
        //generate GCMParameterSpec from nonce
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(apiKeyProperties.getGcmTagLength(), nonce);

        //generate cipher from AES key and GCMParameterSpec
        Cipher cipher = Cipher.getInstance("AES_256/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

        //combine cipher, nonce, and salt and return base64 encoded string

        byte[] cipherText = cipher.doFinal(apiKeyProperties.getCipher().getBytes());
        byte[] fullKey = new byte[cipherText.length + nonce.length + salt.length];
        System.arraycopy(cipherText, 0, fullKey, 0, cipherText.length);
        System.arraycopy(nonce, 0, fullKey, cipherText.length, nonce.length);
        System.arraycopy(salt, 0, fullKey, cipherText.length + nonce.length, salt.length);
        return Base64.getEncoder().encodeToString(fullKey);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
        throw new RuntimeException("Failed to create API key", e);
    }
    }
}
