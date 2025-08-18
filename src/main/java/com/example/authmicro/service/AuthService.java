package com.example.authmicro.service;

import com.example.authmicro.dto.*;
import com.example.authmicro.entity.AuthUser;
import com.example.authmicro.entity.Role;
import com.example.authmicro.entity.ServiceCredential;
import com.example.authmicro.repository.AuthUserRepository;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Transactional
public class AuthService {

    private final AuthUserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TotpService totpService;

    @Autowired
    public AuthService(AuthUserRepository userRepository, 
                      JwtService jwtService, 
                      TotpService totpService) {
        this.userRepository = userRepository;
        this.passwordEncoder = new BCryptPasswordEncoder(12);
        this.jwtService = jwtService;
        this.totpService = totpService;
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

    public LoginResponse refreshToken(Long id, String name) {
        AuthUser user = getUserById(id);
        if (!user.isEnabled()) {
            throw new RuntimeException("User is disabled");
        }
        String serviceName = name;
        Boolean isAuthLogin = serviceName == null || serviceName.isEmpty();

        String newToken = isAuthLogin
                ? jwtService.generateToken(user)
                : jwtService.generateToken(user, serviceName);
        return new LoginResponse(newToken, jwtService.getExpirationTime());
    }

    public LoginResponse verifyTotp(String email, TotpVerificationRequest request) {
        String serviceName = request.getServiceName();
        Optional<AuthUser> userOptional = userRepository.findByEmail(email);
        
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
}
