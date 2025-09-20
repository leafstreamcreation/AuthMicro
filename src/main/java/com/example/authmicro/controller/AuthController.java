package com.example.authmicro.controller;

import com.example.authmicro.dto.*;
import com.example.authmicro.entity.AuthUser;
import com.example.authmicro.service.AuthService;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping
public class AuthController {

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        Map<String, String> status = new HashMap<>();
        status.put("status", "UP");
        status.put("service", "auth-micro");
        return ResponseEntity.ok(status);
    }

    @PostMapping("/login")
    public ResponseEntity<Response> login(@Valid @RequestBody LoginRequest request) {
        try {
            LoginResponse response = authService.login(request);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<Response> refresh(Authentication authentication) {
        
        try {
            Long userId = ((AuthenticationDetails) authentication.getDetails()).getUserId();
            String serviceName = ((AuthenticationDetails) authentication.getDetails()).getServiceName();
            String token = ((AuthenticationDetails) authentication.getDetails()).getToken();
            LoginResponse response = authService.refreshToken(userId, serviceName, token);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<Response> signup(@Valid @RequestBody UserBodyRequest request) {
        try {
            AuthUser user = authService.createUser(request);
            UserResponse response = authService.convertToUserResponse(user);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
        }
    }

    @PostMapping("/2fa/verify")
    public ResponseEntity<Response> verify2FA(@Valid @RequestBody TotpVerificationRequest request,
                                                  @RequestParam String email) {
        try {
            LoginResponse response = authService.verifyTotp(email, request);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
        }
    }

    @PostMapping("/2fa/enable")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> enable2FA(Authentication authentication) {
        try {
            Long userId = ( (AuthenticationDetails) authentication.getDetails()).getUserId();
            String qrCodeUrl = authService.enable2FA(userId);
            
            Map<String, String> response = new HashMap<>();
            response.put("qrCodeUrl", qrCodeUrl);
            response.put("message", "2FA enabled successfully");
            
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @PostMapping("/2fa/disable")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> disable2FA(Authentication authentication) {
        try {
            Long userId = ((AuthenticationDetails) authentication.getDetails()).getUserId();
            authService.disable2FA(userId);
            Map<String, String> response = new HashMap<>();
            response.put("message", "2FA disabled successfully");
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @PostMapping("/profile")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<Response> getProfile(Authentication authentication) {
        try {
            String email = authentication.getName();
            AuthUser user = authService.getUserByEmail(email);
            UserResponse response = authService.convertToUserResponse(user);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping("/profile/update")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<Response> updateProfile(@Valid @RequestBody UserBodyRequest request,
                                                  Authentication authentication) {
        try {
            Long userId = ((AuthenticationDetails) authentication.getDetails()).getUserId();
            AuthUser updated = authService.updateUser(userId, request);
            UserResponse response = authService.convertToUserResponse(updated);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
        }
    }

    @PostMapping("/credentials")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<Response> updateCredentials(@Valid @RequestBody UpdateCredentialsRequest request,
                                                      Authentication authentication) {
        try {
            Long userId = ((AuthenticationDetails) authentication.getDetails()).getUserId();
            AuthUser updated = authService.updateUserCredentials(userId, request);
            UserResponse response = authService.convertToUserResponse(updated);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
        }
    }

    @PostMapping("/recover")
    public ResponseEntity<Map<String, String>> recoverAccount(@Valid @RequestBody UserBodyRequest request) {
        try {
            authService.recoverUserAccount(request.getEmail());

            Map<String, String> response = new HashMap<>();
            response.put("message", "Recovery email sent");
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @PostMapping("/recover/confirm")
    public ResponseEntity<Map<String, String>> confirmRecovery(@Valid @RequestBody RecoveryRequest request) {
        try {
            authService.confirmUserRecovery(request.getEmail(), request.getToken(), request.getNewPassword());

            Map<String, String> response = new HashMap<>();
            response.put("message", "Password updated successfully");
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

}
