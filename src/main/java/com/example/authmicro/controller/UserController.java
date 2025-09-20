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
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/users")
public class UserController {

    private final AuthService authService;

    @Autowired
    public UserController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/create")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Response> createUser(@Valid @RequestBody UserBodyRequest request) {
        try {
            AuthUser user = authService.createUser(request);
            UserResponse response = authService.convertToUserResponse(user);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
        }
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<Response>> getAllUsers() {
        try {
            List<AuthUser> users = authService.getAllUsers();
            List<Response> responses = users.stream()
                    .map(authService::convertToUserResponse)
                    .collect(Collectors.toList());
            return ResponseEntity.ok(responses);
        } catch (RuntimeException e) {
            List<Response> errorResponse = new ArrayList<>();
            errorResponse.add(new ErrorResponse(e.getMessage()));
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    @PostMapping("/{id}/profile")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Response> updateUserProfile(@PathVariable Long id, @RequestBody UserBodyRequest request) {
        try {
            AuthUser user = authService.updateUser(id, request);
            UserResponse response = authService.convertToUserResponse(user);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
        }
    }

    @PostMapping("/{id}/credentials")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> updateCredentials(@PathVariable Long id,
                                                                @Valid @RequestBody UpdateCredentialsRequest request,
                                                                Authentication authentication) {
        try {
            authService.updateUserCredentials(id, request);
            
            Map<String, String> response = new HashMap<>();
            response.put("message", "Credentials updated successfully");
            
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @PostMapping("/{id}/2fa/enable")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> enable2FAForUser(@PathVariable Long id,
                                                               Authentication authentication) {
        try {
            String qrCodeUrl = authService.enable2FA(id);
            
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

    @PostMapping("/{id}/2fa/disable")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> disable2FAForUser(@PathVariable Long id,
                                                                Authentication authentication) {
        try {
            authService.disable2FA(id);
            Map<String, String> response = new HashMap<>();
            response.put("message", "2FA disabled successfully");
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @PostMapping("/{id}/enabled")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> toggleUserEnabled(@PathVariable Long id) {
        try {
            authService.toggleUserEnabled(id);
            Map<String, String> response = new HashMap<>();
            response.put("message", "User enabled status updated successfully");
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

}
