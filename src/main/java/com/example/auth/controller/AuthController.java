package com.example.auth.controller;

import com.example.auth.dto.ClientProofRequest;
import com.example.auth.dto.ClientProofResponse;
import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.service.AuthService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Controller REST pour l'authentification.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public Map<String, Object> register(@RequestBody RegisterRequest request) {
        return authService.register(request);
    }

    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @PostMapping("/client-proof")
    public ClientProofResponse clientProof(@RequestBody ClientProofRequest request) {
        return authService.verifyClientProof(request);
    }

    @GetMapping("/me")
    public Map<String, Object> me(@RequestHeader("Authorization") String authHeader) {
        return authService.getProfile(authHeader);
    }

    @PostMapping("/logout")
    public Map<String, Object> logout(@RequestHeader("Authorization") String authHeader) {
        return authService.logout(authHeader);
    }
}