package com.example.auth.controller;

import com.example.auth.dto.ClientProofRequest;
import com.example.auth.dto.ClientProofResponse;
import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.service.AuthService;
import com.example.auth.service.ClientProofService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests unitaires de AuthController.
 *
 * @author Poun
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
public class AuthControllerTest {

    @Mock
    private AuthService authService;

    @Mock
    private ClientProofService clientProofService;

    @InjectMocks
    private AuthController authController;

    @Test
    void testRegister() {
        RegisterRequest request = new RegisterRequest();
        Map<String, Object> expected = new HashMap<>();
        expected.put("message", "Inscription réussie");

        when(authService.register(request)).thenReturn(expected);

        Map<String, Object> result = authController.register(request);

        assertEquals(expected, result);
        verify(authService).register(request);
    }

    @Test
    void testLogin() {
        LoginRequest request = new LoginRequest();
        Map<String, Object> expected = new HashMap<>();
        expected.put("message", "Connexion réussie");

        when(authService.login(request)).thenReturn(expected);

        Map<String, Object> result = authController.login(request);

        assertEquals(expected, result);
        verify(authService).login(request);
    }

    @Test
    void testBuildClientProof() {
        ClientProofRequest request = new ClientProofRequest();
        ClientProofResponse response = new ClientProofResponse();
        response.setEmail("test@mail.com");

        when(clientProofService.buildProof(request)).thenReturn(response);

        ClientProofResponse result = authController.buildClientProof(request);

        assertEquals("test@mail.com", result.getEmail());
        verify(clientProofService).buildProof(request);
    }

    @Test
    void testMe() {
        Map<String, Object> expected = new HashMap<>();
        expected.put("email", "test@mail.com");

        when(authService.getMe("Bearer token123")).thenReturn(expected);

        Map<String, Object> result = authController.me("Bearer token123");

        assertEquals(expected, result);
        verify(authService).getMe("Bearer token123");
    }

    @Test
    void testLogout() {
        Map<String, Object> expected = new HashMap<>();
        expected.put("message", "Déconnexion réussie");

        when(authService.logout("Bearer token123")).thenReturn(expected);

        Map<String, Object> result = authController.logout("Bearer token123");

        assertEquals(expected, result);
        verify(authService).logout("Bearer token123");
    }
}