package com.example.auth.service;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.AuthNonce;
import com.example.auth.entity.User;
import com.example.auth.repository.AuthNonceRepository;
import com.example.auth.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Tests unitaires de AuthService.
 *
 * @author Poun
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
public class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordCryptoService passwordCryptoService;

    @Mock
    private AuthNonceRepository authNonceRepository;

    @Mock
    private HmacService hmacService;

    @InjectMocks
    private AuthService authService;

    @Test
    void testRegisterPasswordNull() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("poun@mail.com");
        request.setPassword(null);

        Map<String, Object> response = authService.register(request);

        assertTrue(response.containsKey("error"));
    }

    @Test
    void testRegisterPasswordInvalid() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("poun@mail.com");
        request.setPassword("123");

        Map<String, Object> response = authService.register(request);

        assertTrue(response.containsKey("error"));
    }

    @Test
    void testRegisterEmailAlreadyUsed() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("poun@mail.com");
        request.setPassword("Password123!");

        User user = new User();

        when(userRepository.findByEmail("poun@mail.com")).thenReturn(Optional.of(user));

        Map<String, Object> response = authService.register(request);

        assertEquals("Email déjà utilisé", response.get("error"));
    }

    @Test
    void testRegisterSuccess() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("poun@mail.com");
        request.setPassword("Password123!");

        when(userRepository.findByEmail("poun@mail.com")).thenReturn(Optional.empty());
        when(passwordCryptoService.encrypt("Password123!")).thenReturn("encrypted-password");

        Map<String, Object> response = authService.register(request);

        assertEquals("Inscription réussie", response.get("message"));
        verify(userRepository).save(any(User.class));
    }

    @Test
    void testLoginEmailMissing() {
        LoginRequest request = new LoginRequest();
        request.setEmail(null);
        request.setNonce("nonce");
        request.setTimestamp(1700000000L);
        request.setHmac("abc");

        Map<String, Object> response = authService.login(request);

        assertEquals("Email obligatoire", response.get("error"));
    }

    @Test
    void testLoginNonceMissing() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@mail.com");
        request.setNonce(null);
        request.setTimestamp(1700000000L);
        request.setHmac("abc");

        Map<String, Object> response = authService.login(request);

        assertEquals("Nonce obligatoire", response.get("error"));
    }

    @Test
    void testLoginTimestampMissing() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@mail.com");
        request.setNonce("nonce");
        request.setTimestamp(0);
        request.setHmac("abc");

        Map<String, Object> response = authService.login(request);

        assertEquals("Timestamp obligatoire", response.get("error"));
    }

    @Test
    void testLoginHmacMissing() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@mail.com");
        request.setNonce("nonce");
        request.setTimestamp(1700000000L);
        request.setHmac(null);

        Map<String, Object> response = authService.login(request);

        assertEquals("HMAC obligatoire", response.get("error"));
    }

    @Test
    void testLoginUserNotFound() {
        LoginRequest request = new LoginRequest();
        request.setEmail("notfound@mail.com");
        request.setNonce("nonce");
        request.setTimestamp(System.currentTimeMillis() / 1000);
        request.setHmac("abc");

        when(userRepository.findByEmail("notfound@mail.com")).thenReturn(Optional.empty());

        Map<String, Object> response = authService.login(request);

        assertEquals("Utilisateur introuvable", response.get("error"));
    }

    @Test
    void testLoginExpiredRequest() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@mail.com");
        request.setNonce("nonce");
        request.setTimestamp((System.currentTimeMillis() / 1000) - 1000);
        request.setHmac("abc");

        User user = new User();
        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(user));

        Map<String, Object> response = authService.login(request);

        assertEquals("Requête expirée", response.get("error"));
    }

    @Test
    void testLoginNonceAlreadyUsed() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@mail.com");
        request.setNonce("nonce123");
        request.setTimestamp(System.currentTimeMillis() / 1000);
        request.setHmac("abc");

        User user = new User();
        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(user));
        when(authNonceRepository.findByUserAndNonce(user, "nonce123"))
                .thenReturn(Optional.of(new AuthNonce()));

        Map<String, Object> response = authService.login(request);

        assertEquals("Nonce déjà utilisé", response.get("error"));
    }

    @Test
    void testLoginInvalidHmac() {
        long now = System.currentTimeMillis() / 1000;

        LoginRequest request = new LoginRequest();
        request.setEmail("test@mail.com");
        request.setNonce("nonce123");
        request.setTimestamp(now);
        request.setHmac("bad-hmac");

        User user = new User();
        user.setPasswordEncrypted("encrypted");

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(user));
        when(authNonceRepository.findByUserAndNonce(user, "nonce123")).thenReturn(Optional.empty());
        when(passwordCryptoService.decrypt("encrypted")).thenReturn("Password123!");

        String message = "test@mail.com:nonce123:" + now;
        when(hmacService.buildMessage("test@mail.com", "nonce123", now)).thenReturn(message);
        when(hmacService.hmacSha256("Password123!", message)).thenReturn("good-hmac");

        Map<String, Object> response = authService.login(request);

        assertEquals("HMAC invalide", response.get("error"));
    }

    @Test
    void testLoginSuccess() {
        long now = System.currentTimeMillis() / 1000;

        LoginRequest request = new LoginRequest();
        request.setEmail("test@mail.com");
        request.setNonce("nonce123");
        request.setTimestamp(now);
        request.setHmac("good-hmac");

        User user = new User();
        user.setEmail("test@mail.com");
        user.setPasswordEncrypted("encrypted-password");

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(user));
        when(authNonceRepository.findByUserAndNonce(user, "nonce123")).thenReturn(Optional.empty());
        when(passwordCryptoService.decrypt("encrypted-password")).thenReturn("Password123!");

        String message = "test@mail.com:nonce123:" + now;
        when(hmacService.buildMessage("test@mail.com", "nonce123", now)).thenReturn(message);
        when(hmacService.hmacSha256("Password123!", message)).thenReturn("good-hmac");

        Map<String, Object> response = authService.login(request);

        assertEquals("Connexion réussie", response.get("message"));
        assertNotNull(response.get("accessToken"));
        assertEquals("test@mail.com", response.get("email"));

        verify(authNonceRepository).save(any(AuthNonce.class));
        verify(userRepository, atLeastOnce()).save(user);
    }

    @Test
    void testGetMeTokenMissing() {
        Map<String, Object> response = authService.getMe(null);

        assertEquals("Token manquant ou invalide", response.get("error"));
    }

    @Test
    void testGetMeUserNotFound() {
        when(userRepository.findByToken("bad-token")).thenReturn(Optional.empty());

        Map<String, Object> response = authService.getMe("Bearer bad-token");

        assertEquals("Utilisateur non trouvé pour ce token", response.get("error"));
    }

    @Test
    void testGetMeTokenExpired() {
        User user = new User();
        user.setToken("token123");
        user.setTokenExpiresAt(LocalDateTime.now().minusMinutes(1));

        when(userRepository.findByToken("token123")).thenReturn(Optional.of(user));

        Map<String, Object> response = authService.getMe("Bearer token123");

        assertEquals("Token expiré ou invalide", response.get("error"));
    }

    @Test
    void testGetMeSuccess() {
        User user = new User();
        user.setId(1L);
        user.setName("Poun");
        user.setEmail("poun@mail.com");
        user.setCreatedAt(LocalDateTime.now());
        user.setToken("token123");
        user.setTokenExpiresAt(LocalDateTime.now().plusMinutes(10));

        when(userRepository.findByToken("token123")).thenReturn(Optional.of(user));

        Map<String, Object> response = authService.getMe("Bearer token123");

        assertEquals(1L, response.get("id"));
        assertEquals("Poun", response.get("name"));
        assertEquals("poun@mail.com", response.get("email"));
    }

    @Test
    void testLogoutTokenMissing() {
        Map<String, Object> response = authService.logout(null);

        assertEquals("Token manquant ou invalide", response.get("error"));
    }

    @Test
    void testLogoutUserNotFound() {
        when(userRepository.findByToken("bad-token")).thenReturn(Optional.empty());

        Map<String, Object> response = authService.logout("Bearer bad-token");

        assertEquals("Utilisateur non trouvé", response.get("error"));
    }

    @Test
    void testLogoutSuccess() {
        User user = new User();
        user.setToken("token123");
        user.setTokenExpiresAt(LocalDateTime.now().plusMinutes(10));

        when(userRepository.findByToken("token123")).thenReturn(Optional.of(user));

        Map<String, Object> response = authService.logout("Bearer token123");

        assertEquals("Déconnexion réussie", response.get("message"));
        assertNull(user.getToken());
        assertNull(user.getTokenExpiresAt());
        verify(userRepository).save(user);
    }

    @Test
    void testIssueToken() {
        User user = new User();
        user.setEmail("poun@mail.com");

        Map<String, Object> response = authService.issueToken(user);

        assertEquals("Connexion réussie", response.get("message"));
        assertEquals("poun@mail.com", response.get("email"));
        assertNotNull(response.get("accessToken"));
        assertNotNull(response.get("expiresAt"));

        verify(userRepository).save(user);
        assertNotNull(user.getToken());
        assertNotNull(user.getTokenExpiresAt());
    }
}