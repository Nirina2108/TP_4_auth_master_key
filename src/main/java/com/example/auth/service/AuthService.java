package com.example.auth.service;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.AuthNonce;
import com.example.auth.entity.User;
import com.example.auth.repository.AuthNonceRepository;
import com.example.auth.repository.UserRepository;
import com.example.auth.validator.PasswordPolicyValidator;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Service contenant la logique métier de l'authentification.
 *
 * TP4 :
 * - HMAC conservé (TP3)
 * - nonce + timestamp (anti-replay)
 * - mot de passe chiffré avec CryptoService
 *
 * @author Poun
 * @version 4.0
 */
@Service
public class AuthService {

    private static final String KEY_ERROR = "error";
    private static final String KEY_MESSAGE = "message";
    private static final int TOKEN_DURATION_MINUTES = 15;

    private final UserRepository userRepository;
    private final CryptoService cryptoService;
    private final AuthNonceRepository authNonceRepository;
    private final HmacService hmacService;

    private final PasswordPolicyValidator passwordPolicyValidator = new PasswordPolicyValidator();

    public AuthService(UserRepository userRepository,
                       CryptoService cryptoService,
                       AuthNonceRepository authNonceRepository,
                       HmacService hmacService) {
        this.userRepository = userRepository;
        this.cryptoService = cryptoService;
        this.authNonceRepository = authNonceRepository;
        this.hmacService = hmacService;
    }

    /**
     * Inscription utilisateur.
     */
    public Map<String, Object> register(RegisterRequest request) {
        Map<String, Object> response = new HashMap<>();

        if (request.getPassword() == null || !passwordPolicyValidator.isValid(request.getPassword())) {
            response.put(KEY_ERROR, passwordPolicyValidator.getRulesMessage());
            return response;
        }

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            response.put(KEY_ERROR, "Email déjà utilisé");
            return response;
        }

        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());

        // TP4 : chiffrement du mot de passe
        user.setPasswordEncrypted(cryptoService.encrypt(request.getPassword()));

        user.setCreatedAt(LocalDateTime.now());
        user.setToken(null);
        user.setTokenExpiresAt(null);

        userRepository.save(user);

        response.put(KEY_MESSAGE, "Inscription réussie");
        return response;
    }

    /**
     * Login sécurisé avec HMAC.
     */
    public Map<String, Object> login(LoginRequest request) {
        Map<String, Object> response = new HashMap<>();

        if (request.getEmail() == null || request.getEmail().isBlank()) {
            response.put(KEY_ERROR, "Email obligatoire");
            return response;
        }

        if (request.getNonce() == null || request.getNonce().isBlank()) {
            response.put(KEY_ERROR, "Nonce obligatoire");
            return response;
        }

        if (request.getTimestamp() <= 0) {
            response.put(KEY_ERROR, "Timestamp obligatoire");
            return response;
        }

        if (request.getHmac() == null || request.getHmac().isBlank()) {
            response.put(KEY_ERROR, "HMAC obligatoire");
            return response;
        }

        User user = userRepository.findByEmail(request.getEmail()).orElse(null);

        if (user == null) {
            response.put(KEY_ERROR, "Utilisateur introuvable");
            return response;
        }

        long now = System.currentTimeMillis() / 1000;
        long diff = Math.abs(now - request.getTimestamp());

        if (diff > 300) {
            response.put(KEY_ERROR, "Requête expirée");
            return response;
        }

        if (authNonceRepository.findByUserAndNonce(user, request.getNonce()).isPresent()) {
            response.put(KEY_ERROR, "Nonce déjà utilisé");
            return response;
        }

        // TP4 : déchiffrement du mot de passe
        String decryptedPassword = cryptoService.decrypt(user.getPasswordEncrypted());

        String message = hmacService.buildMessage(
                request.getEmail(),
                request.getNonce(),
                request.getTimestamp()
        );

        String expectedHmac = hmacService.hmacSha256(decryptedPassword, message);

        if (!constantTimeEquals(expectedHmac, request.getHmac())) {
            response.put(KEY_ERROR, "HMAC invalide");
            return response;
        }

        AuthNonce authNonce = new AuthNonce();
        authNonce.setUser(user);
        authNonce.setNonce(request.getNonce());
        authNonce.setCreatedAt(LocalDateTime.now());
        authNonce.setExpiresAt(LocalDateTime.now().plusMinutes(5));
        authNonce.setConsumed(true);
        authNonceRepository.save(authNonce);

        return issueToken(user);
    }

    public Map<String, Object> getMe(String authorizationHeader) {
        Map<String, Object> response = new HashMap<>();

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            response.put(KEY_ERROR, "Token manquant ou invalide");
            return response;
        }

        String token = authorizationHeader.substring(7);

        User user = userRepository.findByToken(token).orElse(null);

        if (user == null) {
            response.put(KEY_ERROR, "Utilisateur non trouvé");
            return response;
        }

        if (user.getTokenExpiresAt() == null || user.getTokenExpiresAt().isBefore(LocalDateTime.now())) {
            response.put(KEY_ERROR, "Token expiré");
            return response;
        }

        response.put("id", user.getId());
        response.put("name", user.getName());
        response.put("email", user.getEmail());
        response.put("createdAt", user.getCreatedAt());
        response.put("tokenExpiresAt", user.getTokenExpiresAt());

        return response;
    }

    public Map<String, Object> logout(String authorizationHeader) {
        Map<String, Object> response = new HashMap<>();

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            response.put(KEY_ERROR, "Token manquant");
            return response;
        }

        String token = authorizationHeader.substring(7);

        User user = userRepository.findByToken(token).orElse(null);

        if (user == null) {
            response.put(KEY_ERROR, "Utilisateur non trouvé");
            return response;
        }

        user.setToken(null);
        user.setTokenExpiresAt(null);
        userRepository.save(user);

        response.put(KEY_MESSAGE, "Déconnexion réussie");
        return response;
    }

    public Map<String, Object> issueToken(User user) {
        Map<String, Object> response = new HashMap<>();

        String token = UUID.randomUUID().toString();
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(TOKEN_DURATION_MINUTES);

        user.setToken(token);
        user.setTokenExpiresAt(expiresAt);
        userRepository.save(user);

        response.put(KEY_MESSAGE, "Connexion réussie");
        response.put("accessToken", token);
        response.put("expiresAt", expiresAt);
        response.put("email", user.getEmail());

        return response;
    }

    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }

        return result == 0;
    }
}