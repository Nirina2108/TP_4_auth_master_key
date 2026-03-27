package com.example.auth.service;

import com.example.auth.dto.ClientProofRequest;
import com.example.auth.dto.ClientProofResponse;
import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.AuthNonce;
import com.example.auth.entity.User;
import com.example.auth.repository.AuthNonceRepository;
import com.example.auth.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Service principal de l'authentification.
 *
 * Version simple compatible TP4 :
 * - gestion utilisateurs
 * - token simple
 * - protection anti-replay avec nonce
 * - verification HMAC
 *
 * @author Poun
 * @version 4.0
 */
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final AuthNonceRepository authNonceRepository;
    private final HmacService hmacService;

    public AuthService(UserRepository userRepository,
                       AuthNonceRepository authNonceRepository,
                       HmacService hmacService) {
        this.userRepository = userRepository;
        this.authNonceRepository = authNonceRepository;
        this.hmacService = hmacService;
    }

    /**
     * Inscription utilisateur.
     */
    public Map<String, Object> register(RegisterRequest request) {

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email deja utilise");
        }

        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());

        // IMPORTANT : on utilise setPassword (pas passwordEncrypted)
        user.setPassword(request.getPassword());

        userRepository.save(user);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Inscription reussie");
        response.put("email", user.getEmail());

        return response;
    }

    /**
     * Login simple.
     */
    public Map<String, Object> login(LoginRequest request) {

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouve"));

        if (!user.getPassword().equals(request.getPassword())) {
            throw new RuntimeException("Mot de passe incorrect");
        }

        String token = UUID.randomUUID().toString();
        user.setToken(token);

        userRepository.save(user);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Connexion reussie");
        response.put("token", token);

        return response;
    }

    /**
     * Verification HMAC + nonce (anti-replay).
     */
    public ClientProofResponse verifyClientProof(ClientProofRequest request) {

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouve"));

        // 1. verifier nonce deja utilise
        if (authNonceRepository.existsByNonce(request.getNonce())) {
            throw new RuntimeException("Nonce deja utilise");
        }

        // 2. reconstruire message
        String message = hmacService.buildMessage(
                request.getEmail(),
                request.getNonce(),
                request.getTimestamp()
        );

        // 3. recalcul HMAC serveur
        String expectedHmac = hmacService.computeHmac("secret", message);

        if (!expectedHmac.equals(request.getHmac())) {
            throw new RuntimeException("Signature HMAC invalide");
        }

        // 4. sauvegarder nonce
        AuthNonce authNonce = new AuthNonce();
        authNonce.setNonce(request.getNonce());
        authNonce.setUser(user);

        authNonceRepository.save(authNonce);

        // 5. generer token
        String token = UUID.randomUUID().toString();
        user.setToken(token);
        userRepository.save(user);

        return new ClientProofResponse("Preuve client valide", token);
    }

    /**
     * Recuperer profil.
     */
    public Map<String, Object> getProfile(String authorizationHeader) {

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new RuntimeException("Token manquant");
        }

        String token = authorizationHeader.substring(7);

        User user = userRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Token invalide"));

        Map<String, Object> response = new HashMap<>();
        response.put("email", user.getEmail());
        response.put("name", user.getName());

        return response;
    }

    /**
     * Logout.
     */
    public Map<String, Object> logout(String authorizationHeader) {

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new RuntimeException("Token manquant");
        }

        String token = authorizationHeader.substring(7);

        User user = userRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Token invalide"));

        user.setToken(null);
        userRepository.save(user);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Deconnexion reussie");

        return response;
    }
}