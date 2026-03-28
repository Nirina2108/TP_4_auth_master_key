package com.example.auth.service;

import com.example.auth.AuthApplication;
import com.example.auth.dto.ClientProofRequest;
import com.example.auth.dto.ClientProofResponse;
import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.repository.AuthNonceRepository;
import com.example.auth.repository.UserRepository;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.Map;

/**
 * Tests unitaires du service d'authentification.
 *
 * @author Poun
 * @version 4.1
 */
@SpringBootTest(classes = AuthApplication.class)
@ActiveProfiles("test")
public class AuthServiceTest {

    private static final String DEFAULT_NAME = "Poun";
    private static final String DEFAULT_EMAIL = "poun@gmail.com";
    private static final String DEFAULT_PASSWORD = "Password123!";

    @Autowired
    private AuthService authService;

    @Autowired
    private HmacService hmacService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthNonceRepository authNonceRepository;

    /**
     * Nettoyage avant chaque test.
     */
    @BeforeEach
    void setUp() {
        authNonceRepository.deleteAll();
        userRepository.deleteAll();
    }

    /**
     * Construit une requête d'inscription.
     *
     * @param name nom
     * @param email email
     * @param password mot de passe
     * @return requête prête
     */
    private RegisterRequest buildRegisterRequest(String name, String email, String password) {
        RegisterRequest request = new RegisterRequest();
        request.setName(name);
        request.setEmail(email);
        request.setPassword(password);
        return request;
    }

    /**
     * Construit une requête de login.
     *
     * @param email email
     * @param password mot de passe
     * @return requête prête
     */
    private LoginRequest buildLoginRequest(String email, String password) {
        LoginRequest request = new LoginRequest();
        request.setEmail(email);
        request.setPassword(password);
        return request;
    }

    /**
     * Inscrit l'utilisateur par défaut.
     */
    private void registerDefaultUser() {
        authService.register(buildRegisterRequest(DEFAULT_NAME, DEFAULT_EMAIL, DEFAULT_PASSWORD));
    }

    /**
     * Connecte l'utilisateur par défaut et retourne le token.
     *
     * @return token généré
     */
    private String loginDefaultUserAndGetToken() {
        Map<String, Object> loginResponse = authService.login(
                buildLoginRequest(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        );
        return (String) loginResponse.get("token");
    }

    /**
     * Construit une requête client-proof.
     *
     * @param email email
     * @param nonce nonce
     * @param timestamp timestamp
     * @param hmac signature HMAC
     * @return requête prête
     */
    private ClientProofRequest buildProofRequest(String email, String nonce, long timestamp, String hmac) {
        ClientProofRequest request = new ClientProofRequest();
        request.setEmail(email);
        request.setNonce(nonce);
        request.setTimestamp(timestamp);
        request.setHmac(hmac);
        return request;
    }

    /**
     * Construit une requête client-proof valide.
     *
     * @param nonce nonce
     * @param timestamp timestamp
     * @return requête valide
     */
    private ClientProofRequest buildValidProofRequest(String nonce, long timestamp) {
        String message = hmacService.buildMessage(DEFAULT_EMAIL, nonce, timestamp);
        String hmac = hmacService.computeHmac("secret", message);
        return buildProofRequest(DEFAULT_EMAIL, nonce, timestamp, hmac);
    }

    /**
     * Test register valide.
     */
    @Test
    void testRegisterSuccess() {
        Map<String, Object> response = authService.register(
                buildRegisterRequest(DEFAULT_NAME, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        );

        Assertions.assertEquals("Inscription reussie", response.get("message"));
        Assertions.assertEquals(DEFAULT_EMAIL, response.get("email"));
    }

    /**
     * Test register doublon email.
     */
    @Test
    void testRegisterDuplicateEmail() {
        registerDefaultUser();

        RuntimeException exception = Assertions.assertThrows(
                RuntimeException.class,
                () -> authService.register(buildRegisterRequest("Poun2", DEFAULT_EMAIL, DEFAULT_PASSWORD))
        );

        Assertions.assertEquals("Email deja utilise", exception.getMessage());
    }

    /**
     * Test login valide.
     */
    @Test
    void testLoginSuccess() {
        registerDefaultUser();

        Map<String, Object> response = authService.login(
                buildLoginRequest(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        );

        Assertions.assertEquals("Connexion reussie", response.get("message"));
        Assertions.assertNotNull(response.get("token"));
    }

    /**
     * Test login mauvais mot de passe.
     */
    @Test
    void testLoginWrongPassword() {
        registerDefaultUser();

        RuntimeException exception = Assertions.assertThrows(
                RuntimeException.class,
                () -> authService.login(buildLoginRequest(DEFAULT_EMAIL, "FAUX"))
        );

        Assertions.assertEquals("Mot de passe incorrect", exception.getMessage());
    }

    /**
     * Test login utilisateur inconnu.
     */
    @Test
    void testLoginUnknownUser() {
        RuntimeException exception = Assertions.assertThrows(
                RuntimeException.class,
                () -> authService.login(buildLoginRequest("inconnu@gmail.com", DEFAULT_PASSWORD))
        );

        Assertions.assertEquals("Utilisateur non trouve", exception.getMessage());
    }

    /**
     * Test lecture profil avec token valide.
     */
    @Test
    void testGetProfileSuccess() {
        registerDefaultUser();
        String token = loginDefaultUserAndGetToken();

        Map<String, Object> profile = authService.getProfile("Bearer " + token);

        Assertions.assertEquals(DEFAULT_EMAIL, profile.get("email"));
        Assertions.assertEquals(DEFAULT_NAME, profile.get("name"));
    }

    /**
     * Test profil sans token.
     */
    @Test
    void testGetProfileWithoutToken() {
        RuntimeException exception = Assertions.assertThrows(
                RuntimeException.class,
                () -> authService.getProfile(null)
        );

        Assertions.assertEquals("Token manquant", exception.getMessage());
    }

    /**
     * Test logout.
     */
    @Test
    void testLogoutSuccess() {
        registerDefaultUser();
        String token = loginDefaultUserAndGetToken();

        Map<String, Object> logoutResponse = authService.logout("Bearer " + token);

        Assertions.assertEquals("Deconnexion reussie", logoutResponse.get("message"));
    }

    /**
     * Test client-proof valide.
     */
    @Test
    void testClientProofSuccess() {
        registerDefaultUser();

        long timestamp = Instant.now().getEpochSecond();
        ClientProofRequest proofRequest = buildValidProofRequest("nonce-123", timestamp);

        ClientProofResponse response = authService.verifyClientProof(proofRequest);

        Assertions.assertEquals("Preuve client valide", response.getMessage());
        Assertions.assertNotNull(response.getToken());
    }

    /**
     * Test client-proof HMAC invalide.
     */
    @Test
    void testClientProofInvalidHmac() {
        registerDefaultUser();

        ClientProofRequest proofRequest = buildProofRequest(
                DEFAULT_EMAIL,
                "nonce-999",
                Instant.now().getEpochSecond(),
                "INVALIDE"
        );

        RuntimeException exception = Assertions.assertThrows(
                RuntimeException.class,
                () -> authService.verifyClientProof(proofRequest)
        );

        Assertions.assertEquals("Signature HMAC invalide", exception.getMessage());
    }

    /**
     * Test rejeu nonce.
     */
    @Test
    void testClientProofReplayNonce() {
        registerDefaultUser();

        long timestamp = Instant.now().getEpochSecond();
        ClientProofRequest proofRequest = buildValidProofRequest("nonce-replay", timestamp);

        authService.verifyClientProof(proofRequest);

        RuntimeException exception = Assertions.assertThrows(
                RuntimeException.class,
                () -> authService.verifyClientProof(proofRequest)
        );

        Assertions.assertEquals("Nonce deja utilise", exception.getMessage());
    }

    /**
     * Test profil avec faux token.
     */
    @Test
    void testGetProfileInvalidToken() {
        RuntimeException exception = Assertions.assertThrows(
                RuntimeException.class,
                () -> authService.getProfile("Bearer faux-token")
        );

        Assertions.assertEquals("Token invalide", exception.getMessage());
    }

    /**
     * Test logout avec faux token.
     */
    @Test
    void testLogoutInvalidToken() {
        RuntimeException exception = Assertions.assertThrows(
                RuntimeException.class,
                () -> authService.logout("Bearer faux-token")
        );

        Assertions.assertEquals("Token invalide", exception.getMessage());
    }
}