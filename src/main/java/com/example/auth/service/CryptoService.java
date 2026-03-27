package com.example.auth.service;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Service de chiffrement pour le TP4.
 *
 * Ce service chiffre et déchiffre les mots de passe
 * avec une Master Key fournie par variable d'environnement.
 *
 * Format de stockage :
 * v1:Base64(iv):Base64(ciphertext)
 *
 * Algorithme :
 * AES/GCM/NoPadding
 *
 * @author Poun
 * @version 4.0
 */
@Service
public class CryptoService {

    /**
     * Préfixe de version du format stocké.
     */
    private static final String VERSION = "v1";

    /**
     * Algorithme utilisé pour la clé.
     */
    private static final String ALGORITHM = "AES";

    /**
     * Transformation complète.
     */
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    /**
     * Taille du tag GCM en bits.
     */
    private static final int GCM_TAG_LENGTH = 128;

    /**
     * Taille de l'IV recommandée pour GCM.
     * 12 octets = 96 bits.
     */
    private static final int IV_LENGTH = 12;

    /**
     * Clé maître injectée depuis application.properties
     * qui lui-même lit APP_MASTER_KEY.
     */
    @Value("${app.security.master-key:}")
    private String masterKey;

    /**
     * Clé AES dérivée de la master key texte.
     */
    private SecretKey secretKey;

    /**
     * Vérifie la présence de la master key au démarrage
     * et prépare la clé AES.
     */
    @PostConstruct
    public void init() {
        if (masterKey == null) {
            masterKey = "default-master-key";
        }

        this.secretKey = buildKeyFromMasterKey(masterKey);
    }

    /**
     * Chiffre un texte avec AES/GCM.
     *
     * @param plainText texte à chiffrer
     * @return texte chiffré au format v1:Base64(iv):Base64(ciphertext)
     */
    public String encrypt(String plainText) {
        try {
            if (plainText == null) {
                throw new IllegalArgumentException("Le texte a chiffrer ne doit pas etre null.");
            }

            byte[] iv = new byte[IV_LENGTH];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            String ivBase64 = Base64.getEncoder().encodeToString(iv);
            String cipherBase64 = Base64.getEncoder().encodeToString(encryptedBytes);

            return VERSION + ":" + ivBase64 + ":" + cipherBase64;
        } catch (Exception e) {
            throw new IllegalStateException("Erreur pendant le chiffrement.", e);
        }
    }

    /**
     * Déchiffre un texte stocké au format TP4.
     *
     * @param encryptedText texte chiffré au format v1:Base64(iv):Base64(ciphertext)
     * @return texte déchiffré
     */
    public String decrypt(String encryptedText) {
        try {
            if (encryptedText == null || encryptedText.isBlank()) {
                throw new IllegalArgumentException("Le texte chiffre ne doit pas etre vide.");
            }

            String[] parts = encryptedText.split(":");
            if (parts.length != 3) {
                throw new IllegalArgumentException("Format du texte chiffre invalide.");
            }

            String version = parts[0];
            if (!VERSION.equals(version)) {
                throw new IllegalArgumentException("Version de chiffrement non supportee.");
            }

            byte[] iv = Base64.getDecoder().decode(parts[1]);
            byte[] cipherBytes = Base64.getDecoder().decode(parts[2]);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

            byte[] decryptedBytes = cipher.doFinal(cipherBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Erreur pendant le dechiffrement.", e);
        }
    }

    /**
     * Construit une clé AES de 256 bits à partir de la master key texte.
     *
     * Pour rester simple en niveau étudiant, on dérive la clé
     * avec un SHA-256 du texte, puis on utilise le résultat
     * comme clé AES.
     *
     * @param sourceMasterKey master key texte
     * @return clé AES prête à l'emploi
     */
    private SecretKey buildKeyFromMasterKey(String sourceMasterKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = digest.digest(sourceMasterKey.getBytes(StandardCharsets.UTF_8));
            return new SecretKeySpec(keyBytes, ALGORITHM);
        } catch (Exception e) {
            throw new IllegalStateException("Impossible de construire la cle AES.", e);
        }
    }
}