package com.example.auth.service;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Service de chiffrement réversible des mots de passe.
 *
 * Utilise AES-GCM qui garantit à la fois la confidentialité
 * et l'intégrité des données (authenticated encryption).
 *
 * @author Poun
 * @version 4.0
 */
@Service
public class PasswordCryptoService {

    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;

    // ✅ Fix java:S2119 — SecureRandom reused as a static final field
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Value("${app.security.smk}")
    private String serverMasterKey;

    private SecretKeySpec secretKeySpec;

    @PostConstruct
    public void init() {
        byte[] keyBytes = serverMasterKey.getBytes(StandardCharsets.UTF_8);
        byte[] finalKey = new byte[16];

        for (int i = 0; i < finalKey.length; i++) {
            finalKey[i] = (i < keyBytes.length) ? keyBytes[i] : 0;
        }

        this.secretKeySpec = new SecretKeySpec(finalKey, "AES");
    }

    /**
     * Chiffre un texte avec AES-GCM.
     *
     * L'IV aléatoire (12 bytes) est préfixé au ciphertext,
     * puis le tout est encodé en Base64 : [IV (12b) | ciphertext]
     *
     * @param plainText texte en clair
     * @return texte chiffré encodé en Base64
     */
    public String encrypt(String plainText) {
        try {
            // 1. Générer un IV aléatoire unique pour chaque chiffrement
            byte[] iv = new byte[GCM_IV_LENGTH];
            SECURE_RANDOM.nextBytes(iv); // ✅ Reuses static instance

            // 2. Initialiser le cipher en mode GCM
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, parameterSpec);

            // 3. Chiffrer
            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            // 4. Combiner IV + ciphertext et encoder en Base64
            byte[] combined = new byte[GCM_IV_LENGTH + cipherText.length];
            System.arraycopy(iv, 0, combined, 0, GCM_IV_LENGTH);
            System.arraycopy(cipherText, 0, combined, GCM_IV_LENGTH, cipherText.length);

            return Base64.getEncoder().encodeToString(combined);

        } catch (Exception e) {
            throw new IllegalStateException("Erreur pendant le chiffrement du mot de passe", e);
        }
    }

    /**
     * Déchiffre un texte Base64 chiffré avec AES-GCM.
     *
     * Extrait d'abord l'IV (12 premiers bytes), puis déchiffre le reste.
     *
     * @param encryptedText texte chiffré en Base64 (format: IV | ciphertext)
     * @return texte en clair
     */
    public String decrypt(String encryptedText) {
        try {
            // 1. Décoder le Base64
            byte[] combined = Base64.getDecoder().decode(encryptedText);

            // 2. Extraire l'IV (12 premiers bytes)
            byte[] iv = new byte[GCM_IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH);

            // 3. Extraire le ciphertext (le reste)
            byte[] cipherText = new byte[combined.length - GCM_IV_LENGTH];
            System.arraycopy(combined, GCM_IV_LENGTH, cipherText, 0, cipherText.length);

            // 4. Déchiffrer
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, parameterSpec);

            byte[] decryptedBytes = cipher.doFinal(cipherText);
            return new String(decryptedBytes, StandardCharsets.UTF_8);

        } catch (Exception e) {
            throw new IllegalStateException("Erreur pendant le déchiffrement du mot de passe", e);
        }
    }
}