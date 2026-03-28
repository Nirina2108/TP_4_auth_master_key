package com.example.auth.service;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Service de chiffrement réversible des mots de passe.
 *
 * @author Poun
 * @version 4.2
 */
@Service
public class PasswordCryptoService {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    private static final int KEY_LENGTH = 16;
    private static final int IV_LENGTH = 16;

    @Value("${app.security.smk}")
    private String serverMasterKey;

    private SecretKeySpec secretKeySpec;

    @PostConstruct
    public void init() {
        this.secretKeySpec = new SecretKeySpec(buildKey(serverMasterKey), ALGORITHM);
    }

    /**
     * Chiffrement avec IV aléatoire.
     */
    public String encrypt(String plainText) {
        try {
            byte[] iv = generateRandomIv();

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            // On concatène IV + données
            byte[] finalBytes = new byte[iv.length + encryptedBytes.length];
            System.arraycopy(iv, 0, finalBytes, 0, iv.length);
            System.arraycopy(encryptedBytes, 0, finalBytes, iv.length, encryptedBytes.length);

            return Base64.getEncoder().encodeToString(finalBytes);

        } catch (Exception e) {
            throw new RuntimeException("Erreur chiffrement", e);
        }
    }

    /**
     * Déchiffrement avec extraction IV.
     */
    public String decrypt(String encryptedText) {
        try {
            byte[] allBytes = Base64.getDecoder().decode(encryptedText);

            byte[] iv = new byte[IV_LENGTH];
            byte[] encryptedBytes = new byte[allBytes.length - IV_LENGTH];

            System.arraycopy(allBytes, 0, iv, 0, IV_LENGTH);
            System.arraycopy(allBytes, IV_LENGTH, encryptedBytes, 0, encryptedBytes.length);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            return new String(decryptedBytes, StandardCharsets.UTF_8);

        } catch (Exception e) {
            throw new RuntimeException("Erreur dechiffrement", e);
        }
    }

    private byte[] buildKey(String masterKey) {
        byte[] keyBytes = masterKey.getBytes(StandardCharsets.UTF_8);
        byte[] finalKey = new byte[KEY_LENGTH];

        for (int i = 0; i < KEY_LENGTH; i++) {
            finalKey[i] = (i < keyBytes.length) ? keyBytes[i] : 0;
        }

        return finalKey;
    }

    /**
     * Génère un IV aléatoire sécurisé.
     */
    private byte[] generateRandomIv() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}