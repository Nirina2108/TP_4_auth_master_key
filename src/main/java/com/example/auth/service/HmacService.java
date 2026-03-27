package com.example.auth.service;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Service pour calculer HMAC SHA-256.
 */
@Service
public class HmacService {

    /**
     * Construit le message à signer.
     */
    public String buildMessage(String email, String nonce, long timestamp) {
        return email + ":" + nonce + ":" + timestamp;
    }

    /**
     * Calcule le HMAC SHA-256.
     */
    public String computeHmac(String secret, String message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");

            SecretKeySpec key = new SecretKeySpec(
                    secret.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA256"
            );

            mac.init(key);

            byte[] raw = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));

            return Base64.getEncoder().encodeToString(raw);

        } catch (Exception e) {
            throw new RuntimeException("Erreur HMAC", e);
        }
    }
}