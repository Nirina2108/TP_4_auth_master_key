package com.example.auth.service;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Tests unitaires du service HMAC.
 *
 * @author Poun
 * @version 4.0
 */
public class HmacServiceTest {

    /**
     * Verifie la construction du message.
     */
    @Test
    void testBuildMessage() {
        HmacService hmacService = new HmacService();
        String message = hmacService.buildMessage("a@gmail.com", "nonce123", 123456L);

        Assertions.assertEquals("a@gmail.com:nonce123:123456", message);
    }

    /**
     * Verifie que le HMAC n'est pas null.
     */
    @Test
    void testComputeHmacNotNull() {
        HmacService hmacService = new HmacService();
        String hmac = hmacService.computeHmac("secret", "abc:def:123");

        Assertions.assertNotNull(hmac);
    }

    /**
     * Verifie que le HMAC n'est pas vide.
     */
    @Test
    void testComputeHmacNotEmpty() {
        HmacService hmacService = new HmacService();
        String hmac = hmacService.computeHmac("secret", "abc:def:123");

        Assertions.assertFalse(hmac.isEmpty());
    }

    /**
     * Verifie que deux calculs identiques donnent le meme resultat.
     */
    @Test
    void testComputeHmacSameInputSameOutput() {
        HmacService hmacService = new HmacService();

        String h1 = hmacService.computeHmac("secret", "abc:def:123");
        String h2 = hmacService.computeHmac("secret", "abc:def:123");

        Assertions.assertEquals(h1, h2);
    }

    /**
     * Verifie que deux messages differents donnent des HMAC differents.
     */
    @Test
    void testComputeHmacDifferentMessageDifferentOutput() {
        HmacService hmacService = new HmacService();

        String h1 = hmacService.computeHmac("secret", "abc:def:123");
        String h2 = hmacService.computeHmac("secret", "abc:def:124");

        Assertions.assertNotEquals(h1, h2);
    }
}