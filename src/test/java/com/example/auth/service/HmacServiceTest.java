package com.example.auth.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires de HmacService.
 *
 * @author Poun
 * @version 1.0
 */
public class HmacServiceTest {

    @Test
    void testBuildMessage() {
        HmacService service = new HmacService();

        String message = service.buildMessage("test@mail.com", "abc123", 1700000000L);

        assertEquals("test@mail.com:abc123:1700000000", message);
    }

    @Test
    void testHmacSha256ReturnsValue() {
        HmacService service = new HmacService();

        String result = service.hmacSha256("secret123", "mon-message");

        assertNotNull(result);
        assertFalse(result.isBlank());
    }

    @Test
    void testHmacSha256SameInputSameOutput() {
        HmacService service = new HmacService();

        String hmac1 = service.hmacSha256("secret123", "message");
        String hmac2 = service.hmacSha256("secret123", "message");

        assertEquals(hmac1, hmac2);
    }

    @Test
    void testHmacSha256DifferentSecretDifferentOutput() {
        HmacService service = new HmacService();

        String hmac1 = service.hmacSha256("secret1", "message");
        String hmac2 = service.hmacSha256("secret2", "message");

        assertNotEquals(hmac1, hmac2);
    }

    @Test
    void testGenerateHmac() {
        HmacService service = new HmacService();

        String result = service.generateHmac("message-simple");

        assertNotNull(result);
        assertFalse(result.isBlank());
    }

    @Test
    void testGenerateHmacSameInputSameOutput() {
        HmacService service = new HmacService();

        String hmac1 = service.generateHmac("abc");
        String hmac2 = service.generateHmac("abc");

        assertEquals(hmac1, hmac2);
    }
    @Test
    void testHmacNotEmpty() {
        HmacService service = new HmacService();

        String hmac = service.generateHmac("data");

        assertNotNull(hmac);
        assertFalse(hmac.isEmpty());
    }
}