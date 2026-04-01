package com.example.auth.entity;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires de AuthNonce.
 *
 * @author Poun
 * @version 1.0
 */
public class AuthNonceTest {

    @Test
    void testGettersAndSetters() {
        AuthNonce authNonce = new AuthNonce();
        User user = new User();
        LocalDateTime createdAt = LocalDateTime.now();
        LocalDateTime expiresAt = createdAt.plusMinutes(5);

        authNonce.setId(1L);
        authNonce.setUser(user);
        authNonce.setNonce("nonce-001");
        authNonce.setCreatedAt(createdAt);
        authNonce.setExpiresAt(expiresAt);
        authNonce.setConsumed(true);

        assertEquals(1L, authNonce.getId());
        assertEquals(user, authNonce.getUser());
        assertEquals("nonce-001", authNonce.getNonce());
        assertEquals(createdAt, authNonce.getCreatedAt());
        assertEquals(expiresAt, authNonce.getExpiresAt());
        assertTrue(authNonce.isConsumed());
    }

    @Test
    void testDefaultConstructor() {
        AuthNonce authNonce = new AuthNonce();

        assertNotNull(authNonce);
        assertNull(authNonce.getId());
        assertNull(authNonce.getUser());
        assertNull(authNonce.getNonce());
        assertNull(authNonce.getCreatedAt());
        assertNull(authNonce.getExpiresAt());
        assertFalse(authNonce.isConsumed());
    }
}