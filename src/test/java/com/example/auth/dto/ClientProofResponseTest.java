package com.example.auth.dto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires de ClientProofResponse.
 *
 * @author Poun
 * @version 1.0
 */
public class ClientProofResponseTest {

    @Test
    void testGettersAndSetters() {
        ClientProofResponse response = new ClientProofResponse();

        response.setEmail("client@test.com");
        response.setNonce("nonce123");
        response.setTimestamp(1700000000L);
        response.setMessage("client@test.com:nonce123:1700000000");
        response.setHmac("abc123hmac");

        assertEquals("client@test.com", response.getEmail());
        assertEquals("nonce123", response.getNonce());
        assertEquals(1700000000L, response.getTimestamp());
        assertEquals("client@test.com:nonce123:1700000000", response.getMessage());
        assertEquals("abc123hmac", response.getHmac());
    }
}