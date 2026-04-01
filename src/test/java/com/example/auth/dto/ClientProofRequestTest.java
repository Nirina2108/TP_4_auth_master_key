package com.example.auth.dto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires de ClientProofRequest.
 *
 * @author Poun
 * @version 1.0
 */
public class ClientProofRequestTest {

    @Test
    void testGettersAndSetters() {
        ClientProofRequest request = new ClientProofRequest();

        request.setEmail("client@test.com");
        request.setPassword("Password123!");

        assertEquals("client@test.com", request.getEmail());
        assertEquals("Password123!", request.getPassword());
    }
}