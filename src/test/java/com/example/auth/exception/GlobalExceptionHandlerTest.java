package com.example.auth.exception;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires de GlobalExceptionHandler.
 *
 * @author Poun
 * @version 1.0
 */
public class GlobalExceptionHandlerTest {

    @Test
    void testHandleRuntimeException() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();

        RuntimeException exception = new RuntimeException("Erreur test");
        Map<String, Object> response = handler.handleRuntimeException(exception);

        assertNotNull(response);
        assertEquals("Erreur test", response.get("error"));
    }
}