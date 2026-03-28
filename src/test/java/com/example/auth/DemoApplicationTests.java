package com.example.auth;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Test simple de chargement du contexte Spring.
 *
 * @author Poun
 * @version 4.0
 */
@SpringBootTest(classes = AuthApplication.class)
@ActiveProfiles("test")
class DemoApplicationTests {

    /**
     * Vérifie que le contexte Spring démarre correctement.
     */
    @Test
    void contextLoads() {
    }
}