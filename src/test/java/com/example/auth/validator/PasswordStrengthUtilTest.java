package com.example.auth.validator;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Tests utilitaires de mot de passe.
 */
public class PasswordStrengthUtilTest {

    @Test
    void testClassInstantiation() {
        PasswordStrengthUtil util = new PasswordStrengthUtil();
        Assertions.assertNotNull(util);
    }
}