package com.example.auth.validator;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Tests du validateur de mot de passe TP3.
 *
 * @author Poun
 * @version 4.0
 */
public class PasswordPolicyValidatorTest {

    /**
     * Mot de passe valide.
     */
    @Test
    void testValidPassword() {
        String password = "Password123!";

        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        boolean result = validator.isValid(password);

        Assertions.assertTrue(result);
    }

    /**
     * Trop court.
     */
    @Test
    void testPasswordTooShort() {
        String password = "Pass1!";

        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        boolean result = validator.isValid(password);

        Assertions.assertFalse(result);
    }

    /**
     * Pas de majuscule.
     */
    @Test
    void testNoUppercase() {
        String password = "password123!";

        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        boolean result = validator.isValid(password);

        Assertions.assertFalse(result);
    }

    /**
     * Pas de minuscule.
     */
    @Test
    void testNoLowercase() {
        String password = "PASSWORD123!";

        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        boolean result = validator.isValid(password);

        Assertions.assertFalse(result);
    }

    /**
     * Pas de chiffre.
     */
    @Test
    void testNoDigit() {
        String password = "Password!!!";

        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        boolean result = validator.isValid(password);

        Assertions.assertFalse(result);
    }

    /**
     * Pas de caractère spécial.
     */
    @Test
    void testNoSpecialChar() {
        String password = "Password123";

        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        boolean result = validator.isValid(password);

        Assertions.assertFalse(result);
    }
}