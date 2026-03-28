package com.example.auth.service;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Tests du service PasswordCryptoService.
 *
 * @author Poun
 * @version 4.0
 */
public class PasswordCryptoServiceTest {

    /**
     * Construit un service prêt à être utilisé.
     *
     * @return service initialisé
     */
    private PasswordCryptoService createService() {
        PasswordCryptoService service = new PasswordCryptoService();
        ReflectionTestUtils.setField(service, "serverMasterKey", "test-smk-tp4");
        service.init();
        return service;
    }

    /**
     * Vérifie le cycle chiffrement / déchiffrement.
     */
    @Test
    void testEncryptDecryptSuccess() {
        PasswordCryptoService service = createService();

        String plainText = "Password123!";
        String encrypted = service.encrypt(plainText);
        String decrypted = service.decrypt(encrypted);

        Assertions.assertNotNull(encrypted);
        Assertions.assertNotEquals(plainText, encrypted);
        Assertions.assertEquals(plainText, decrypted);
    }

    /**
     * Vérifie qu'un texte chiffré invalide provoque une erreur.
     */
    @Test
    void testDecryptInvalidText() {
        PasswordCryptoService service = createService();

        Assertions.assertThrows(RuntimeException.class, () -> service.decrypt("INVALIDE"));
    }
}