package com.example.auth.service;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Tests du service CryptoService.
 *
 * @author Poun
 * @version 4.0
 */
public class CryptoServiceTest {

    /**
     * Construit un service prêt à être utilisé.
     *
     * @return service initialisé
     */
    private CryptoService createService() {
        CryptoService service = new CryptoService();
        ReflectionTestUtils.setField(service, "masterKey", "test-master-key-tp4");
        service.init();
        return service;
    }

    /**
     * Vérifie qu'un texte chiffré peut être déchiffré.
     */
    @Test
    void testEncryptDecryptSuccess() {
        CryptoService service = createService();

        String plainText = "bonjour";
        String encrypted = service.encrypt(plainText);
        String decrypted = service.decrypt(encrypted);

        Assertions.assertNotNull(encrypted);
        Assertions.assertNotEquals(plainText, encrypted);
        Assertions.assertEquals(plainText, decrypted);
    }

    /**
     * Vérifie qu'un texte null provoque une erreur.
     */
    @Test
    void testEncryptWithNullText() {
        CryptoService service = createService();

        Assertions.assertThrows(IllegalStateException.class, () -> service.encrypt(null));
    }

    /**
     * Vérifie qu'un texte vide provoque une erreur au déchiffrement.
     */
    @Test
    void testDecryptWithBlankText() {
        CryptoService service = createService();

        Assertions.assertThrows(IllegalStateException.class, () -> service.decrypt(""));
    }

    /**
     * Vérifie qu'un mauvais format provoque une erreur.
     */
    @Test
    void testDecryptWithInvalidFormat() {
        CryptoService service = createService();

        Assertions.assertThrows(IllegalStateException.class, () -> service.decrypt("invalide"));
    }

    /**
     * Vérifie qu'une mauvaise version provoque une erreur.
     */
    @Test
    void testDecryptWithInvalidVersion() {
        CryptoService service = createService();

        String invalidText = "v2:abc:def";

        Assertions.assertThrows(IllegalStateException.class, () -> service.decrypt(invalidText));
    }
}