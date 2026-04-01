package com.example.auth.service;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires de PasswordCryptoService.
 *
 * @author Poun
 * @version 1.0
 */
public class PasswordCryptoServiceTest {

    /**
     * Cree un service initialise avec une cle simple.
     *
     * @return service pret a etre utilise
     * @throws Exception si erreur reflection
     */
    private PasswordCryptoService createService() throws Exception {
        PasswordCryptoService service = new PasswordCryptoService();

        Field field = PasswordCryptoService.class.getDeclaredField("serverMasterKey");
        field.setAccessible(true);
        field.set(service, "tp3-secret-smk-2026");

        service.init();
        return service;
    }

    @Test
    void testEncryptAndDecrypt() throws Exception {
        PasswordCryptoService service = createService();

        String plainText = "MonMotDePasse123!";
        String encrypted = service.encrypt(plainText);
        String decrypted = service.decrypt(encrypted);

        assertNotNull(encrypted);
        assertNotEquals(plainText, encrypted);
        assertEquals(plainText, decrypted);
    }

    @Test
    void testEncryptWithEmptyText() throws Exception {
        PasswordCryptoService service = createService();

        String encrypted = service.encrypt("");
        String decrypted = service.decrypt(encrypted);

        assertNotNull(encrypted);
        assertEquals("", decrypted);
    }


    @Test
    void testDecryptInvalidBase64() throws Exception {
        PasswordCryptoService service = createService();

        assertThrows(Exception.class, () -> {
            service.decrypt("%%%texte-invalide%%%");
        });
    }
    @Test
    void testInitWithShortKey() throws Exception {
        PasswordCryptoService service = new PasswordCryptoService();

        Field field = PasswordCryptoService.class.getDeclaredField("serverMasterKey");
        field.setAccessible(true);
        field.set(service, "abc");

        assertDoesNotThrow(service::init);

        String encrypted = service.encrypt("bonjour");
        String decrypted = service.decrypt(encrypted);

        assertEquals("bonjour", decrypted);
    }

    @Test
    void testInitWithLongKey() throws Exception {
        PasswordCryptoService service = new PasswordCryptoService();

        Field field = PasswordCryptoService.class.getDeclaredField("serverMasterKey");
        field.setAccessible(true);
        field.set(service, "cle-super-longue-pour-faire-le-test-123456");

        assertDoesNotThrow(service::init);

        String encrypted = service.encrypt("testLongKey");
        String decrypted = service.decrypt(encrypted);

        assertEquals("testLongKey", decrypted);
    }
}