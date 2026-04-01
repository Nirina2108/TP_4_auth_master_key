package com.example.auth.validator;

/**
 * Validateur simple de politique de mot de passe.
 *
 * Règles actuellement appliquées dans ce code :
 * - au moins 8 caractères
 * - au moins une majuscule
 * - au moins une minuscule
 * - au moins un chiffre
 * - au moins un caractère spécial
 *
 * @author Poun
 * @version 2.2
 */
public class PasswordPolicyValidator {

    /**
     * Longueur minimale réellement appliquée par ce validateur.
     */
    private static final int MIN_LENGTH = 8;

    /**
     * Vérifie si le mot de passe respecte les règles de sécurité.
     *
     * @param password mot de passe
     * @return true si valide, sinon false
     */
    public boolean isValid(String password) {

        if (password == null) {
            return false;
        }

        if (password.length() < MIN_LENGTH) {
            return false;
        }

        if (!password.matches(".*[A-Z].*")) {
            return false;
        }

        if (!password.matches(".*[a-z].*")) {
            return false;
        }

        if (!password.matches(".*[0-9].*")) {
            return false;
        }

        if (!password.matches(".*[!@#$%^&*()].*")) {
            return false;
        }

        return true;
    }

    /**
     * Retourne un message simple expliquant la règle.
     *
     * @return message de validation
     */
    public String getRulesMessage() {
        return "Le mot de passe doit contenir au moins 8 caractères, une majuscule, une minuscule, un chiffre et un caractère spécial.";
    }
}