package com.example.auth.repository;

import com.example.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Repository pour les utilisateurs.
 *
 * @author Poun
 * @version 4.0
 */
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Recherche un utilisateur par email.
     *
     * @param email email de l'utilisateur
     * @return utilisateur trouve ou vide
     */
    Optional<User> findByEmail(String email);

    /**
     * Recherche un utilisateur par token.
     *
     * @param token token de session
     * @return utilisateur trouve ou vide
     */
    Optional<User> findByToken(String token);

    /**
     * Verifie si un email existe deja.
     *
     * @param email email
     * @return true si existe
     */
    boolean existsByEmail(String email);
}