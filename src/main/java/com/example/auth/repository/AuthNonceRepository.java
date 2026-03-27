package com.example.auth.repository;

import com.example.auth.entity.AuthNonce;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Repository pour la gestion des nonces.
 *
 * @author Poun
 * @version 4.0
 */
public interface AuthNonceRepository extends JpaRepository<AuthNonce, Long> {

    /**
     * Recherche un nonce par sa valeur.
     *
     * @param nonce valeur du nonce
     * @return nonce trouve ou vide
     */
    Optional<AuthNonce> findByNonce(String nonce);

    /**
     * Verifie si un nonce existe deja.
     *
     * @param nonce valeur du nonce
     * @return true si existe, sinon false
     */
    boolean existsByNonce(String nonce);
}