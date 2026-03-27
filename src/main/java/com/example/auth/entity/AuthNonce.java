package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entite representant un nonce utilise pour proteger
 * le systeme contre les attaques par rejeu.
 *
 * Un nonce est une valeur unique utilisee une seule fois.
 *
 * @author Poun
 * @version 4.0
 */
@Entity
@Table(name = "auth_nonce")
public class AuthNonce {

    /**
     * Identifiant unique du nonce.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Valeur du nonce.
     */
    @Column(nullable = false, unique = true)
    private String nonce;

    /**
     * Date de creation.
     */
    private LocalDateTime createdAt;

    /**
     * Utilisateur lie a ce nonce.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /**
     * Constructeur par defaut.
     */
    public AuthNonce() {
    }

    /**
     * Initialisation avant insertion.
     */
    @PrePersist
    public void prePersist() {
        createdAt = LocalDateTime.now();
    }

    public Long getId() {
        return id;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}