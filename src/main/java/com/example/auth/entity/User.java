package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Entite representant un utilisateur.
 *
 * Cette classe stocke les informations principales
 * d'un utilisateur authentifie dans l'application.
 *
 * @author Poun
 * @version 4.0
 */
@Entity
@Table(name = "users")
public class User {

    /**
     * Identifiant unique.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Nom de l'utilisateur.
     */
    @Column(nullable = false)
    private String name;

    /**
     * Email unique.
     */
    @Column(nullable = false, unique = true)
    private String email;

    /**
     * Mot de passe ou hash du mot de passe.
     */
    @Column(name = "password_hash", nullable = false)
    private String password;

    /**
     * Token de session.
     */
    @Column(length = 500)
    private String token;

    /**
     * Date de creation.
     */
    private LocalDateTime createdAt;

    /**
     * Liste des nonces lies a cet utilisateur.
     *
     * Cascade ALL :
     * si on supprime un user, ses nonces seront aussi supprimes.
     */
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<AuthNonce> nonces = new ArrayList<>();

    /**
     * Constructeur par defaut.
     */
    public User() {
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

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    /**
     * Garde le nom setPassword pour ne rien casser
     * meme si la colonne en base s'appelle password_hash.
     */
    public void setPassword(String password) {
        this.password = password;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public List<AuthNonce> getNonces() {
        return nonces;
    }

    public void setNonces(List<AuthNonce> nonces) {
        this.nonces = nonces;
    }
}