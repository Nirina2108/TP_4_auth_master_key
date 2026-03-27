package com.example.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.LocalDateTime;

/**
 * Entité représentant un utilisateur.
 *
 * TP4 :
 * - le mot de passe n'est jamais stocké en clair
 * - le mot de passe est stocké sous forme chiffrée
 * - le champ passwordEncrypted contient la valeur protégée
 * - le token reste utilisé pour les routes protegees comme /api/me
 *
 * Cette entité reste simple pour un usage pédagogique.
 *
 * @author Poun
 * @version 4.0
 */
@Entity
@Table(name = "users")
public class User {

    /**
     * Identifiant unique de l'utilisateur.
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
     * Email unique de l'utilisateur.
     */
    @Column(nullable = false, unique = true)
    private String email;

    /**
     * Mot de passe chiffré.
     *
     * La valeur stockée ici est produite par le CryptoService
     * avec la Master Key du TP4.
     */
    @Column(name = "password_encrypted", nullable = false, length = 500)
    private String passwordEncrypted;

    /**
     * Token d'authentification utilisé pour les appels protégés.
     */
    @Column(length = 255)
    private String token;

    /**
     * Date d'expiration du token.
     */
    @Column(name = "token_expires_at")
    private LocalDateTime tokenExpiresAt;

    /**
     * Date de création du compte.
     */
    @Column(name = "created_at")
    private LocalDateTime createdAt;

    /**
     * Constructeur vide.
     */
    public User() {
    }

    /**
     * Retourne l'identifiant.
     *
     * @return id utilisateur
     */
    public Long getId() {
        return id;
    }

    /**
     * Modifie l'identifiant.
     *
     * @param id nouvel identifiant
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * Retourne le nom.
     *
     * @return nom utilisateur
     */
    public String getName() {
        return name;
    }

    /**
     * Modifie le nom.
     *
     * @param name nouveau nom
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Retourne l'email.
     *
     * @return email utilisateur
     */
    public String getEmail() {
        return email;
    }

    /**
     * Modifie l'email.
     *
     * @param email nouvel email
     */
    public void setEmail(String email) {
        this.email = email;
    }

    /**
     * Retourne le mot de passe chiffré.
     *
     * @return mot de passe chiffré
     */
    public String getPasswordEncrypted() {
        return passwordEncrypted;
    }

    /**
     * Modifie le mot de passe chiffré.
     *
     * @param passwordEncrypted nouvelle valeur chiffrée
     */
    public void setPasswordEncrypted(String passwordEncrypted) {
        this.passwordEncrypted = passwordEncrypted;
    }

    /**
     * Retourne le token.
     *
     * @return token utilisateur
     */
    public String getToken() {
        return token;
    }

    /**
     * Modifie le token.
     *
     * @param token nouveau token
     */
    public void setToken(String token) {
        this.token = token;
    }

    /**
     * Retourne la date d'expiration du token.
     *
     * @return date d'expiration
     */
    public LocalDateTime getTokenExpiresAt() {
        return tokenExpiresAt;
    }

    /**
     * Modifie la date d'expiration du token.
     *
     * @param tokenExpiresAt nouvelle date d'expiration
     */
    public void setTokenExpiresAt(LocalDateTime tokenExpiresAt) {
        this.tokenExpiresAt = tokenExpiresAt;
    }

    /**
     * Retourne la date de création.
     *
     * @return date de création
     */
    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    /**
     * Modifie la date de création.
     *
     * @param createdAt nouvelle date
     */
    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}