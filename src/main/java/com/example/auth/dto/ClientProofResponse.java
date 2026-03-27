package com.example.auth.dto;

/**
 * DTO reponse apres verification HMAC.
 */
public class ClientProofResponse {

    private String message;
    private String token;

    public ClientProofResponse() {
    }

    public ClientProofResponse(String message, String token) {
        this.message = message;
        this.token = token;
    }

    public String getMessage() {
        return message;
    }

    public String getToken() {
        return token;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public void setToken(String token) {
        this.token = token;
    }
}