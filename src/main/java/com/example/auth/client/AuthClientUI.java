package com.example.auth.client;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * Interface JavaFX moderne pour tester les APIs du TP_4.
 *
 * Fonctionnalites :
 * - register
 * - login
 * - me
 * - logout
 * - client-proof HMAC
 * - rejeu du meme nonce
 * - login invalide
 * - doublon email
 *
 * Validation mot de passe TP_3 :
 * - au moins 12 caracteres
 * - au moins une majuscule
 * - au moins une minuscule
 * - au moins un chiffre
 * - au moins un caractere special
 *
 * @author Poun
 * @version 4.0
 */
public class AuthClientUI extends Application {

    /**
     * URL de base de l'API.
     */
    private static final String BASE_URL = "http://127.0.0.1:8000/api/auth";

    /**
     * Secret HMAC de demonstration.
     */
    private static final String HMAC_SECRET = "secret";

    private TextField nameField;
    private TextField emailField;
    private PasswordField passwordField;
    private TextField nonceField;
    private TextField timestampField;
    private TextField hmacField;

    private TextArea resultArea;
    private Label statusLabel;

    private String currentToken;
    private String lastClientProofNonce;
    private long lastClientProofTimestamp;
    private String lastClientProofHmac;

    @Override
    public void start(Stage stage) {
        stage.setTitle("TP_4 - Auth UI Moderne");

        Label titleLabel = new Label("TP_4 - Interface de test des APIs");
        Label helpLabel = new Label(
                "Mot de passe TP_3 : 12+ caracteres, majuscule, minuscule, chiffre, caractere special."
        );

        titleLabel.setStyle("-fx-font-size: 24px; -fx-font-weight: bold; -fx-text-fill: white;");
        helpLabel.setStyle("-fx-text-fill: #bbbbbb; -fx-font-size: 12px;");

        nameField = new TextField();
        emailField = new TextField();
        passwordField = new PasswordField();
        nonceField = new TextField();
        timestampField = new TextField();
        hmacField = new TextField();

        nameField.setPromptText("Nom");
        emailField.setPromptText("Email");
        passwordField.setPromptText("Mot de passe");
        nonceField.setPromptText("Nonce auto si vide");
        timestampField.setPromptText("Timestamp auto si vide");
        hmacField.setPromptText("HMAC auto si vide");

        String fieldStyle =
                "-fx-background-color: #1e1e1e;" +
                        "-fx-text-fill: white;" +
                        "-fx-prompt-text-fill: #9aa0a6;" +
                        "-fx-border-color: #30363d;" +
                        "-fx-border-radius: 8;" +
                        "-fx-background-radius: 8;" +
                        "-fx-padding: 8;";

        nameField.setStyle(fieldStyle);
        emailField.setStyle(fieldStyle);
        passwordField.setStyle(fieldStyle);
        nonceField.setStyle(fieldStyle);
        timestampField.setStyle(fieldStyle);
        hmacField.setStyle(fieldStyle);

        GridPane formGrid = new GridPane();
        formGrid.setHgap(12);
        formGrid.setVgap(12);

        formGrid.add(createLabel("Nom"), 0, 0);
        formGrid.add(nameField, 1, 0);

        formGrid.add(createLabel("Email"), 0, 1);
        formGrid.add(emailField, 1, 1);

        formGrid.add(createLabel("Mot de passe"), 0, 2);
        formGrid.add(passwordField, 1, 2);

        formGrid.add(createLabel("Nonce"), 0, 3);
        formGrid.add(nonceField, 1, 3);

        formGrid.add(createLabel("Timestamp"), 0, 4);
        formGrid.add(timestampField, 1, 4);

        formGrid.add(createLabel("HMAC"), 0, 5);
        formGrid.add(hmacField, 1, 5);

        ColumnConstraints c1 = new ColumnConstraints();
        c1.setMinWidth(130);
        ColumnConstraints c2 = new ColumnConstraints();
        c2.setHgrow(Priority.ALWAYS);
        formGrid.getColumnConstraints().addAll(c1, c2);

        Button registerButton = new Button("Register");
        Button loginButton = new Button("Login");
        Button meButton = new Button("Me");
        Button logoutButton = new Button("Logout");
        Button generateHmacButton = new Button("Generer HMAC");
        Button clientProofButton = new Button("Client Proof");
        Button replayButton = new Button("Rejouer Nonce");
        Button badLoginButton = new Button("Login invalide");
        Button duplicateButton = new Button("Doublon email");
        Button clearButton = new Button("Clear");

        styleButton(registerButton, "#238636");
        styleButton(loginButton, "#1f6feb");
        styleButton(meButton, "#1f6feb");
        styleButton(logoutButton, "#da3633");
        styleButton(generateHmacButton, "#8957e5");
        styleButton(clientProofButton, "#1f6feb");
        styleButton(replayButton, "#d29922");
        styleButton(badLoginButton, "#da3633");
        styleButton(duplicateButton, "#d29922");
        styleButton(clearButton, "#6e7681");

        registerButton.setOnAction(e -> handleRegister());
        loginButton.setOnAction(e -> handleLogin());
        meButton.setOnAction(e -> handleMe());
        logoutButton.setOnAction(e -> handleLogout());
        generateHmacButton.setOnAction(e -> generateHmacInFields());
        clientProofButton.setOnAction(e -> handleClientProof());
        replayButton.setOnAction(e -> handleReplayNonce());
        badLoginButton.setOnAction(e -> handleBadLogin());
        duplicateButton.setOnAction(e -> handleDuplicateRegister());
        clearButton.setOnAction(e -> clearFields());

        FlowPane buttonPane = new FlowPane();
        buttonPane.setHgap(10);
        buttonPane.setVgap(10);
        buttonPane.getChildren().addAll(
                registerButton, loginButton, meButton, logoutButton,
                generateHmacButton, clientProofButton, replayButton,
                badLoginButton, duplicateButton, clearButton
        );

        statusLabel = new Label("Pret.");
        statusLabel.setStyle("-fx-text-fill: #58a6ff; -fx-font-size: 13px; -fx-font-weight: bold;");

        resultArea = new TextArea();
        resultArea.setEditable(false);
        resultArea.setWrapText(true);
        resultArea.setPrefHeight(330);
        resultArea.setStyle(
                "-fx-control-inner-background: #0d1117;" +
                        "-fx-text-fill: #7ee787;" +
                        "-fx-font-family: 'Consolas';" +
                        "-fx-font-size: 13px;" +
                        "-fx-border-color: #30363d;" +
                        "-fx-border-radius: 8;" +
                        "-fx-background-radius: 8;"
        );

        VBox root = new VBox(16);
        root.setPadding(new Insets(20));
        root.getChildren().addAll(titleLabel, helpLabel, formGrid, buttonPane, statusLabel, resultArea);
        root.setStyle("-fx-background-color: linear-gradient(to bottom, #0d1117, #161b22);");

        Scene scene = new Scene(root, 1020, 780);
        stage.setScene(scene);
        stage.show();
    }

    /**
     * Cree un label stylise.
     */
    private Label createLabel(String text) {
        Label label = new Label(text + " :");
        label.setStyle("-fx-text-fill: white; -fx-font-size: 13px; -fx-font-weight: bold;");
        return label;
    }

    /**
     * Applique un style dark moderne a un bouton.
     */
    private void styleButton(Button button, String color) {
        button.setPrefWidth(150);
        button.setStyle(
                "-fx-background-color: " + color + ";" +
                        "-fx-text-fill: white;" +
                        "-fx-font-weight: bold;" +
                        "-fx-background-radius: 8;" +
                        "-fx-cursor: hand;"
        );

        button.setOnMouseEntered(e -> button.setOpacity(0.85));
        button.setOnMouseExited(e -> button.setOpacity(1.0));
    }

    /**
     * Register.
     */
    private void handleRegister() {
        String name = nameField.getText().trim();
        String email = emailField.getText().trim();
        String password = passwordField.getText();

        if (name.isEmpty() || email.isEmpty() || password.isEmpty()) {
            showMessage("REGISTER", "Veuillez remplir nom, email et mot de passe.");
            return;
        }

        if (!isPasswordValid(password)) {
            showMessage("REGISTER",
                    "Mot de passe invalide.\n" +
                            "Il faut au moins 12 caracteres, une majuscule, une minuscule, un chiffre et un caractere special.");
            return;
        }

        String body = "{"
                + "\"name\":\"" + escapeJson(name) + "\","
                + "\"email\":\"" + escapeJson(email) + "\","
                + "\"password\":\"" + escapeJson(password) + "\""
                + "}";

        sendRequest("POST", "/register", body, null, "REGISTER");
    }

    /**
     * Login.
     */
    private void handleLogin() {
        String email = emailField.getText().trim();
        String password = passwordField.getText();

        if (email.isEmpty() || password.isEmpty()) {
            showMessage("LOGIN", "Veuillez remplir email et mot de passe.");
            return;
        }

        String body = "{"
                + "\"email\":\"" + escapeJson(email) + "\","
                + "\"password\":\"" + escapeJson(password) + "\""
                + "}";

        String response = sendRequest("POST", "/login", body, null, "LOGIN");

        if (response != null) {
            String token = extractJsonValue(response, "token");
            if (token != null && !token.isEmpty()) {
                currentToken = token;
                statusLabel.setText("Token login recupere.");
            }
        }
    }

    /**
     * /me.
     */
    private void handleMe() {
        if (currentToken == null || currentToken.isEmpty()) {
            showMessage("ME", "Aucun token disponible. Faites un login ou un client-proof.");
            return;
        }

        sendRequest("GET", "/me", null, currentToken, "ME");
    }

    /**
     * Logout.
     */
    private void handleLogout() {
        if (currentToken == null || currentToken.isEmpty()) {
            showMessage("LOGOUT", "Aucun token disponible.");
            return;
        }

        String response = sendRequest("POST", "/logout", null, currentToken, "LOGOUT");

        if (response != null && response.contains("Deconnexion reussie")) {
            currentToken = null;
            statusLabel.setText("Logout effectue, token local vide.");
        }
    }

    /**
     * Generation HMAC automatique.
     */
    private void generateHmacInFields() {
        String email = emailField.getText().trim();

        if (email.isEmpty()) {
            showMessage("HMAC", "Veuillez remplir l'email.");
            return;
        }

        String nonce = nonceField.getText().trim();
        if (nonce.isEmpty()) {
            nonce = generateNonce();
            nonceField.setText(nonce);
        }

        long timestamp;
        if (timestampField.getText().trim().isEmpty()) {
            timestamp = Instant.now().getEpochSecond();
            timestampField.setText(String.valueOf(timestamp));
        } else {
            try {
                timestamp = Long.parseLong(timestampField.getText().trim());
            } catch (NumberFormatException e) {
                showMessage("HMAC", "Timestamp invalide.");
                return;
            }
        }

        String message = buildMessage(email, nonce, timestamp);
        String hmac = computeHmac(HMAC_SECRET, message);
        hmacField.setText(hmac);

        showMessage("GENERER HMAC",
                "Message : " + message + "\n\n" +
                        "Secret : " + HMAC_SECRET + "\n\n" +
                        "HMAC Base64 : " + hmac);
    }

    /**
     * Client Proof.
     */
    private void handleClientProof() {
        String email = emailField.getText().trim();

        if (email.isEmpty()) {
            showMessage("CLIENT PROOF", "Veuillez remplir l'email.");
            return;
        }

        String nonce = nonceField.getText().trim();
        if (nonce.isEmpty()) {
            nonce = generateNonce();
            nonceField.setText(nonce);
        }

        long timestamp;
        if (timestampField.getText().trim().isEmpty()) {
            timestamp = Instant.now().getEpochSecond();
            timestampField.setText(String.valueOf(timestamp));
        } else {
            try {
                timestamp = Long.parseLong(timestampField.getText().trim());
            } catch (NumberFormatException e) {
                showMessage("CLIENT PROOF", "Timestamp invalide.");
                return;
            }
        }

        String hmac = hmacField.getText().trim();
        if (hmac.isEmpty()) {
            hmac = computeHmac(HMAC_SECRET, buildMessage(email, nonce, timestamp));
            hmacField.setText(hmac);
        }

        lastClientProofNonce = nonce;
        lastClientProofTimestamp = timestamp;
        lastClientProofHmac = hmac;

        String body = "{"
                + "\"email\":\"" + escapeJson(email) + "\","
                + "\"nonce\":\"" + escapeJson(nonce) + "\","
                + "\"timestamp\":" + timestamp + ","
                + "\"hmac\":\"" + escapeJson(hmac) + "\""
                + "}";

        String response = sendRequest("POST", "/client-proof", body, null, "CLIENT PROOF");

        if (response != null) {
            String token = extractJsonValue(response, "token");
            if (token != null && !token.isEmpty()) {
                currentToken = token;
                statusLabel.setText("Token client-proof recupere.");
            }
        }
    }

    /**
     * Rejeu du meme nonce.
     */
    private void handleReplayNonce() {
        String email = emailField.getText().trim();

        if (email.isEmpty() || lastClientProofNonce == null || lastClientProofHmac == null) {
            showMessage("REPLAY NONCE", "Faites d'abord un client-proof valide.");
            return;
        }

        String body = "{"
                + "\"email\":\"" + escapeJson(email) + "\","
                + "\"nonce\":\"" + escapeJson(lastClientProofNonce) + "\","
                + "\"timestamp\":" + lastClientProofTimestamp + ","
                + "\"hmac\":\"" + escapeJson(lastClientProofHmac) + "\""
                + "}";

        sendRequest("POST", "/client-proof", body, null, "REPLAY NONCE");
    }

    /**
     * Login invalide.
     */
    private void handleBadLogin() {
        String email = emailField.getText().trim();

        if (email.isEmpty()) {
            showMessage("LOGIN INVALIDE", "Veuillez remplir l'email.");
            return;
        }

        String body = "{"
                + "\"email\":\"" + escapeJson(email) + "\","
                + "\"password\":\"FAUX_PASSWORD_123!\""
                + "}";

        sendRequest("POST", "/login", body, null, "LOGIN INVALIDE");
    }

    /**
     * Register doublon.
     */
    private void handleDuplicateRegister() {
        String name = nameField.getText().trim();
        String email = emailField.getText().trim();
        String password = passwordField.getText();

        if (name.isEmpty() || email.isEmpty() || password.isEmpty()) {
            showMessage("DOUBLON EMAIL", "Veuillez remplir nom, email et mot de passe.");
            return;
        }

        String body = "{"
                + "\"name\":\"" + escapeJson(name) + "\","
                + "\"email\":\"" + escapeJson(email) + "\","
                + "\"password\":\"" + escapeJson(password) + "\""
                + "}";

        sendRequest("POST", "/register", body, null, "DOUBLON EMAIL");
    }

    /**
     * Clear.
     */
    private void clearFields() {
        nameField.clear();
        emailField.clear();
        passwordField.clear();
        nonceField.clear();
        timestampField.clear();
        hmacField.clear();
        resultArea.clear();
        currentToken = null;
        lastClientProofNonce = null;
        lastClientProofHmac = null;
        lastClientProofTimestamp = 0L;
        statusLabel.setText("Pret.");
    }

    /**
     * Envoi HTTP.
     */
    private String sendRequest(String method, String endpoint, String body, String token, String title) {
        HttpURLConnection connection = null;

        try {
            URL url = new URL(BASE_URL + endpoint);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod(method);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Accept", "application/json");

            if (token != null && !token.isEmpty()) {
                connection.setRequestProperty("Authorization", "Bearer " + token);
            }

            if (body != null) {
                connection.setDoOutput(true);
                try (OutputStream os = connection.getOutputStream()) {
                    os.write(body.getBytes(StandardCharsets.UTF_8));
                }
            }

            int statusCode = connection.getResponseCode();
            InputStream stream = statusCode >= 400 ? connection.getErrorStream() : connection.getInputStream();
            String response = readStream(stream);

            resultArea.setText(
                    "===== " + title + " =====\n" +
                            "URL : " + BASE_URL + endpoint + "\n" +
                            "Methode : " + method + "\n\n" +
                            "Request body :\n" + (body == null ? "(vide)" : body) + "\n\n" +
                            "Status : " + statusCode + "\n\n" +
                            "Response :\n" + response
            );

            statusLabel.setText(title + " : " + statusCode);
            return response;

        } catch (Exception e) {
            resultArea.setText(
                    "===== " + title + " =====\n" +
                            "Erreur technique : " + e.getMessage()
            );
            statusLabel.setText(title + " : erreur");
            return null;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * Lecture stream.
     */
    private String readStream(InputStream stream) throws Exception {
        if (stream == null) {
            return "";
        }

        StringBuilder builder = new StringBuilder();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                builder.append(line).append("\n");
            }
        }

        return builder.toString().trim();
    }

    /**
     * Message HMAC.
     */
    private String buildMessage(String email, String nonce, long timestamp) {
        return email + ":" + nonce + ":" + timestamp;
    }

    /**
     * Calcul HMAC Base64.
     */
    private String computeHmac(String secret, String message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec key = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(key);
            byte[] raw = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(raw);
        } catch (Exception e) {
            throw new RuntimeException("Erreur HMAC", e);
        }
    }

    /**
     * Nonce simple.
     */
    private String generateNonce() {
        return "nonce-" + UUID.randomUUID().toString().substring(0, 8);
    }

    /**
     * Validation mot de passe TP_3.
     */
    private boolean isPasswordValid(String password) {
        if (password == null || password.length() < 12) {
            return false;
        }

        boolean hasUppercase = password.matches(".*[A-Z].*");
        boolean hasLowercase = password.matches(".*[a-z].*");
        boolean hasDigit = password.matches(".*\\d.*");
        boolean hasSpecial = password.matches(".*[^a-zA-Z0-9].*");

        return hasUppercase && hasLowercase && hasDigit && hasSpecial;
    }

    /**
     * Affichage simple.
     */
    private void showMessage(String title, String content) {
        resultArea.setText("===== " + title + " =====\n" + content);
        statusLabel.setText(title);
    }

    /**
     * Echappement JSON.
     */
    private String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /**
     * Extraction simple d'une valeur JSON string.
     */
    private String extractJsonValue(String json, String key) {
        String pattern = "\"" + key + "\"";
        int keyIndex = json.indexOf(pattern);

        if (keyIndex == -1) {
            return null;
        }

        int colonIndex = json.indexOf(":", keyIndex);
        if (colonIndex == -1) {
            return null;
        }

        int firstQuote = json.indexOf("\"", colonIndex + 1);
        if (firstQuote == -1) {
            return null;
        }

        int secondQuote = json.indexOf("\"", firstQuote + 1);
        if (secondQuote == -1) {
            return null;
        }

        return json.substring(firstQuote + 1, secondQuote);
    }

    public static void main(String[] args) {
        launch(args);
    }
}