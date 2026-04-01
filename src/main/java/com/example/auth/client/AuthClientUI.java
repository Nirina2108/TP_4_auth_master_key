package com.example.auth.client;

import com.example.auth.validator.PasswordStrengthUtil;
import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.Separator;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

/**
 * Interface JavaFX simple pour tester l'authentification.
 *
 * @author Poun
 * @version 2.5
 */
public class AuthClientUI extends Application {

    private static final String STYLE_TITLE = "-fx-font-size: 20px; -fx-font-weight: bold;";
    private static final String STYLE_SECTION_TITLE = "-fx-font-size: 16px; -fx-font-weight: bold;";
    private static final String STYLE_ERROR = "-fx-text-fill: red;";
    private static final String STYLE_SUCCESS = "-fx-text-fill: green;";
    private static final String STYLE_WARNING_BOLD = "-fx-text-fill: orange; -fx-font-weight: bold;";
    private static final String STYLE_SUCCESS_BOLD = "-fx-text-fill: green; -fx-font-weight: bold;";
    private static final String STYLE_ERROR_BOLD = "-fx-text-fill: red; -fx-font-weight: bold;";

    private TextField registerNameField;
    private TextField registerEmailField;
    private PasswordField registerPasswordField;
    private PasswordField registerConfirmPasswordField;
    private Label passwordStatusLabel;
    private Label registerMessageLabel;

    private TextField loginEmailField;
    private PasswordField loginPasswordField;
    private Label loginMessageLabel;

    private final PasswordStrengthUtil passwordStrengthUtil = new PasswordStrengthUtil();

    @Override
    public void start(Stage stage) {
        Label titleLabel = new Label("TP2 - Authentification fragile");
        titleLabel.setStyle(STYLE_TITLE);

        Label registerTitle = new Label("Inscription");
        registerTitle.setStyle(STYLE_SECTION_TITLE);

        registerNameField = new TextField();
        registerNameField.setPromptText("Nom");

        registerEmailField = new TextField();
        registerEmailField.setPromptText("Email");

        registerPasswordField = new PasswordField();
        registerPasswordField.setPromptText("Mot de passe");

        registerConfirmPasswordField = new PasswordField();
        registerConfirmPasswordField.setPromptText("Confirmer le mot de passe");

        passwordStatusLabel = new Label("Saisissez un mot de passe");
        passwordStatusLabel.setStyle(STYLE_ERROR_BOLD);

        registerMessageLabel = new Label();

        Button registerButton = new Button("S'inscrire");
        registerButton.setMaxWidth(Double.MAX_VALUE);
        registerButton.setOnAction(event -> handleRegister());

        registerPasswordField.textProperty().addListener((observable, oldValue, newValue) -> updatePasswordIndicator());
        registerConfirmPasswordField.textProperty().addListener((observable, oldValue, newValue) -> updatePasswordIndicator());

        Label loginTitle = new Label("Connexion");
        loginTitle.setStyle(STYLE_SECTION_TITLE);

        loginEmailField = new TextField();
        loginEmailField.setPromptText("Email");

        loginPasswordField = new PasswordField();
        loginPasswordField.setPromptText("Mot de passe");

        loginMessageLabel = new Label();

        Button loginButton = new Button("Se connecter");
        loginButton.setMaxWidth(Double.MAX_VALUE);
        loginButton.setOnAction(event -> handleLogin());

        VBox root = new VBox(10);
        root.setPadding(new Insets(20));
        root.setAlignment(Pos.TOP_CENTER);

        root.getChildren().addAll(
                titleLabel,
                new Separator(),

                registerTitle,
                registerNameField,
                registerEmailField,
                registerPasswordField,
                registerConfirmPasswordField,
                passwordStatusLabel,
                registerButton,
                registerMessageLabel,

                new Separator(),

                loginTitle,
                loginEmailField,
                loginPasswordField,
                loginButton,
                loginMessageLabel
        );

        Scene scene = new Scene(root, 420, 520);

        stage.setTitle("TP2 Auth Client");
        stage.setScene(scene);
        stage.show();
    }

    private void updatePasswordIndicator() {
        String password = registerPasswordField.getText();
        String confirmPassword = registerConfirmPasswordField.getText();

        String level = passwordStrengthUtil.evaluate(password);
        String message = passwordStrengthUtil.getMessage(password, confirmPassword);

        passwordStatusLabel.setText(message);

        if (!passwordStrengthUtil.isPolicyValid(password)) {
            passwordStatusLabel.setStyle(STYLE_ERROR_BOLD);
            return;
        }

        if (!passwordStrengthUtil.passwordsMatch(password, confirmPassword)) {
            passwordStatusLabel.setStyle(STYLE_ERROR_BOLD);
            return;
        }

        if (PasswordStrengthUtil.GREEN.equals(level)) {
            passwordStatusLabel.setStyle(STYLE_SUCCESS_BOLD);
        } else {
            passwordStatusLabel.setStyle(STYLE_WARNING_BOLD);
        }
    }

    private void handleRegister() {
        String name = registerNameField.getText();
        String email = registerEmailField.getText();
        String password = registerPasswordField.getText();
        String confirmPassword = registerConfirmPasswordField.getText();

        if (name == null || name.isBlank()) {
            registerMessageLabel.setText("Le nom est obligatoire.");
            registerMessageLabel.setStyle(STYLE_ERROR);
            return;
        }

        if (email == null || email.isBlank()) {
            registerMessageLabel.setText("L'email est obligatoire.");
            registerMessageLabel.setStyle(STYLE_ERROR);
            return;
        }

        if (!passwordStrengthUtil.isPolicyValid(password)) {
            registerMessageLabel.setText("Le mot de passe ne respecte pas les règles.");
            registerMessageLabel.setStyle(STYLE_ERROR);
            return;
        }

        if (!passwordStrengthUtil.passwordsMatch(password, confirmPassword)) {
            registerMessageLabel.setText("La confirmation du mot de passe est différente.");
            registerMessageLabel.setStyle(STYLE_ERROR);
            return;
        }

        registerMessageLabel.setText("Formulaire valide. Inscription prête à être envoyée.");
        registerMessageLabel.setStyle(STYLE_SUCCESS);
    }

    private void handleLogin() {
        String email = loginEmailField.getText();
        String password = loginPasswordField.getText();

        if (email == null || email.isBlank()) {
            loginMessageLabel.setText("L'email est obligatoire.");
            loginMessageLabel.setStyle(STYLE_ERROR);
            return;
        }

        if (password == null || password.isBlank()) {
            loginMessageLabel.setText("Le mot de passe est obligatoire.");
            loginMessageLabel.setStyle(STYLE_ERROR);
            return;
        }

        loginMessageLabel.setText("Connexion prête à être envoyée.");
        loginMessageLabel.setStyle(STYLE_SUCCESS);
    }

    public static void main(String[] args) {
        launch(args);
    }
}