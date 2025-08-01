package br.com.travelex.cognito.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.travelex.cognito.exception.AuthenticationException;
import br.com.travelex.cognito.request.ChangePasswordRequest;
import br.com.travelex.cognito.request.ConfirmForgotPasswordRequest;
import br.com.travelex.cognito.request.ForgotPasswordRequest;
import br.com.travelex.cognito.request.LoginRequest;
import br.com.travelex.cognito.request.RefreshTokenRequest;
import br.com.travelex.cognito.response.AuthenticationResponse;
import br.com.travelex.cognito.response.ResetPasswordResponse;
import br.com.travelex.cognito.service.CognitoAuthService;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.DescribeUserPoolResponse;

@RestController
@RequestMapping("/v1/auth")
public class AuthenticationController {

    private final CognitoAuthService cognitoAuthService;

    public AuthenticationController(CognitoAuthService cognitoAuthService) {
        this.cognitoAuthService = cognitoAuthService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            Map<String, String> attributes = new HashMap<>();
            attributes.put("custom:authCookie", "717.388.060-22|ECommerce|20250525.175032457|2760|1747761920143|MCwCFGKTo2rHaC6GF3TOgVzQee3vFbknAhRwLmUZMG6FMt6fk7M6OR4mVaUw0g==");
            cognitoAuthService.updateUserAttributes(request.getUsername(), attributes);

            AuthenticationResponse result = 
                cognitoAuthService.authenticateUser(request.getUsername(), request.getPassword());
            
            // Criar resposta com tokens
            Map<String, Object> response = new HashMap<>();
            response.put("accessToken", result.getAccessToken());
            response.put("idToken", result.getIdToken());
            response.put("refreshToken", result.getRefreshToken());
            response.put("expiresIn", result.getExpiresIn());
            
            return ResponseEntity.ok(response);

        } catch (AuthenticationException e) {
            return ResponseEntity.status(401).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Erro interno: " + e.getMessage()));
        }
    }
    
    @PostMapping("/refresh")
    public ResponseEntity<?> login(@RequestBody RefreshTokenRequest refreshToken,
        @RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            
            String idToken = null;
            // Extrair ID token do header Authorization
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                idToken = authHeader.substring(7); // Remover "Bearer " do início
            }
            AuthenticationResponse result = 
                cognitoAuthService.refreshTokens(refreshToken.getRefreshToken(), idToken);
            
            // Criar resposta com tokens
            Map<String, Object> response = new HashMap<>();
            response.put("accessToken", result.getAccessToken());
            response.put("idToken", result.getIdToken());
            response.put("refreshToken", result.getRefreshToken());
            response.put("expiresIn", result.getExpiresIn());
            
            return ResponseEntity.ok(response);

        } catch (AuthenticationException e) {
            return ResponseEntity.status(401).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Erro interno: " + e.getMessage()));
        }
    }

    
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        try {
            ResetPasswordResponse forgotPassword = cognitoAuthService.forgotPassword(request.getUsername(), request.getEmail(), request.getPhoneNumber());
            return ResponseEntity.ok(forgotPassword);
            //return ResponseEntity.ok(new MessageResponseDto("Código de recuperação enviado para o email cadastrado"));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/confirm-password")
    public ResponseEntity<?> confirmForgotPassword(@RequestBody ConfirmForgotPasswordRequest request) {
        try {
            cognitoAuthService.confirmForgotPassword(
                    request.getUsername(),
                    request.getConfirmationCode(),
                    request.getNewPassword()
            );
            return ResponseEntity.ok("Senha redefinida com sucesso");
            //return ResponseEntity.ok(new MessageResponseDto("Código de recuperação enviado para o email cadastrado"));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest request) {
        try {
            cognitoAuthService.changePassword(
                    request.getAccessToken(),
                    request.getOldPassword(),
                    request.getNewPassword()
            );
            return ResponseEntity.ok("Senha redefinida com sucesso");
            //return ResponseEntity.ok(new MessageResponseDto("Código de recuperação enviado para o email cadastrado"));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/policies")
    public ResponseEntity<String> retrievePasswordPolicies() {

        try {

            // Obter políticas de senha do Cognito
            DescribeUserPoolResponse response = cognitoAuthService.retrievePasswordPolicies();
            var policy = response.userPool().policies().passwordPolicy();

			// to change it: Amazon Cognito > User pools > [User-pool] > Authentication methods > Edit password policy
			StringBuffer sb = new StringBuffer();
            sb.append("Comprimento mínimo: " + policy.minimumLength() + "\n");
            sb.append("Requer letra maiúscula: " + policy.requireUppercase() + "\n");
            sb.append("Requer letra minúscula: " + policy.requireLowercase() + "\n");
            sb.append("Requer número: " + policy.requireNumbers() + "\n");
            sb.append("Requer símbolo: " + policy.requireSymbols() + "\n");
            sb.append("Tamanho do historico de senhas: " + policy.passwordHistorySize() + "\n");

        	return ResponseEntity.ok(sb.toString());

        } catch (CognitoIdentityProviderException e) {
            System.err.println("Erro: " + e.awsErrorDetails().errorMessage());
        }
		return ResponseEntity.noContent().build();
    }

    @PutMapping("/{username}/disable")
    public ResponseEntity<String> disableUser(@PathVariable String username) {
        try {
            cognitoAuthService.disableUser(username);
            return ResponseEntity.ok("Usuário " + username + " desabilitado com sucesso");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Erro: " + e.getMessage());
        }
    }

    @PutMapping("/{username}/enable")
    public ResponseEntity<String> enableUser(@PathVariable String username) {
        try {
            cognitoAuthService.enableUser(username);
            return ResponseEntity.ok("Usuário " + username + " habilitado com sucesso");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Erro: " + e.getMessage());
        }
    }

    @PostMapping("/user/attributes")
    public ResponseEntity<Map<String, String>> updateUserAttributes(
            @RequestBody UpdateAttributesRequest request) {
        
        cognitoAuthService.updateUserAttributes(request.getUsername(), request.getAttributes());
        
        // Retornar os atributos atualizados
        Map<String, String> updatedAttributes = 
                cognitoAuthService.getUserAttributes(request.getUsername());
        
        return ResponseEntity.ok(updatedAttributes);
    }
    
    @GetMapping("/user/{username}/attributes")
    public ResponseEntity<Map<String, String>> getUserAttributes(@PathVariable String username) {
        Map<String, String> attributes = cognitoAuthService.getUserAttributes(username);
        return ResponseEntity.ok(attributes);
    }
    
    @PostMapping("/user/create")
    public ResponseEntity<String> createUser(@RequestBody CreateUserRequest request) {
        cognitoAuthService.createUser(
                request.getUsername(), 
                request.getTemporaryPassword(), 
                request.getAttributes()
        );
        
        return ResponseEntity.ok("Usuário criado com sucesso");
    }
    
    @PostMapping("/token/decode")
    public ResponseEntity<Map<String, Object>> decodeToken(@RequestBody TokenRequest request) {
        Map<String, Object> claims = cognitoAuthService.extractClaims(request.getToken());
        return ResponseEntity.ok(claims);
    }

    // Classes adicionais para request
    public static class UpdateAttributesRequest {
        private String username;
        private Map<String, String> attributes;
        
        // Getters e setters
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public Map<String, String> getAttributes() { return attributes; }
        public void setAttributes(Map<String, String> attributes) { this.attributes = attributes; }
    }
    
    public static class CreateUserRequest {
        private String username;
        private String temporaryPassword;
        private Map<String, String> attributes;
        
        // Getters e setters
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getTemporaryPassword() { return temporaryPassword; }
        public void setTemporaryPassword(String temporaryPassword) { this.temporaryPassword = temporaryPassword; }
        public Map<String, String> getAttributes() { return attributes; }
        public void setAttributes(Map<String, String> attributes) { this.attributes = attributes; }
    }
    
    public static class TokenRequest {
        private String token;
        
        // Getters e setters
        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }

}
