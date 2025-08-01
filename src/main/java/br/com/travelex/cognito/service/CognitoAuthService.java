package br.com.travelex.cognito.service;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import br.com.travelex.cognito.exception.AuthenticationException;
import br.com.travelex.cognito.exception.RegistrationException;
import br.com.travelex.cognito.exception.UserLockedException;
import br.com.travelex.cognito.response.AuthenticationResponse;
import br.com.travelex.cognito.response.ResetPasswordResponse;
import jakarta.annotation.PostConstruct;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class CognitoAuthService {

    @Value("${aws.cognito.userPoolId}")
    private String userPoolId;

    @Value("${aws.cognito.clientId}")
    private String clientId;

    @Value("${aws.cognito.clientSecret}")
    private String clientSecret;

    @Value("${aws.region}")
    private String region;

    private CognitoIdentityProviderClient cognitoClient = null;
    private Region awsRegion = null;
    
    /**
     * Construtor alternativo que usa credenciais do ambiente
     * (variáveis de ambiente, arquivo ~/.aws/credentials, etc.)
     */
    @PostConstruct
    public void init() {
        this.awsRegion = Region.of(region);
        
        // Configuração do cliente usando credenciais do ambiente
        this.cognitoClient = CognitoIdentityProviderClient.builder()
                .region(this.awsRegion)
                .build();
    }

    /**
     * Autentica um usuário e retorna os tokens JWT
     */
    public AuthenticationResponse authenticateUser(String username, String password) {
        try {
            // Preparar parâmetros de autenticação
            Map<String, String> authParams = new HashMap<>();
            authParams.put("USERNAME", username);
            authParams.put("PASSWORD", password);
            
            // Adicionar SECRET_HASH se um clientSecret foi fornecido
            if (clientSecret != null && !clientSecret.isEmpty()) {
                authParams.put("SECRET_HASH", calculateSecretHash(username));
            }

            // Criar solicitação de autenticação
            AdminInitiateAuthRequest authRequest = AdminInitiateAuthRequest.builder()
                    .userPoolId(userPoolId)
                    .clientId(clientId)
                    .authFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
                    .authParameters(authParams)
                    .build();

            // Executar autenticação
            AdminInitiateAuthResponse authResponse = cognitoClient.adminInitiateAuth(authRequest);
            
            // Verificar se a autenticação foi bem-sucedida
            if (authResponse.authenticationResult() != null) {
                return new AuthenticationResponse(
                        authResponse.authenticationResult().accessToken(),
                        authResponse.authenticationResult().idToken(),
                        authResponse.authenticationResult().refreshToken(),
                        authResponse.authenticationResult().expiresIn()
                );
            } else if (authResponse.challengeName() != null) {
                // Lidar com desafios de autenticação (MFA, nova senha, etc.)
                throw new AuthenticationException("Desafio de autenticação requerido: " + authResponse.challengeName());
            } else {
                throw new AuthenticationException("Falha na autenticação: Nenhum resultado ou desafio retornado");
            }
            
        } catch (NotAuthorizedException e) {
            if (e.getMessage().contains("Tentativas excedidas")) {
                // Usuário está bloqueado pelo mecanismo automático do Cognito
                throw new UserLockedException("Conta temporariamente bloqueada devido a múltiplas tentativas falhas. Tente novamente mais tarde.");
            } else {
                // Outras razões para NotAuthorizedException (credenciais inválidas, etc.)
                throw new RuntimeException("Credenciais inválidas", e);
            }
        } catch (UserNotFoundException e) {
            throw new AuthenticationException("Usuário não encontrado: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new AuthenticationException("Erro na autenticação: " + e.getMessage(), e);
        }
    }

    /**
     * Atualiza tokens usando um refresh token
     * @param idToken 
     */
    public AuthenticationResponse refreshTokens(String refreshToken, String idToken) {
        try {
            Map<String, String> authParams = new HashMap<>();
            authParams.put("REFRESH_TOKEN", refreshToken);
            authParams.put("CLIENT_ID", clientId);
            
            // Adicionar SECRET_HASH se necessário
            if (clientSecret != null && !clientSecret.isEmpty()) {
                    // Obter username do ID token
                String username = null;
                if (idToken != null) {
                    try {
                        username = getUsernameFromIdToken(idToken);
                    } catch (Exception e) {
                        // Log do erro
                        throw new AuthenticationException("Erro ao extrair username do ID token: " + e.getMessage(), e);
                    }
                }
                // Para refresh token, o SECRET_HASH é calculado apenas com clientId e clientSecret
                authParams.put("SECRET_HASH", calculateSecretHash(username));
            }
            
            AdminInitiateAuthRequest authRequest = AdminInitiateAuthRequest.builder()
                    .userPoolId(userPoolId)
                    .authFlow(AuthFlowType.REFRESH_TOKEN_AUTH)
                    .clientId(clientId)
                    .authParameters(authParams)
                    .build();

            // Executar autenticação
            AdminInitiateAuthResponse response = cognitoClient.adminInitiateAuth(authRequest);

            return new AuthenticationResponse(
                    response.authenticationResult().accessToken(),
                    response.authenticationResult().idToken(),
                    refreshToken, // Mantém o mesmo refresh token
                    response.authenticationResult().expiresIn()
            );
            
        } catch (NotAuthorizedException e) {
            throw new AuthenticationException("Refresh token inválido ou expirado: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new AuthenticationException("Erro ao atualizar tokens: " + e.getMessage(), e);
        }
    }

    /**
     * Inicia o processo de recuperação de senha enviando o código para um destino personalizado
     * 
     * @param username Nome de usuário no Cognito
     * @param email Email para onde enviar o código (diferente do cadastrado)
     * @param phoneNumber Telefone para onde enviar o código (diferente do cadastrado)
     * @return Informações sobre onde o código foi enviado
     */
    public ResetPasswordResponse forgotPassword(
            String username, String email, String phoneNumber) {
        
        try {
            // 1. Determinar se o destino é email ou telefone
            //boolean isEmail = customDestination.contains("@");
            //String attributeName = isEmail ? "email" : "phone_number";
            //String deliveryMethod = isEmail ? "EMAIL" : "SMS";
            
            // Formatar telefone se necessário
            if (!phoneNumber.startsWith("+")) {
                phoneNumber = "+" + phoneNumber; // Formato E.164
            }
            
            // 2. Atualizar o atributo do usuário
            Map<String, String> attributes = new HashMap<>();
            attributes.put("email", email);
            attributes.put("phone_number", phoneNumber);
            this.updateUserAttributes(username, attributes);
            
            // 3. Marcar o atributo como verificado
            Map<String, String> verifiedAttribute = new HashMap<>();
            verifiedAttribute.put("email_verified", "true");
            verifiedAttribute.put("phone_number_verified", "true");
            this.updateUserAttributes(username, verifiedAttribute);
            
            // 4. Iniciar o processo de recuperação de senha
            ForgotPasswordRequest forgotRequest = ForgotPasswordRequest.builder()
                    .clientId(clientId)
                    .username(username)
                    .secretHash(calculateSecretHash(username))
                    .build();
            
            // DOC: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ForgotPassword.html
            ForgotPasswordResponse response = cognitoClient.forgotPassword(forgotRequest);
            
            // 5. Retornar informações sobre onde o código foi enviado
            return new ResetPasswordResponse(
                true,
                "Código enviado com sucesso para " + maskDestination(phoneNumber),
                response.codeDeliveryDetails().deliveryMedium().toString()
            );
            
        } catch (Exception e) {
            throw new RuntimeException("Erro ao iniciar recuperação de senha: " + e.getMessage(), e);
        }
    }

    /**
     * Confirma a redefinição de senha com o código recebido
     */
    public void confirmForgotPassword(String username, String confirmationCode, String newPassword) {
        try {

            ConfirmForgotPasswordRequest request = ConfirmForgotPasswordRequest.builder()
                    .clientId(clientId)
                    .username(username)
                    .confirmationCode(confirmationCode)
                    .secretHash(calculateSecretHash(username))
                    .password(newPassword)
                    .build();

            // DOC: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmForgotPassword.html 
            cognitoClient.confirmForgotPassword(request);
        } catch (CodeMismatchException e) {
            throw new RuntimeException("Código de confirmação inválido", e);
        } catch (ExpiredCodeException e) {
            throw new RuntimeException("Código de confirmação expirado", e);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao confirmar redefinição de senha: " + e.getMessage(), e);
        }
    }
    
    /**
     * Retorna políticas de senhas do Cognito
     * @return DescribeUserPoolResponse com as políticas de senha
     */
    public DescribeUserPoolResponse retrievePasswordPolicies() {
        try {
            DescribeUserPoolRequest request = DescribeUserPoolRequest.builder()
                    .userPoolId(userPoolId)
                    .build();

            return cognitoClient.describeUserPool(request);
            
        } catch (NotAuthorizedException e) {
            throw new RuntimeException("Token inválido ou senha incorreta", e);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao buscar políticas de senha: " + e.getMessage(), e);
        }
    }
    
    /**
     * Altera a senha do usuário quando ele está logado
     */
    public void changePassword(String accessToken, String oldPassword, String newPassword) {
        try {
            ChangePasswordRequest request = ChangePasswordRequest.builder()
                    .accessToken(accessToken)
                    .previousPassword(oldPassword)
                    .proposedPassword(newPassword)
                    .build();

            // DOC: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ChangePassword.html
            cognitoClient.changePassword(request);
        } catch (NotAuthorizedException e) {
            throw new RuntimeException("Token inválido ou senha incorreta", e);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao alterar senha: " + e.getMessage(), e);
        }
    }

    /**
     * Desabilita um usuário no Cognito User Pool
     */
    public void disableUser(String username) {
        try {
            AdminDisableUserRequest request = AdminDisableUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .build();
            
            cognitoClient.adminDisableUser(request);
            
        } catch (UserNotFoundException e) {
            throw new RuntimeException("Usuário não encontrado: " + username, e);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao desabilitar usuário: " + username, e);
        }
    }

    /**
     * Habilita um usuário previamente desabilitado
     */
    public void enableUser(String username) {
        try {
            AdminEnableUserRequest request = AdminEnableUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .build();
            
            cognitoClient.adminEnableUser(request);
            
        } catch (UserNotFoundException e) {
            throw new RuntimeException("Usuário não encontrado: " + username, e);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao habilitar usuário: " + username, e);
        }
    }

    /**
     * Método para mascarar o email ou telefone onde o código foi enviado
     * Ex: j***@example.com ou +55******7890
     */
    private String maskDestination(String destination) {
        if (destination == null || destination.isEmpty()) {
            return "";
        }
        
        if (destination.contains("@")) {
            // É um email
            int atIndex = destination.indexOf('@');
            if (atIndex <= 1) return destination;
            
            String username = destination.substring(0, atIndex);
            String domain = destination.substring(atIndex);
            
            return username.substring(0, 1) + "***" + domain;
        } else {
            // É um telefone
            if (destination.length() <= 4) return destination;
            
            return destination.substring(0, 3) + "******" + 
                   destination.substring(destination.length() - 4);
        }
    }

    /**
     * Extrai o username (sub ou cognito:username) de um ID token JWT
     */
    private String getUsernameFromIdToken(String idToken) {
        try {
            // Decodificar o token sem verificar a assinatura (apenas para leitura)
            String[] parts = idToken.split("\\.");
            if (parts.length != 3) {
                throw new IllegalArgumentException("Token JWT inválido");
            }
            
            // Decodificar a parte de payload (segunda parte)
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            
            // Converter para JSON
            ObjectMapper mapper = new ObjectMapper();
            JsonNode payloadJson = mapper.readTree(payload);
            
            // Tentar obter o username de diferentes claims
            if (payloadJson.has("cognito:username")) {
                return payloadJson.get("cognito:username").asText();
            } else if (payloadJson.has("sub")) {
                return payloadJson.get("sub").asText();
            } else if (payloadJson.has("email")) {
                return payloadJson.get("email").asText();
            }
            
            throw new IllegalArgumentException("Não foi possível encontrar username no token");
        } catch (Exception e) {
            throw new RuntimeException("Erro ao processar ID token", e);
        }
    }

    /**
     * Calcula o SECRET_HASH necessário para autenticação
     */
    private String calculateSecretHash(String username) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec key = new SecretKeySpec(
                    clientSecret.getBytes(StandardCharsets.UTF_8), 
                    "HmacSHA256"
            );
            mac.init(key);
            mac.update(username.getBytes(StandardCharsets.UTF_8));
            byte[] result = mac.doFinal(clientId.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(result);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao calcular SECRET_HASH", e);
        }
    }

    /**
     * Registra um novo usuário no Cognito
     */
    public void registerUser(String username, String password, Map<String, String> userAttributes) {
        try {
            // Converter atributos para o formato esperado pelo Cognito
            java.util.List<AttributeType> cognitoAttributes = userAttributes.entrySet().stream()
                    .map(entry -> AttributeType.builder()
                            .name(entry.getKey())
                            .value(entry.getValue())
                            .build())
                    .collect(java.util.stream.Collectors.toList());

            // Criar solicitação de registro
            AdminCreateUserRequest createRequest = AdminCreateUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .temporaryPassword(password)
                    .userAttributes(cognitoAttributes)
                    .messageAction(MessageActionType.SUPPRESS) // Não enviar email
                    .build();

            // Executar registro
            AdminCreateUserResponse createResponse = cognitoClient.adminCreateUser(createRequest);

            // Definir senha permanente (opcional, dependendo do fluxo desejado)
            AdminSetUserPasswordRequest passwordRequest = AdminSetUserPasswordRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .password(password)
                    .permanent(true)
                    .build();

            cognitoClient.adminSetUserPassword(passwordRequest);
            
        } catch (UsernameExistsException e) {
            throw new RegistrationException("Usuário já existe: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new RegistrationException("Erro ao registrar usuário: " + e.getMessage(), e);
        }
    }

    /**
     * Fecha o cliente Cognito e libera recursos
     */
    public void close() {
        if (cognitoClient != null) {
            cognitoClient.close();
        }
    }

    /**
     * Adiciona ou atualiza atributos do usuário
     */
    public void updateUserAttributes(String username, Map<String, String> attributes) {
        try {
            //logger.info("Atualizando atributos para o usuário: {}", username);
            
            List<AttributeType> attributeList = attributes.entrySet().stream()
                    .map(entry -> AttributeType.builder()
                            .name(entry.getKey())
                            .value(entry.getValue())
                            .build())
                    .collect(Collectors.toList());
            
            AdminUpdateUserAttributesRequest updateRequest = AdminUpdateUserAttributesRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .userAttributes(attributeList)
                    .build();
            
            cognitoClient.adminUpdateUserAttributes(updateRequest);
            //logger.info("Atributos atualizados com sucesso para o usuário: {}", username);
            
        } catch (Exception e) {
            //logger.error("Erro ao atualizar atributos do usuário: {}", e.getMessage(), e);
            throw new RuntimeException("Falha ao atualizar atributos: " + e.getMessage(), e);
        }
    }

    /**
     * Obtém todos os atributos de um usuário
     */
    public Map<String, String> getUserAttributes(String username) {
        try {
            //logger.info("Obtendo atributos do usuário: {}", username);
            
            AdminGetUserRequest getUserRequest = AdminGetUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .build();
            
            AdminGetUserResponse response = cognitoClient.adminGetUser(getUserRequest);
            
            Map<String, String> attributes = response.userAttributes().stream()
                    .collect(Collectors.toMap(
                            AttributeType::name,
                            AttributeType::value
                    ));
            
            //logger.info("Atributos obtidos com sucesso para o usuário: {}", username);
            return attributes;
            
        } catch (Exception e) {
            //logger.error("Erro ao obter atributos do usuário: {}", e.getMessage(), e);
            throw new RuntimeException("Falha ao obter atributos: " + e.getMessage(), e);
        }
    }

    /**
     * Cria um novo usuário com atributos específicos
     */
    public void createUser(String username, String temporaryPassword, Map<String, String> attributes) {
        try {
            //logger.info("Criando novo usuário: {}", username);
            
            List<AttributeType> attributeList = attributes.entrySet().stream()
                    .map(entry -> AttributeType.builder()
                            .name(entry.getKey())
                            .value(entry.getValue())
                            .build())
                    .collect(Collectors.toList());
            
            AdminCreateUserRequest createRequest = AdminCreateUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .temporaryPassword(temporaryPassword)
                    .userAttributes(attributeList)
                    .build();
            
            cognitoClient.adminCreateUser(createRequest);
            //logger.info("Usuário criado com sucesso: {}", username);
            
        } catch (Exception e) {
            //logger.error("Erro ao criar usuário: {}", e.getMessage(), e);
            throw new RuntimeException("Falha ao criar usuário: " + e.getMessage(), e);
        }
    }

    /**
     * Decodifica e extrai claims de um token JWT
     * Nota: Esta é uma implementação simplificada. Em produção, use uma biblioteca como JJWT ou Nimbus JOSE+JWT
     */
    public Map<String, Object> extractClaims(String jwtToken) {
        try {
            // Dividir o token em partes (header, payload, signature)
            String[] parts = jwtToken.split("\\.");
            if (parts.length != 3) {
                throw new IllegalArgumentException("Token inválido");
            }
            
            // Decodificar a parte do payload (claims)
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            
            // Converter JSON para Map (requer uma biblioteca JSON como Jackson ou Gson)
            // Este é um exemplo usando Jackson:
            ObjectMapper mapper = new ObjectMapper();
            return mapper.readValue(payload, new TypeReference<Map<String, Object>>() {});
            
        } catch (Exception e) {
            //logger.error("Erro ao extrair claims do token: {}", e.getMessage(), e);
            throw new RuntimeException("Falha ao processar token JWT: " + e.getMessage(), e);
        }
    }

}
