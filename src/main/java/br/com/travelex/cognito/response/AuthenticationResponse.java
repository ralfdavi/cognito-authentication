package br.com.travelex.cognito.response;

/**
 * Classe para representar o resultado da autenticação
 */
public class AuthenticationResponse {
    private String accessToken;
    private String idToken;
    private String refreshToken;
    private Integer expiresIn;
    private String tokenType;
    private String error;
    
    //public AuthResponse() {}

    public AuthenticationResponse(String accessToken, String idToken, String refreshToken, Integer expiresIn) {
        this.accessToken = accessToken;
        this.idToken = idToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
    }
    
    public AuthenticationResponse(String error) {
        this.error = error;
    }
    
    // Getters e setters
    public String getAccessToken() { return accessToken; }
    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
    public String getIdToken() { return idToken; }
    public void setIdToken(String idToken) { this.idToken = idToken; }
    public String getRefreshToken() { return refreshToken; }
    public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }
    public Integer getExpiresIn() { return expiresIn; }
    public void setExpiresIn(Integer expiresIn) { this.expiresIn = expiresIn; }
    public String getTokenType() { return tokenType; }
    public void setTokenType(String tokenType) { this.tokenType = tokenType; }
    public String getError() { return error; }
    public void setError(String error) { this.error = error; }
}
