package br.com.travelex.cognito.request;

public class RefreshTokenRequest {
    private String refreshToken;
    
    // Getters e setters
    public String getRefreshToken() {
        return refreshToken;
    }
    
    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
