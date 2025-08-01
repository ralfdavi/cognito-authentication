package br.com.travelex.cognito.request;

public class ChangePasswordRequest {
    private String accessToken;
    private String oldPassword;
    private String newPassword;
    
    // Getters e Setters
    public String getAccessToken() { return accessToken; }
    public void setAccessToken(String newPassword) { this.accessToken = newPassword; }
    public String getOldPassword() { return oldPassword; }
    public void setOldPassword(String username) { this.oldPassword = username; }
    public String getNewPassword() { return newPassword; }
    public void setNewPassword(String confirmationCode) { this.newPassword = confirmationCode; }
}
