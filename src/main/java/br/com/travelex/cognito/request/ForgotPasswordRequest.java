package br.com.travelex.cognito.request;

public class ForgotPasswordRequest {
    private String username;
    private String email;
    private String phoneNumber;
    
    // Getters e setters
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getEmail() { return email; }
    public void setEmail(String destination) { this.email = destination; }
    public String getPhoneNumber() {
        return phoneNumber;
    }
    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }
}
