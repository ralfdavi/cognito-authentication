package br.com.travelex.cognito.response;

public class ResetPasswordResponse {
    private final boolean success;
    private final String message;
    private final String deliveryMethod;
    
    public ResetPasswordResponse(boolean success, String message, String deliveryMethod) {
        this.success = success;
        this.message = message;
        this.deliveryMethod = deliveryMethod;
    }
    
    // Getters
    public boolean isSuccess() {
        return success;
    }
    
    public String getMessage() {
        return message;
    }
    
    public String getDeliveryMethod() {
        return deliveryMethod;
    }
}
