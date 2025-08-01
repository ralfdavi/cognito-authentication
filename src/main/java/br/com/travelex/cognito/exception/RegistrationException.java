package br.com.travelex.cognito.exception;

/**
 * Exceção personalizada para erros de registro
 */
public class RegistrationException extends RuntimeException {
    public RegistrationException(String message) {
        super(message);
    }

    public RegistrationException(String message, Throwable cause) {
        super(message, cause);
    }
}
