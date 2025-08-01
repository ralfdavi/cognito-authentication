package br.com.travelex.cognito.exception;

/**
 * Exceção personalizada para erros de autenticação
 */
public  class AuthenticationException extends RuntimeException {
    public AuthenticationException(String message) {
        super(message);
    }

    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}