package br.com.travelex.cognito.exception;

public class UserLockedException extends RuntimeException {

    public UserLockedException(String message) {
        super(message);
    }

    public UserLockedException(String message, Throwable cause) {
        super(message, cause);
    }
}
