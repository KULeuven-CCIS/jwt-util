package be.kuleuven.ccis.util.exceptions;

/**
 * Is thrown when a JWT token cannot be validated or is invalid.
 */
public class JWTValidationException extends Exception {
    public JWTValidationException(String message) {
        super(message);
    }

    public JWTValidationException() {
        super();
    }
}
