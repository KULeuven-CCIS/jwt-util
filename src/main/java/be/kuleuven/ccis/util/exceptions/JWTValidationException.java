package be.kuleuven.ccis.util.exceptions;

public class JWTValidationException extends Exception {
    public JWTValidationException(String message) {
        super(message);
    }

    public JWTValidationException() {
        super();
    }
}
