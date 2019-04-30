package be.kuleuven.ccis.util.exceptions;

/**
 * is thrown when a JWT token cannot be parsed
 */
public class JWTParseException extends Exception {
    public JWTParseException() {
        super();
    }

    public JWTParseException(String s) {
        super(s);
    }
}
