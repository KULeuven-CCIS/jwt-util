package be.kuleuven.ccis.util.exceptions;

/**
 * Is thrown when the creation of a JWT fails.
 */
public class JWTCreationFailedException extends Exception {
    public JWTCreationFailedException(String s) {
        super(s);
    }

    public JWTCreationFailedException(String s, Throwable throwable) {
        super(s, throwable);
    }
}
