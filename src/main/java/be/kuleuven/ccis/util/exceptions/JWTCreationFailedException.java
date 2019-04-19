package be.kuleuven.ccis.util.exceptions;

/**
 * Created by u0090265 on 28.02.17.
 */
public class JWTCreationFailedException extends Exception {
    public JWTCreationFailedException(String s) {
        super(s);
    }

    public JWTCreationFailedException(String s, Throwable throwable) {
        super(s, throwable);
    }
}
