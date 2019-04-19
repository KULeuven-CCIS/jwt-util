package be.kuleuven.ccis.util.exceptions;

public class JWTParseException extends RuntimeException {
    public JWTParseException() {
        super();
    }

    public JWTParseException(String s) {
        super(s);
    }
}
