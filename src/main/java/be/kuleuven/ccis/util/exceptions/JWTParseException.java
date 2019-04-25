package be.kuleuven.ccis.util.exceptions;

public class JWTParseException extends Exception {
    public JWTParseException() {
        super();
    }

    public JWTParseException(String s) {
        super(s);
    }
}
