package be.kuleuven.ccis.util.exceptions;

/**
 * Is thrown when the bootstrap of JWT util fails.
 */
public class BootstrapException extends RuntimeException {
    public BootstrapException(String message) {
        super(message);
    }
}
