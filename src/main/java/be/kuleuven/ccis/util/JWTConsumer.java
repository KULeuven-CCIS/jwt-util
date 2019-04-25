package be.kuleuven.ccis.util;

public interface JWTConsumer {
    /**
     * Takes the JWT String as argument. Checks the jwt for validity.
     *
     * @param jwt
     * @return A simple JWT object.
     */
    JWT extract(String jwt);
}
