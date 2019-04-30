package be.kuleuven.ccis.util;

public interface JWTConsumer {
    /**
     * Takes a JWT string as argument. Decodes the JWT, checks the validity of the signature and the JWT and returns the JWT.
     *
     * @param jwt
     * @return A simple JWT object.
     */
    JWT extract(String jwt);
}
