package be.kuleuven.ccis.util;

import be.kuleuven.ccis.util.exceptions.JWTCreationFailedException;

/**
 * Created by u0090265 on 28.02.17.
 */
public interface JWTIssuer {
    /**
     * @param subject The subject (mostly user) for whom the JWT is created.
     * @return The JWT String in its full glory.
     * @throws JWTCreationFailedException
     */
    String create(String subject) throws JWTCreationFailedException;
}
