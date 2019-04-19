package be.kuleuven.ccis.util;

import be.kuleuven.ccis.util.exceptions.JWTCreationFailedException;

/**
 * Created by u0090265 on 28.02.17.
 */
public interface JWTIssuer {
    String create(String userId) throws JWTCreationFailedException;
}
