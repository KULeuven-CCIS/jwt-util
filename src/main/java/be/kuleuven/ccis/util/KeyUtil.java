package be.kuleuven.ccis.util;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;

/**
 * Created by u0090265 on 28.02.17.
 */
public interface KeyUtil {
    KeyPair parseKeyPair(String pemFileLocation) throws IOException;

    PublicKey parsePublicKey(String pemFileLocation) throws IOException;
}
