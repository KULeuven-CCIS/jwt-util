package be.kuleuven.ccis.util;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

/**
 * Created by u0090265 on 01.03.17.
 */
public interface JWTFactory {
    JWSAlgorithm getJWSAlgorithm();

    JWEAlgorithm getJWEAlgorithm();

    EncryptionMethod getJWEEncryptionMethod();
}
