package be.kuleuven.ccis.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class JWTHelper {
    public static JWSSigner getJWSSigner(final PrivateKey privateKey) throws JOSEException {
        return new ECDSASigner((ECPrivateKey) privateKey);
    }

    public static JWEEncrypter getJWEEncrypter(final PublicKey publicKey) throws JOSEException {
        return new ECDHEncrypter((ECPublicKey) publicKey);
    }

    public static JWEDecrypter getJWEDecrypter(final PrivateKey privateKey) throws JOSEException {
        return new ECDHDecrypter((ECPrivateKey) privateKey);
    }

    public static JWSVerifier getJWSVerifier(final PublicKey publicKey) throws JOSEException {
        return new ECDSAVerifier((ECPublicKey) publicKey);
    }
}
