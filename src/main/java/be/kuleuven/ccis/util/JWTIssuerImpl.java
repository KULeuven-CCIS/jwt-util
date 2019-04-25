package be.kuleuven.ccis.util;

import be.kuleuven.ccis.util.exceptions.JWTCreationFailedException;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Date;

import static be.kuleuven.ccis.util.JWTHelper.getJWEEncrypter;
import static be.kuleuven.ccis.util.JWTHelper.getJWSSigner;

public class JWTIssuerImpl implements JWTIssuer {
    private final static Logger LOGGER = LoggerFactory.getLogger(JWTIssuer.class);
    private final KeyPair issuerKeyPair;
    private final PublicKey consumerPublicKey;
    private final String issuer;
    private final JWEAlgorithm jweAlgorithm;
    private final JWSAlgorithm jwsAlgorithm;
    private final EncryptionMethod encryptionMethod;

    private JWTIssuerImpl(KeyPair issuerKeyPair, PublicKey consumerPublicKey, String issuer, JWEAlgorithm jweAlgorithm, JWSAlgorithm jwsAlgorithm, EncryptionMethod encryptionMethod) {
        assert issuerKeyPair != null : "Please define the issuer keypair";
        assert consumerPublicKey != null : "Please define the consumer public key";
        assert issuer != null && !issuer.isEmpty() : "Please define an issuer";
        assert jweAlgorithm != null : "Please define a jwe algorithm";
        assert jwsAlgorithm != null : "Please define a jws algorithm";
        assert encryptionMethod != null : "Please define an encryptionMethod";
        this.jweAlgorithm = jweAlgorithm;
        this.jwsAlgorithm = jwsAlgorithm;
        this.encryptionMethod = encryptionMethod;
        this.issuerKeyPair = issuerKeyPair;
        this.consumerPublicKey = consumerPublicKey;
        this.issuer = issuer;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String create(String subject) throws JWTCreationFailedException {
        return new JWTBuilder(subject)
                .sign()
                .encrypt()
                .build();
    }

    private JWTClaimsSet createJWTClaimSet(String userId) {
        return new JWTClaimsSet.Builder()
                .subject(userId)
                .issuer(issuer)
                .issueTime(new Date())
                .build();
    }

    public static class JWTUtilIssuerBuilder {
        private KeyPair issuerKeyPair;
        final KeyUtil u = new KeyUtilImpl();
        private PublicKey consumerPublicKey;

        private String issuer;
        private JWEAlgorithm jweAlgorithm = JWEAlgorithm.ECDH_ES;
        private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.ES512;
        private EncryptionMethod encryptionMethod = EncryptionMethod.A128CBC_HS256;

        public JWTUtilIssuerBuilder setIssuer(final String issuer) {
            this.issuer = issuer;
            return this;
        }

        public JWTUtilIssuerBuilder setIssuerKeyPair(final String issuerKeyPairLocation) throws IOException {
            this.issuerKeyPair = u.parseKeyPair(issuerKeyPairLocation);
            return this;
        }

        public JWTUtilIssuerBuilder setConsumerPublicKey(final String consumerPublicKeyLocation) throws IOException {
            this.consumerPublicKey = u.parsePublicKey(consumerPublicKeyLocation);
            return this;
        }

        public JWTUtilIssuerBuilder setJweAlgorithm(String jwsAlgorithm) {
            this.jwsAlgorithm = JWSAlgorithm.parse(jwsAlgorithm);
            return this;
        }

        public JWTUtilIssuerBuilder setJwsAlgorithm(String jweAlgorithm) {
            this.jweAlgorithm = JWEAlgorithm.parse(jweAlgorithm);
            return this;
        }

        public JWTUtilIssuerBuilder setEncryptionMethod(String encryptionMethod) {
            this.encryptionMethod = EncryptionMethod.parse(encryptionMethod);
            return this;
        }

        public JWTIssuerImpl build() {
            return new JWTIssuerImpl(this.issuerKeyPair, this.consumerPublicKey, this.issuer, this.jweAlgorithm, this.jwsAlgorithm, this.encryptionMethod);
        }
    }

    private class JWTBuilder {
        private JWTClaimsSet claimsSet;
        private SignedJWT signedJWT;
        private JWEObject jweObject;

        JWTBuilder(String userId) {
            claimsSet = createJWTClaimSet(userId);
        }

        JWTBuilder sign() throws JWTCreationFailedException {
            signedJWT = new SignedJWT(new JWSHeader(jwsAlgorithm), claimsSet);
            try {
                signedJWT.sign(getJWSSigner(issuerKeyPair.getPrivate()));
            } catch (Exception e) {
                e.printStackTrace();
                throw new JWTCreationFailedException("Could not sign JWT", e);
            }
            return this;
        }

        JWTBuilder encrypt() throws JWTCreationFailedException {
            jweObject = new JWEObject(
                    new JWEHeader.Builder(jweAlgorithm, encryptionMethod)
                            .contentType("JWT") // required to signal nested JWT
                            .build(),
                    new Payload(signedJWT));

            // Perform encryption
            try {
                jweObject.encrypt(getJWEEncrypter(consumerPublicKey));
                LOGGER.debug("Created encrypted + signed jwt: {}", jweObject.serialize());

            } catch (Exception e) {
                e.printStackTrace();
                throw new JWTCreationFailedException("Could not encrypt JWT", e);
            }
            return this;
        }

        String build() {
            if (jweObject != null) {
                return jweObject.serialize();
            } else if (signedJWT != null) {
                return signedJWT.serialize();
            } else {
                return claimsSet.toString();
            }

        }
    }

}
