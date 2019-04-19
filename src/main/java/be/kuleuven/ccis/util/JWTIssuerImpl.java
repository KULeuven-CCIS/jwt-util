package be.kuleuven.ccis.util;

import be.kuleuven.ccis.util.exceptions.JWTCreationFailedException;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.IOException;
import java.security.KeyPair;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import static be.kuleuven.ccis.util.JWTHelper.getJWEEncrypter;
import static be.kuleuven.ccis.util.JWTHelper.getJWSSigner;

public class JWTIssuerImpl implements JWTIssuer {
    private final static Logger LOGGER = Logger.getLogger(JWTIssuerImpl.class.getName());
    private final JWTFactory jwtFactory;
    private final KeyPair issuerKeyPair;
    private final KeyPair consumerKeyPair;
    private final String issuer;

    private JWTIssuerImpl(JWTFactory jwtFactory, KeyPair issuerKeyPair, KeyPair consumerKeyPair, String issuer) {
        assert jwtFactory != null : "JWT factory should be initialized";
        assert issuerKeyPair != null : "Please define the issuer keypair";
        assert consumerKeyPair != null : "Please define the consumer keypair";
        assert issuer != null && !issuer.isEmpty() : "Please define an issuer";
        this.jwtFactory = jwtFactory;
        this.issuerKeyPair = issuerKeyPair;
        this.consumerKeyPair = consumerKeyPair;
        this.issuer = issuer;
    }

    @Override
    public String create(String userId) throws JWTCreationFailedException {
        return new JWTBuilder(userId)
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

    private class JWTBuilder {
        private JWTClaimsSet claimsSet;
        private SignedJWT signedJWT;
        private JWEObject jweObject;

        JWTBuilder(String userId) {
            claimsSet = createJWTClaimSet(userId);
        }

        JWTBuilder sign() throws JWTCreationFailedException {
            signedJWT = new SignedJWT(new JWSHeader(jwtFactory.getJWSAlgorithm()), claimsSet);
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
                    new JWEHeader.Builder(jwtFactory.getJWEAlgorithm(), jwtFactory.getJWEEncryptionMethod())
                            .contentType("JWT") // required to signal nested JWT
                            .build(),
                    new Payload(signedJWT));

            // Perform encryption
            try {
                jweObject.encrypt(getJWEEncrypter(consumerKeyPair.getPublic()));
                LOGGER.log(Level.FINE, String.format("Created encrypted + signed jwt: %s", jweObject.serialize()));

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

    public class JWTUtilIssuerBuilder {
        private JWTFactory jwtFactory;

        private KeyPair issuerKeyPair;
        private KeyPair consumerKeyPair;

        private String issuer;

        public JWTUtilIssuerBuilder setIssuer(final String issuer) {
            this.issuer = issuer;
            return this;
        }

        public JWTUtilIssuerBuilder setKeys(final String issuerKeyPairLocation, final String consumerKeyPairLocation) throws IOException {
            final KeyUtil u = new KeyUtilImpl();
            this.issuerKeyPair = u.parseKeyPair(issuerKeyPairLocation);
            this.consumerKeyPair = u.parseKeyPair(consumerKeyPairLocation);
            return this;
        }

        public JWTUtilIssuerBuilder setJWTProperties(JWSAlgorithm jwsAlgorithm, JWEAlgorithm jweAlgorithm, EncryptionMethod encryptionMethod) {
            this.jwtFactory = new DefaultJWTFactoryImpl(jwsAlgorithm, jweAlgorithm, encryptionMethod);
            return this;
        }

        public JWTIssuerImpl build() {
            if (this.jwtFactory == null) {
                //Define the default implementation if not issued
                this.jwtFactory = new DefaultJWTFactoryImpl();
            }
            return new JWTIssuerImpl(this.jwtFactory, this.issuerKeyPair, this.consumerKeyPair, this.issuer);
        }
    }

}
