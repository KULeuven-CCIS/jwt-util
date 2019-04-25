package be.kuleuven.ccis.util;

import be.kuleuven.ccis.util.exceptions.JWTParseException;
import be.kuleuven.ccis.util.exceptions.JWTValidationException;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static be.kuleuven.ccis.util.JWTHelper.getJWSVerifier;
import static java.time.Duration.parse;

public class JWTConsumerImpl implements JWTConsumer {
    private final static Logger LOGGER = LoggerFactory.getLogger(JWTConsumerImpl.class);
    private final KeyPair consumerPrivateKeyPair;
    private final Set<JWEAlgorithm> supportedJweAlgorithms;
    private final Set<JWSAlgorithm> supportedJwsAlgorithms;
    private final Set<EncryptionMethod> supportedEncryptionMethods;
    private final Duration expirationDuration;
    private final Map<String, PublicKey> trustedIssuers;

    private JWTConsumerImpl(KeyPair consumerPrivateKeyPair, Set<JWEAlgorithm> supportedJweAlgorithms, Set<JWSAlgorithm> supportedJwsAlgorithms, Set<EncryptionMethod> supportedEncryptionMethods, Duration expirationDuration, Map<String, PublicKey> trustedIssuers) {
        assert consumerPrivateKeyPair != null : "Please provide a consumer keypair";
        assert supportedEncryptionMethods != null && !supportedEncryptionMethods.isEmpty() : "Please provide a set of valid supported encryption methods";
        assert supportedJweAlgorithms != null && !supportedJweAlgorithms.isEmpty() : "Please provide a set of valid JWE algorithms";
        assert supportedJwsAlgorithms != null && !supportedJwsAlgorithms.isEmpty() : "Please provide a set of valid JWS algorithms";
        assert trustedIssuers != null && !trustedIssuers.isEmpty() : "Please provide a set of trusted issuers";
        assert expirationDuration != null : "Please provide an expiration duration";
        this.consumerPrivateKeyPair = consumerPrivateKeyPair;
        this.supportedJweAlgorithms = supportedJweAlgorithms;
        this.supportedJwsAlgorithms = supportedJwsAlgorithms;
        this.supportedEncryptionMethods = supportedEncryptionMethods;
        this.expirationDuration = expirationDuration;
        this.trustedIssuers = trustedIssuers;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JWT extract(String jwt) {

        try {
            return new JWTChecker(jwt)
                    .decryptJWE()
                    .extractSignedJWT()
                    .extractClaimSet()
                    .verifyJWT()
                    .get();

        } catch (JWTParseException | JWTValidationException e) {
            LOGGER.warn("Unable to parse or validate JWT: {}", e.getMessage());
        }
        return null;

    }

    public static class JWTConsumerBuilder {
        private final KeyUtil u = new KeyUtilImpl();
        private KeyPair consumerPrivateKeyPair;
        private Set<JWEAlgorithm> supportedJweAlgorithms;
        private Set<JWSAlgorithm> supportedJwsAlgorithms;
        private Set<EncryptionMethod> supportedEncryptionMethods;
        private Duration expirationDuration;
        private Map<String, PublicKey> trustedIssuers;

        public JWTConsumerBuilder setPrivateKeyPair(final String consumerPrivateKeyLocation) throws IOException {
            this.consumerPrivateKeyPair = u.parseKeyPair(consumerPrivateKeyLocation);
            return this;
        }

        public JWTConsumerBuilder setSupportedJweAlgorithms(final List<String> supportedJweAlgorithms) {
            this.supportedJweAlgorithms = supportedJweAlgorithms.stream().map(JWEAlgorithm::parse).collect(Collectors.toSet());
            return this;
        }

        public JWTConsumerBuilder setSupportedJwsAlgorithms(final List<String> supportedJwsAlgorithms) {
            this.supportedJwsAlgorithms = supportedJwsAlgorithms.stream().map(JWSAlgorithm::parse).collect(Collectors.toSet());
            return this;
        }

        public JWTConsumerBuilder setSupportedEncryptionMethods(final List<String> supportedJEncryptionMethods) {
            this.supportedEncryptionMethods = supportedJEncryptionMethods.stream().map(EncryptionMethod::parse).collect(Collectors.toSet());
            return this;
        }

        public JWTConsumerBuilder setExpiration(final String expirationDuration) {
            this.expirationDuration = parse(expirationDuration);
            return this;
        }

        public JWTConsumerBuilder setJWTIssuers(final Map<String, String> trustedIssuers) {
            this.trustedIssuers = new HashMap<>();
            trustedIssuers.forEach((key, value) -> {
                try {
                    this.trustedIssuers.put(key, u.parsePublicKey(value));
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            });
            return this;

        }

        public JWTConsumer build() {
            return new JWTConsumerImpl(consumerPrivateKeyPair, supportedJweAlgorithms, supportedJwsAlgorithms, supportedEncryptionMethods, expirationDuration, trustedIssuers);
        }
    }

    private class JWTChecker {
        private JWEObject jweObject;
        private SignedJWT jwt;
        private JWTClaimsSet claimsSet;

        JWTChecker(String jwt) throws JWTParseException {
            try {
                jweObject = JWEObject.parse(jwt);
            } catch (ParseException e) {
                e.printStackTrace();
                throw new JWTParseException();
            }
        }

        JWTChecker decryptJWE() throws JWTParseException {
            if (jweObject == null) {
                throw new JWTParseException("There is no JWE object present to check");
            } else if (!supportedJweAlgorithms.contains(jweObject.getHeader().getAlgorithm()) ||
                    !supportedEncryptionMethods.contains(jweObject.getHeader().getEncryptionMethod())) {
                LOGGER.warn("JWE was encrypted using a different algorithm ({}) or encryption method ({})",
                        jweObject.getHeader().getAlgorithm(),
                        jweObject.getHeader().getEncryptionMethod());
                throw new JWTParseException("Could not decrypt JWE: unknown algorithm or encryption method");
            }

            try {
                this.jweObject.decrypt(JWTHelper.getJWEDecrypter(consumerPrivateKeyPair.getPrivate()));
            } catch (JOSEException e) {
                e.printStackTrace();
                throw new JWTParseException("Could not decrypt JWE");
            }
            return this;
        }

        JWTChecker extractSignedJWT() throws JWTParseException {
            this.jwt = jweObject.getPayload().toSignedJWT();
            if (!supportedJwsAlgorithms.contains(jwt.getHeader().getAlgorithm())) {
                LOGGER.warn("JWS was signed using a different algorithm ({})", jwt.getHeader().getAlgorithm());
                throw new JWTParseException("Unknown signing algorithm.");
            }
            return this;
        }

        JWTChecker extractClaimSet() throws JWTValidationException, JWTParseException {
            try {
                this.claimsSet = jwt.getJWTClaimsSet();
            } catch (ParseException e) {
                e.printStackTrace();
                throw new JWTParseException();
            }

            if (claimsSet.getIssuer() == null || claimsSet.getSubject() == null || claimsSet.getIssueTime() == null) {
                LOGGER.warn("JWT did not contain the required elements: sub, iat, iss: {}", claimsSet.toJSONObject().toJSONString());
                throw new JWTValidationException("The JWT does not contain the required elements.");
            }

            if (!trustedIssuers.containsKey(claimsSet.getIssuer())) {
                LOGGER.warn("JWS did not came from a trusted issuer: {}", claimsSet.getIssuer());
                throw new JWTValidationException("JWT issuer not recognized.");
            }

            return this;
        }

        JWTChecker verifyJWT() throws JWTValidationException {
            try {
                if (jwt.verify(getJWSVerifier(trustedIssuers.get(claimsSet.getIssuer())))) {
                    LOGGER.info("Signature of JWT signed by {} is correct", claimsSet.getIssuer());
                    final ZonedDateTime issueTime = ZonedDateTime.ofInstant(claimsSet.getIssueTime().toInstant(), ZoneId.systemDefault());

                    if (issueTime.plus(expirationDuration).isAfter(ZonedDateTime.now())) {
                        LOGGER.debug("JWT is valid for user {}. JWT was created at: {}", claimsSet.getSubject(), issueTime.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
                    } else {
                        LOGGER.warn("JWT has expired. Issued at {}. Expiration at {}.",
                                issueTime.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME),
                                issueTime.plus(expirationDuration).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
                        throw new JWTValidationException("JWT is expired.");
                    }

                }
            } catch (JOSEException e) {
                e.printStackTrace();
                throw new JWTValidationException("Could not verify the JWT");
            }
            return this;
        }

        JWT get() {
            return new JWT(this.claimsSet.getSubject(), this.claimsSet.getIssuer(), this.claimsSet.getExpirationTime());
        }


    }

}
