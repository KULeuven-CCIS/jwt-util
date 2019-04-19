package be.kuleuven.ccis.util;

import be.kuleuven.ccis.util.exceptions.JWTParseException;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

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
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static be.kuleuven.ccis.util.JWTHelper.getJWSVerifier;
import static java.time.Duration.parse;

public class JWTConsumerImpl {
    private final static Logger LOGGER = Logger.getLogger(JWTConsumerImpl.class.getName());
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

    public String extract(String jwt) {

        try {
            return new JWTChecker(jwt)
                    .checkJWE()
                    .decryptJWE()
                    .extractSignedJWT()
                    .extractClaimSet()
                    .verifyJWT()
                    .getSubject();

        } catch (JWTParseException e) {
            LOGGER.log(Level.WARNING, "Unable to parse JWT: {}", e.getMessage());
        }
        return null;

    }

    private class JWTChecker {
        private JWEObject jweObject;
        private SignedJWT jwt;
        private JWTClaimsSet claimsSet;
        private String subject;

        JWTChecker(String jwt) {
            try {
                jweObject = JWEObject.parse(jwt);
            } catch (ParseException e) {
                e.printStackTrace();
                throw new JWTParseException();
            }
        }

        JWTChecker checkJWE() {
            if (jweObject == null) {
                throw new JWTParseException("There is no JWE object present to check");
            } else if (!supportedJweAlgorithms.contains(jweObject.getHeader().getAlgorithm()) ||
                    !supportedEncryptionMethods.contains(jweObject.getHeader().getEncryptionMethod())) {
                LOGGER.log(Level.WARNING, String.format("JWE was encrypted using a different algorithm (%s) or encryption method (%s)",
                        jweObject.getHeader().getAlgorithm(),
                        jweObject.getHeader().getEncryptionMethod()));
            }
            return this;
        }

        JWTChecker decryptJWE() {
            if (jweObject == null) {
                throw new JWTParseException("There is no JWE object present to decrypt");
            }
            try {
                this.jweObject.decrypt(JWTHelper.getJWEDecrypter(consumerPrivateKeyPair.getPrivate()));
            } catch (JOSEException e) {
                e.printStackTrace();
                throw new JWTParseException("Could not decrypt JWE");
            }
            return this;
        }

        JWTChecker extractSignedJWT() {
            this.jwt = jweObject.getPayload().toSignedJWT();
            if (!supportedJwsAlgorithms.contains(jwt.getHeader().getAlgorithm())) {
                LOGGER.log(Level.WARNING, String.format("JWS was signed using a different algorithm (%s)", jwt.getHeader().getAlgorithm()));
            }
            return this;
        }

        JWTChecker extractClaimSet() {
            try {
                this.claimsSet = jwt.getJWTClaimsSet();
            } catch (ParseException e) {
                e.printStackTrace();
                throw new JWTParseException();
            }

            if (claimsSet.getIssuer() == null || claimsSet.getSubject() == null || claimsSet.getIssueTime() == null) {
                LOGGER.log(Level.WARNING, String.format("JWT did not contain the required elements: sub, iat, iss: %s", claimsSet.toJSONObject().toJSONString()));
            }

            if (!trustedIssuers.containsKey(claimsSet.getIssuer())) {
                LOGGER.log(Level.WARNING, String.format("JWS did not came from a trusted issuer: %s", claimsSet.getIssuer()));
            }

            return this;
        }

        JWTChecker verifyJWT() {
            try {
                if (jwt.verify(getJWSVerifier(trustedIssuers.get(claimsSet.getIssuer())))) {
                    LOGGER.info(String.format("Signature of JWT signed by %s is correct", claimsSet.getIssuer()));
                    ZonedDateTime issueTime = ZonedDateTime.ofInstant(claimsSet.getIssueTime().toInstant(), ZoneId.systemDefault());

                    if (issueTime.plus(expirationDuration).isAfter(ZonedDateTime.now())) {
                        LOGGER.log(Level.FINE, String.format("JWT is valid for user %s. JWT was created at: %s", claimsSet.getSubject(), issueTime.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)));
                        this.subject = claimsSet.getSubject();
                    } else {
                        LOGGER.log(Level.WARNING, String.format("JWT has expired. Issued at %s. Expiration at %s.",
                                issueTime.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME),
                                issueTime.plus(expirationDuration).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)));
                    }

                }
            } catch (JOSEException e) {
                e.printStackTrace();
                throw new JWTParseException("Could not verify the JWT");
            }
            return this;
        }

        String getSubject() {
            return this.subject;
        }


    }


    public class JWTConsumerBuilder {
        private final KeyUtil u = new KeyUtilImpl();
        private KeyPair consumerPrivateKeyPair;
        private Set<JWEAlgorithm> supportedJweAlgorithms;
        private Set<JWSAlgorithm> supportedJwsAlgorithms;
        private Set<EncryptionMethod> supportedEncryptionMethods;
        private Duration expirationDuration;
        private Map<String, PublicKey> trustedIssuers;

        public JWTConsumerBuilder setKeys(final String consumerPrivateKeyLocation) throws IOException {
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

        public JWTConsumerImpl build() {
            return new JWTConsumerImpl(consumerPrivateKeyPair, supportedJweAlgorithms, supportedJwsAlgorithms, supportedEncryptionMethods, expirationDuration, trustedIssuers);
        }
    }

}
