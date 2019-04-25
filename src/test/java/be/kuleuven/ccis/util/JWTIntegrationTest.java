package be.kuleuven.ccis.util;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static be.kuleuven.ccis.util.JWTIssuerImpl.JWTUtilIssuerBuilder;

@RunWith(JUnit4.class)
public class JWTIntegrationTest {

    /**
     * Test the creation, then the parsing of the JWT.
     *
     * @throws Exception
     */
    @Test
    public void testItAll() throws Exception {
        final JWTIssuer jwtIssuer = new JWTUtilIssuerBuilder()
                .setIssuer("issuer")
                .setJweAlgorithm(JWSAlgorithm.ES512.getName())
                .setJwsAlgorithm(JWEAlgorithm.ECDH_ES.getName())
                .setEncryptionMethod(EncryptionMethod.A128CBC_HS256.getName())

                .setIssuerKeyPair("classpath:ec512-issuer-key-pair.pem")
                .setConsumerPublicKey("classpath:consumer_public.pem")
                .build();

        final String jwt = jwtIssuer.create("subject");

        final Map<String, String> m = new HashMap<>();
        m.put("issuer", "classpath:issuer_public.pem");

        final JWTConsumer jwtConsumer = new JWTConsumerImpl.JWTConsumerBuilder()
                .setJWTIssuers(m)
                .setSupportedJwsAlgorithms(Collections.singletonList(JWSAlgorithm.ES512.getName()))
                .setSupportedJweAlgorithms(Collections.singletonList(JWEAlgorithm.ECDH_ES.getName()))
                .setSupportedEncryptionMethods(Collections.singletonList(EncryptionMethod.A128CBC_HS256.getName()))
                .setExpiration("P2D")
                .setPrivateKeyPair("classpath:ec512-consumer-key-pair.pem")
                .build();

        final JWT processedJWT = jwtConsumer.extract(jwt);
        Assert.assertNotNull(processedJWT);
        Assert.assertEquals("subject", processedJWT.getSubject());
        Assert.assertEquals("issuer", processedJWT.getIssuer());
    }


    @Test
    public void testExpiredJWT() throws Exception {
        final JWTIssuer jwtIssuer = new JWTUtilIssuerBuilder()
                .setIssuer("issuer")
                .setJweAlgorithm(JWSAlgorithm.ES512.getName())
                .setJwsAlgorithm(JWEAlgorithm.ECDH_ES.getName())
                .setEncryptionMethod(EncryptionMethod.A128CBC_HS256.getName())

                .setIssuerKeyPair("classpath:ec512-issuer-key-pair.pem")
                .setConsumerPublicKey("classpath:consumer_public.pem")
                .build();

        final String jwt = jwtIssuer.create("subject");

        final Map<String, String> m = new HashMap<>();
        m.put("issuer", "classpath:issuer_public.pem");

        final JWTConsumer jwtConsumer = new JWTConsumerImpl.JWTConsumerBuilder()
                .setJWTIssuers(m)
                .setSupportedJwsAlgorithms(Collections.singletonList(JWSAlgorithm.ES512.getName()))
                .setSupportedJweAlgorithms(Collections.singletonList(JWEAlgorithm.ECDH_ES.getName()))
                .setSupportedEncryptionMethods(Collections.singletonList(EncryptionMethod.A128CBC_HS256.getName()))
                .setExpiration("P-2D")
                .setPrivateKeyPair("classpath:ec512-consumer-key-pair.pem")
                .build();

        final JWT processedJWT = jwtConsumer.extract(jwt);
        Assert.assertNull(processedJWT);
    }

    @Test
    public void testBadJWSAlgorithm() throws Exception {
        final JWTIssuer jwtIssuer = new JWTUtilIssuerBuilder()
                .setIssuer("issuer")
                .setJweAlgorithm(JWSAlgorithm.ES512.getName())
                .setJwsAlgorithm(JWEAlgorithm.ECDH_ES_A256KW.getName())
                .setEncryptionMethod(EncryptionMethod.A128CBC_HS256.getName())

                .setIssuerKeyPair("classpath:ec512-issuer-key-pair.pem")
                .setConsumerPublicKey("classpath:consumer_public.pem")
                .build();

        final String jwt = jwtIssuer.create("subject");

        final Map<String, String> m = new HashMap<>();
        m.put("issuer", "classpath:issuer_public.pem");

        final JWTConsumer jwtConsumer = new JWTConsumerImpl.JWTConsumerBuilder()
                .setJWTIssuers(m)
                .setSupportedJwsAlgorithms(Collections.singletonList(JWSAlgorithm.ES512.getName()))
                .setSupportedJweAlgorithms(Collections.singletonList(JWEAlgorithm.ECDH_ES.getName()))
                .setSupportedEncryptionMethods(Collections.singletonList(EncryptionMethod.A128CBC_HS256.getName()))
                .setExpiration("P-2D")
                .setPrivateKeyPair("classpath:ec512-consumer-key-pair.pem")
                .build();

        final JWT processedJWT = jwtConsumer.extract(jwt);
        Assert.assertNull(processedJWT);
    }

    @Test
    public void testBadEncryptionMethod() throws Exception {
        final JWTIssuer jwtIssuer = new JWTUtilIssuerBuilder()
                .setIssuer("issuer")
                .setJweAlgorithm(JWSAlgorithm.ES512.getName())
                .setJwsAlgorithm(JWEAlgorithm.ECDH_ES_A256KW.getName())
                .setEncryptionMethod(EncryptionMethod.A192CBC_HS384.getName())

                .setIssuerKeyPair("classpath:ec512-issuer-key-pair.pem")
                .setConsumerPublicKey("classpath:consumer_public.pem")
                .build();

        final String jwt = jwtIssuer.create("subject");

        final Map<String, String> m = new HashMap<>();
        m.put("issuer", "classpath:issuer_public.pem");

        final JWTConsumer jwtConsumer = new JWTConsumerImpl.JWTConsumerBuilder()
                .setJWTIssuers(m)
                .setSupportedJwsAlgorithms(Collections.singletonList(JWSAlgorithm.ES512.getName()))
                .setSupportedJweAlgorithms(Collections.singletonList(JWEAlgorithm.ECDH_ES.getName()))
                .setSupportedEncryptionMethods(Collections.singletonList(EncryptionMethod.A128CBC_HS256.getName()))
                .setExpiration("P-2D")
                .setPrivateKeyPair("classpath:ec512-consumer-key-pair.pem")
                .build();

        final JWT processedJWT = jwtConsumer.extract(jwt);
        Assert.assertNull(processedJWT);
    }
}
