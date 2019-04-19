package be.kuleuven.ccis.util;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

/**
 * Created by u0090265 on 01.03.17.
 */
public class DefaultJWTFactoryImpl implements JWTFactory {
    private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.ES512;
    private JWEAlgorithm jweAlgorithm = JWEAlgorithm.ECDH_ES_A256KW;
    private EncryptionMethod encryptionMethod = EncryptionMethod.A256GCM;

    public DefaultJWTFactoryImpl(JWSAlgorithm jwsAlgorithm, JWEAlgorithm jweAlgorithm, EncryptionMethod encryptionMethod) {
        this.jwsAlgorithm = jwsAlgorithm;
        this.jweAlgorithm = jweAlgorithm;
        this.encryptionMethod = encryptionMethod;
    }

    public DefaultJWTFactoryImpl() {
    }

    @Override
    public JWSAlgorithm getJWSAlgorithm() {
        return jwsAlgorithm;
    }

    @Override
    public JWEAlgorithm getJWEAlgorithm() {
        return jweAlgorithm;
    }

    @Override
    public EncryptionMethod getJWEEncryptionMethod() {
        return encryptionMethod;
    }
}
