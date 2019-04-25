package be.kuleuven.ccis.util;

import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.*;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;

/**
 * Created by u0090265 on 28.02.17.
 */
public class KeyUtilImpl implements KeyUtil {

    KeyUtilImpl() {
        //Make sure that the security provider is set
        Security.addProvider(BouncyCastleProviderSingleton.getInstance());
    }

    @Override
    public KeyPair parseKeyPair(String pemFileLocation) throws IOException {
        PEMParser pemParser = null;
        try {
            // Parse the EC key pair
            pemParser = new PEMParser(new InputStreamReader(getInputStream(pemFileLocation)));
            PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();

            // Convert to Java (JCA) format
            return new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
        } catch (Exception e) {
            throw new IOException("Could not parse or convert keypair.");
        }

    }

    @Override
    public PublicKey parsePublicKey(String pemFileLocation) throws IOException {
        PEMParser pemParser = null;
        try {
            // Parse the EC key pair
            pemParser = new PEMParser(new InputStreamReader(getInputStream(pemFileLocation)));
            SubjectPublicKeyInfo pemKeyPair = (SubjectPublicKeyInfo) pemParser.readObject();

            // Convert to Java (JCA) format
            return new JcaPEMKeyConverter().getPublicKey(pemKeyPair);
        } catch (Exception e) {
            throw new IOException("Could not parse or convert public key.");
        }

    }

    private InputStream getInputStream(final String path) throws FileNotFoundException {
        if (path.startsWith("classpath:")) {
            final ClassLoader classloader = Thread.currentThread().getContextClassLoader();
            return classloader.getResourceAsStream(path.replace("classpath:", ""));
        } else if (path.startsWith("file:")) {
            return new FileInputStream(path.replace("file:", ""));
        } else {
            return new FileInputStream(path);
        }
    }
}
