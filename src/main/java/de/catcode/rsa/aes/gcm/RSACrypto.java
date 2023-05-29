package de.catcode.rsa.aes.gcm;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSACrypto {

    public KeyPair createRSAKeyPair() {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] wrapSecretKey(final PublicKey publicKey, final SecretKey secretKey) {
        try {
            // Inspiriert von https://devtut.github.io/java/rsa-encryption.html#an-example-using-a-hybrid-cryptosystem-consisting-of-oaep-and-gcm
            final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA1andMGF1Padding");
            cipher.init(Cipher.WRAP_MODE, publicKey);
            return cipher.wrap(secretKey);
        } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public SecretKey unwrapSecretKey(final PrivateKey privateKey, final byte[] wrappedSecretKey) {
        try {
            final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA1andMGF1Padding");
            cipher.init(Cipher.UNWRAP_MODE, privateKey);
            return (SecretKey) cipher.unwrap(wrappedSecretKey, "AES", Cipher.SECRET_KEY);
        } catch (NoSuchPaddingException | InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public PrivateKey readPrivateKeyFromPem(final InputStream inputStream) {
        // https://www.baeldung.com/java-read-pem-file-keys
        // Anhand des Beispiels von baeldung lesen wir den PrivateKey mit Bordmitteln.
        try {
            // Java 8 ist so altbacken. Ab Java 11 geht das alles viel schicker.
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            inputStream.transferTo(baos);

            final String key = baos.toString(StandardCharsets.UTF_8);
            final String privateKeyPEM = key
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PRIVATE KEY-----", "");

            final byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return keyFactory.generatePrivate(keySpec);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Unhandled exception occurred.", e);
        }
    }

    public PublicKey readPublicKeyFromPem(final InputStream inputStream) {
        // https://www.baeldung.com/java-read-pem-file-keys
        // Anhand des Beispiels von baeldung lesen wir den PrivateKey mit Bordmitteln.
        try {
            // Java 8 ist so altbacken. Ab Java 11 geht das alles viel schicker.
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            inputStream.transferTo(baos);

            final String key = baos.toString(StandardCharsets.UTF_8);
            final String privateKeyPEM = key
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PUBLIC KEY-----", "");

            final byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            final X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encoded);
            return keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Unhandled exception occurred.", e);
        }
    }

    public X509Certificate readX509Certificate(final InputStream certificateInputStream) {

        try {
            // Lese das X509 Zertifikat mit Bordmitteln.
            CertificateFactory instance = CertificateFactory.getInstance("X509");
            return (X509Certificate) instance.generateCertificate(certificateInputStream);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }
}
