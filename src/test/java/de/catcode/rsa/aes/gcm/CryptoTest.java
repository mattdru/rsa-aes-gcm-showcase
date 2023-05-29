package de.catcode.rsa.aes.gcm;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.function.Function;

class CryptoTest {

    @Disabled
    @Test
    void createKeyPair() throws IOException {


        final RSACrypto rsaCrypto = new RSACrypto();
        final KeyPair rsaKeyPair = rsaCrypto.createRSAKeyPair();

        final StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PRIVATE KEY-----");
        sb.append(System.lineSeparator());
        sb.append(Base64.getEncoder().encodeToString(rsaKeyPair.getPrivate().getEncoded()));
        sb.append(System.lineSeparator());
        sb.append("-----END PRIVATE KEY-----");

        Files.write(Paths.get("private-key.pem"), sb.toString().getBytes());

        final StringBuilder sbPublic = new StringBuilder();
        sbPublic.append("-----BEGIN PUBLIC KEY-----");
        sbPublic.append(System.lineSeparator());
        sbPublic.append(Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded()));
        sbPublic.append(System.lineSeparator());
        sbPublic.append("-----END PUBLIC KEY-----");

        Files.write(Paths.get("public-key.pem"), sbPublic.toString().getBytes());
    }

    @Test
    void readKeys() {

        final RSACrypto rsaCrypto = new RSACrypto();
        final InputStream pkIs = getClass().getClassLoader().getResourceAsStream("private-key.pem");

        final PrivateKey privateKey = rsaCrypto.readPrivateKeyFromPem(pkIs);
        System.out.println(privateKey);

        // Normalerweise würde man den PublicKey in ein X509 Zertifikat wrappen. Das sparen wir uns aber.
        final InputStream pbIs = getClass().getClassLoader().getResourceAsStream("public-key.pem");
        final PublicKey publicKey = rsaCrypto.readPublicKeyFromPem(pbIs);
        System.out.println(publicKey);
    }

    @Test
    void testEncryptAndDecrypt() {

        final RSACrypto rsaCrypto = new RSACrypto();
        final AESCrypto aesCrypto = new AESCrypto();

        final InputStream pbIs = getClass().getClassLoader().getResourceAsStream("public-key.pem");
        final PublicKey publicKey = rsaCrypto.readPublicKeyFromPem(pbIs);

        final String plainText = "Das kann auch der Inhalt einer Datei sein";

        // OutputStream in eine Datei oder ähnliches
        final ByteArrayOutputStream encryptedOutputStream = new ByteArrayOutputStream();

        final SecretKey randomAesSessionKey = aesCrypto.createRandomAesSessionKey();

        final Function<SecretKey, byte[]> wrapper = (secretKey) -> rsaCrypto.wrapSecretKey(publicKey, randomAesSessionKey);
        aesCrypto.encrypt(new ByteArrayInputStream(plainText.getBytes(StandardCharsets.UTF_8)), encryptedOutputStream, randomAesSessionKey, wrapper);

//        System.out.println(encryptedOutputStream.toString(StandardCharsets.UTF_8));

        final PrivateKey privateKey = rsaCrypto.readPrivateKeyFromPem(getClass().getClassLoader().getResourceAsStream("private-key.pem"));

        final ByteArrayOutputStream decryptedOutputStream = new ByteArrayOutputStream();
        aesCrypto.decrypt(new ByteArrayInputStream(encryptedOutputStream.toByteArray()), decryptedOutputStream, bytes -> rsaCrypto.unwrapSecretKey(privateKey, bytes));
        final String decryptedPlaintext = decryptedOutputStream.toString(StandardCharsets.UTF_8);

        System.out.println(decryptedPlaintext);
        Assertions.assertEquals(plainText, decryptedPlaintext);
    }

    @Disabled
    @Test
    void testIntToBytes() {

        final int lengthOfWrappedSecretKey = 2048;

        System.out.println("" + ((lengthOfWrappedSecretKey >>> 24) & 0xFF));
        System.out.println("" + ((lengthOfWrappedSecretKey >>> 16) & 0xFF));
        System.out.println("" + ((lengthOfWrappedSecretKey >>> 8) & 0xFF));
        System.out.println("" + ((lengthOfWrappedSecretKey >>> 0) & 0xFF));

        byte[] bytes = new byte[4];
        bytes[0] = ((lengthOfWrappedSecretKey >>> 24) & 0xFF);
        bytes[1] = ((lengthOfWrappedSecretKey >>> 16) & 0xFF);
        bytes[2] = ((lengthOfWrappedSecretKey >>> 8) & 0xFF);
        bytes[3] = ((lengthOfWrappedSecretKey >>> 0) & 0xFF);
        System.out.println(bytes);

        int lengthOfSecretKeyBytes = ((bytes[0] << 24) + (bytes[1] << 16) + (bytes[2] << 8) + (bytes[3] << 0));
        System.out.println(lengthOfSecretKeyBytes);
        System.out.println(Integer.toBinaryString(lengthOfWrappedSecretKey));
        System.out.println(Integer.toBinaryString(((lengthOfWrappedSecretKey >>> 8) & 0xFF)));
    }
}
