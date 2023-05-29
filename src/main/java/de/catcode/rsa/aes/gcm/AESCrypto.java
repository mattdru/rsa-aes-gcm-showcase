package de.catcode.rsa.aes.gcm;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.function.Function;

public class AESCrypto {

    private static final String AES_GCM_OPERATION_MODE = "AES/GCM/NoPadding";
    private static final String FILE_IDENTIFIER = "RSAAESGCMSHOWCASEFILE"; // 52 53 41 41 45 53 47 43 4D 53 48 4F 57 43 41 53 45 46 49 4C 45

    public SecretKey createRandomAesSessionKey() {
        final int keySize = 128; // keySize in Bit
        // Bei der SUN Implementierung des SHA1PRNG ist es wichtig direkt nach der Instanziierung eine der next* Methoden aufzurufen.
        // Dadurch wird ein Problem mit setSeed entschärft. Ohne diesen Aufruf erfolgt kein automatischer Seed aus der Entropiequelle
        // und somit könnte man durch einen manuellen setSeed Aufruf immer mit demselben Startwert beginnen.
        // siehe: sun.security.provider.SecureRandom.SecureRandom()
        // Zu Details wie der SHA1PRNG funktioniert siehe auch
        // sun.security.provider.SecureRandom.engineSetSeed <-- Genutzt für das Reseeding
        // sun.security.provider.SecureRandom.engineNextBytes <-- Kernmethode für die next* Aufrufe
        // https://howtodoinjava.com/java8/secure-random-number-generation/
        // https://www.synopsys.com/blogs/software-security/proper-use-of-javas-securerandom/

        // Reseed bei SHA1PRNG nutzt /dev/random, um an die nötige Entropie zu kommen.
        final SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
            secureRandom.nextBytes(new byte[128]);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }

        try {
            // https://mkyong.com/java/java-aes-encryption-and-decryption/
            // https://soatok.blog/2020/05/13/why-aes-gcm-sucks/
            final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(keySize, secureRandom);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Verschlüsselt den Inhalt eines eingehenden InputStreams und schreibt das Resultat auf den gegebenen OutputStream.
     * Es wird eine symmetrische Verschlüsselung (AES) durchgeführt. Als Betriebsmodus wird GCM (Galois Counter Mode) verwendet.
     * <p>
     * Vor das Chiffrat werden das Salt und die IV gehanden. In alternativen Implementierungen könnte man über eine Base64 Kodierung des Salt und der
     * IV nachdenken.
     * Das ist hier aber unnötig.
     * Salt+IV+Cipher
     * <p>
     * Zum Entschlüsseln müssen zuerst das Salt und die IV gelesen werden.
     *
     * @param inputStream      die zu verschlüsselnden Daten als InputStream
     * @param outputStream     der OutputStream auf den das Verschlüsselungsergebnis geschrieben werden soll
     * @param secretKey        der {@link SecretKey} der zur Anwendung kommt
     * @param secredKeyWrapper eine Function, die das Wrapping des SecretKeys umsetzt
     */
    public void encrypt(final InputStream inputStream, final OutputStream outputStream, final SecretKey secretKey, final Function<SecretKey, byte[]> secredKeyWrapper) {

        try {
            // https://en.wikipedia.org/wiki/Galois/Counter_Mode
            // GCM Tag Length (AuthenticationTag) kann einer der folgenden Werte sein 128, 120, 112, 104, or 96.
            // Wir nehmen einfach 128
            final IvParameterSpec ivParameterSpec = createRandomIV();
            final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, ivParameterSpec.getIV());
            final Cipher cipher = Cipher.getInstance(AES_GCM_OPERATION_MODE);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

            try (final CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher)) {
                // Der write der IV muss auf dem outputStream und nicht auf dem cipherOutputStream erfolgen, weil diese nicht verschlüsselt werden sollen.
                byte[] wrappedSecretKey = secredKeyWrapper.apply(secretKey);

                // Schreibe die Länge des SecretKeys
                // Code aus dem DataOutputStream entwendet.
                // Die Idee ist es, einen 32 bit Integer auf Bytes zu verteilen, da es diese sind die wir schreiben.
                // Wir beginnen hier mit dem höherwertigen Bits.
                final int lengthOfWrappedSecretKey = wrappedSecretKey.length;
//                System.out.println(lengthOfWrappedSecretKey);
                outputStream.write(FILE_IDENTIFIER.getBytes(StandardCharsets.UTF_8));
                outputStream.write((lengthOfWrappedSecretKey >>> 24) & 0xFF);
                outputStream.write((lengthOfWrappedSecretKey >>> 16) & 0xFF);
                outputStream.write((lengthOfWrappedSecretKey >>> 8) & 0xFF);
                outputStream.write((lengthOfWrappedSecretKey >>> 0) & 0xFF);

                outputStream.write(wrappedSecretKey);
                outputStream.write(ivParameterSpec.getIV());
                inputStream.transferTo(cipherOutputStream);
            } catch (IOException e) {
                throw new RuntimeException("Unhandled exception occurred.", e);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                 InvalidKeyException e) {
            throw new RuntimeException("Unhandled exception occurred.", e);
        }
    }

    /**
     * Entschlüsselt den eigenhenden InputStream und schreibt das Resultat auf den gegebenen OutputStream.
     *
     * @param inputStream        die verschlüsselten Daten als InputStream
     * @param outputStream       der OutputStream auf den das Entschlüsselungsergebnis geschrieben werden soll
     * @param secretKeyUnwrapper Function die den extrahierten SecretKey unwrapped
     */
    public void decrypt(final InputStream inputStream, final OutputStream outputStream, final Function<byte[], SecretKey> secretKeyUnwrapper) {

        final byte[] ivBytes = new byte[12];

        try {
            final byte[] fileIdentifierBytes = new byte[FILE_IDENTIFIER.getBytes().length];
            inputStream.read(fileIdentifierBytes);
            // Lese die Länge des SecretKeys
            // Code aus dem DataInputStream entwendet.
            int ch1 = inputStream.read();
            int ch2 = inputStream.read();
            int ch3 = inputStream.read();
            int ch4 = inputStream.read();
            if ((ch1 | ch2 | ch3 | ch4) < 0) {
                throw new EOFException();
            }
            int lengthOfSecretKeyBytes = ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + (ch4 << 0));

            final byte[] secretKeyBytes = new byte[lengthOfSecretKeyBytes];
            inputStream.read(secretKeyBytes);
            inputStream.read(ivBytes);
            final SecretKey secretKey = secretKeyUnwrapper.apply(secretKeyBytes);
            final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, ivBytes);
            final Cipher cipher = Cipher.getInstance(AES_GCM_OPERATION_MODE);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

            try (final CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher)) {
                transferTo(cipherInputStream, outputStream);
            } catch (IOException e) {
                throw new RuntimeException("Unhandled exception occurred.", e);
            }
        } catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException |
                 InvalidKeyException e) {
            throw new RuntimeException("Unhandled exception occurred.", e);
        }
    }

    /**
     * Gecloned aus dem JDK17, um den CipherInputStream ohne viel Foo auf den OutputStream transferieren zu können.
     * <p>
     * Reads all bytes from this input stream and writes the bytes to the
     * given output stream in the order that they are read. On return, this
     * input stream will be at end of stream. This method does not close either
     * stream.
     * <p>
     * This method may block indefinitely reading from the input stream, or
     * writing to the output stream. The behavior for the case where the input
     * and/or output stream is <i>asynchronously closed</i>, or the thread
     * interrupted during the transfer, is highly input and output stream
     * specific, and therefore not specified.
     * <p>
     * If an I/O error occurs reading from the input stream or writing to the
     * output stream, then it may do so after some bytes have been read or
     * written. Consequently the input stream may not be at end of stream and
     * one, or both, streams may be in an inconsistent state. It is strongly
     * recommended that both streams be promptly closed if an I/O error occurs.
     *
     * @param out the output stream, non-null
     * @return the number of bytes transferred
     * @throws IOException          if an I/O error occurs when reading or writing
     * @throws NullPointerException if {@code out} is {@code null}
     * @since 9
     */
    private long transferTo(final InputStream is, final OutputStream out) throws IOException {
        final int DEFAULT_BUFFER_SIZE = 8192;
        Objects.requireNonNull(out, "out");
        long transferred = 0;
        byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
        int read;
        while ((read = is.read(buffer, 0, DEFAULT_BUFFER_SIZE)) >= 0) {
            out.write(buffer, 0, read);
            transferred += read;
        }
        return transferred;
    }

    private IvParameterSpec createRandomIV() {
        // Da wir die nonce nur für GCM in diesem Beispiel verwenden ist die Länge des Arrays 12. Bei GCM ist diese 12, bei CBC 16.
        // siehe dazu die passenden RFCs.
        final byte[] nonce = new byte[12];
        SecureRandomProvider.getInstance().nextBytes(nonce);
        return new IvParameterSpec(nonce);
    }
}
