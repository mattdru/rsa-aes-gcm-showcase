package de.catcode.rsa.aes.gcm;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * Eine SecureRandomInstanz soll wiederverwendet werden.
 * Das ist wohl soweit in Ordnung, wenn man in gewissen Abständen einen Reseed vornimmt.
 * Ein Vorteil der Wiederverwendung ist, dass die Zufallsquelle, die den begrenzten Zufall enthält nicht unnötig belastet wird.
 * Gerade in VMs oder Docker Containern kann diese a) recht schmal bemessen sein und sich nur langsam wieder auffüllen,
 * auch wenn dies durch verbessere Virtualisierungslösungen und Kernel Unterstützungen besser geworden ist.
 * <p>
 * Nimmt man den Zufall von /dev/random dann blockiert die Anwendung, wenn kein Zufall mehr vorhanden ist.
 * Ein switch auf /dev/urandom verhindert zwar die Blockierung, aber dieser schöpft aus derselben Entropiequelle wie
 * /dev/random. Daher macht es durchaus Sinn auf den SHA1PRNG1 zu setzen und diesen regelmäßig zu reseeden.
 * <p>
 * Ein Reseed ist wichtig um zu vermeiden, dass auf den Seed geschlossen werden kann auf dem der SHA1PRNG operiert.
 * Würde man diesen Seed kennen, dann wäre es u.U möglich die nächsten dann nicht mehr zufälligen Werte zu bestimmen.
 * <p>
 * Das ist für diesen Showcase völlig überzogen.
 * Unter Last könnte diese Überlegung aber tatsächlich interessant werden, wenn schnell nacheinander neue SecureRandom
 * Instanzen erzeugt werden würden.
 */
public final class SecureRandomProvider {

    private static SecureRandomProvider INSTANCE;
    private final SecureRandom secureRandom;

    private int byteCounter = 0;
    private final int reseedAfter = 5000; // Reseed nach 5000 Bytes.

    private SecureRandomProvider() {
        // noop
        try {
            // Initialize correctly
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
            secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
            secureRandom.nextBytes(new byte[128]);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }

    }

    public static SecureRandomProvider getInstance() {
        if (Objects.isNull(INSTANCE)) {
            INSTANCE = new SecureRandomProvider();
        }
        return INSTANCE;
    }

    public void nextBytes(byte[] buf) {
        secureRandom.nextBytes(buf);
        byteCounter += buf.length;
        if (byteCounter >= reseedAfter) {
            reseed();
        }
    }

    private void reseed() {
        secureRandom.reseed();
        // Alternativ könnte man einen separaten SecureRandomProvider instanzieren, der dann den seed bereitstellt.
//        final SecureRandom secondSecureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
//        secondSecureRandom.nextBytes(new byte[55]);
        // NIST SP800-90A suggests 440 bits for SHA1 seed --> 55 bytes
        // https://tersesystems.com/blog/2015/12/17/the-right-way-to-use-securerandom/
        // Reseed bei SHA1PRNG nutzt /dev/random, um an die nötige Entropie zu kommen.
//        secureRandom.setSeed(secondSecureRandom.generateSeed(55));
        byteCounter = 0; // setze auf 0 für den nächsten reseed.
    }
}
