# rsa-aes-gcm-showcase

Showcase zur Verwendung von RSA in Verbindung mit AES und GCM

## Beschreibung

Es soll ein Input z.B. eine Datei via AES (symmetrisches Verschlüsselungsverfahren) verschlüsselt werden.  
Für die Verschlüsselung wird ein genau für diesen Vorgang randomisiert erzeugter Schlüssel verwendet.  
Dieser Schlüssel wird mittels des RSA PublicKeys eines fiktiven Empfängers verschlüsselt (Wrap Mode), sodass dieser Empfänger mit seinem
RSA Private Key in der Lage ist diesen zu entschlüssel (Unwrap Mode) und somit den mit AES verschlüsselten Input wieder zu entschlüsseln.

Zur Übertragung zum Empfänger soll genau eine Datei verwendet werden. Das macht es erforderlich alle nötigen Informationen vor dem Versenden
aneinander zu hängen und auf Empfängerseite wieder zu zerlegen.

## Dateiaufbau

Der Aufbau der Datei nach erfolgter Verschlüsselung ist wie folgt.

* Identifier, der den Dateityp kennzeichnet (Magic Bytes)
* Anzahl an Bytes des verschlüsselten (gewrappten) AES SecretKeys. (Abhängig von der RSA PublicKey Schlüssellänge)
* Bytes des verschlüsselten AES SecretKeys
* IV (Initialization Vector) 12 Bytes
* Payload (verschlüsselter Input) n-Bytes
