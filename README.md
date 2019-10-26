# macOS-Audit
## Zweck
Das Skript ermöglicht es macOS 10.11, 10.12, 10.13 und 10.14 auf Basis der Anforderungen des BSI IT-Grundschutz zu auditieren.

## Ergebnis
Als Ergebnis wird eine Textdatei sowie alle relvante Auditteilergebnisse als TXT-Dateien gesichert. Die Ergebnisdateien werden im Pfad /private/tmp/BSI_Audit/${DATE} abgelegt.

## Version
Wahrscheinlich habe ich nicht alle mögliche Input/Output-Fehler auf Grund von unterschiedlichen Gegebenheiten erkannt und abgefangen. Für Verbesserungsvorschläge bin ich jederzeit offen. 

## Vorausetzungen
Das verwendete Benutzerkonto muss sudo Rechte besitzen und dem Programm Terminal muss voller Festplattenzugriff gewährt werden. 

## Anforderungsbasis für das Skript
Für das Auditskript wurde auf das BSI IT-Grundschutz-Kompendium in der Edition 2019 zurückgegriffen und diese beiden Bausteine verwendet.

### SYS.2.1 Allgemeiner Client
* SYS.2.1.A1 Benutzerauthentisierung
* SYS.2.1.A2 Rollentrennung
* SYS.2.1.A3 Aktivieren von Autoupdate-Mechanismen
* SYS.2.1.A4 Regelmäßige Datensicherung
* SYS.2.1.A5 Bildschirmsperre
* SYS.2.1.A6 Einsatz von Viren-Schutzprogrammen
* SYS.2.1.A7 Protokollierung
* SYS.2.1.A8 Absicherung des Boot-Vorgangs
* SYS.2.1.A9 Festlegung einer Sicherheitsrichtlinie für Clients
* SYS.2.1.A10 Planung des Einsatzes von Clients
* SYS.2.1.A11 Beschaffung von Clients
* SYS.2.1.A12 Kompatibilitätsprüfung von Software
* SYS.2.1.A13 Zugriff auf Ausführungsumgebungen mit unbeobachtbarer Codeausführung
* SYS.2.1.A14 Updates und Patches für Firmware, Betriebssystem und Anwendungen
* SYS.2.1.A15 Sichere Installation und Konfiguration von Clients
* SYS.2.1.A16 Deaktivierung und Deinstallation nicht benötigter Komponenten und Kennungen
* SYS.2.1.A17 Einsatzfreigabe
* SYS.2.1.A18 Nutzung von TLS
* SYS.2.1.A19 Restriktive Rechtevergabe
* SYS.2.1.A20 Schutz der Administrationsschnittstellen
* SYS.2.1.A21 Verhinderung der unautorisierten Nutzung von Rechnermikrofonen und Kameras
* SYS.2.1.A22 Abmelden nach Aufgabenerfüllung
* SYS.2.1.A23 Nutzung von Client-Server-Diensten
* SYS.2.1.A24 Umgang mit Wechseldatenträgern im laufenden System
* SYS.2.1.A25 Richtlinie zur sicheren IT-Nutzung
* SYS.2.1.A26 Schutz von Anwendungen
* SYS.2.1.A27 Geregelte Außerbetriebnahme eines Clients
* SYS.2.1.A28 Verschlüsselung der Clients(C)
* SYS.2.1.A29 Systemüberwachung(A)
* SYS.2.1.A30 Einrichten einer Referenzinstallation für Clients(CIA)
* SYS.2.1.A31 Einrichtung lokaler Paketfilter(CIA)
* SYS.2.1.A32 Einsatz zusätzlicher Maßnahmen zum Schutz vor Exploits(CIA)
* SYS.2.1.A33 Application Whitelisting(CIA)
* SYS.2.1.A34 Einsatz von Anwendungsisolation(CIA)
* SYS.2.1.A35 Aktive Verwaltung der Wurzelzertifikate(CI)
* SYS.2.1.A36 Selbstverwalteter Einsatz von SecureBoot und TPM(CI)
* SYS.2.1.A37 Schutz vor unbefugten Anmeldungen(CIA)
* SYS.2.1.A38 Einbindung in die Notfallplanung(A)
* SYS.2.1.A39 Unterbrechungsfreie und stabile Stromversorgung (A)
* SYS.2.1.A40 Betriebsdokumentation(A)
* SYS.2.1.A41 Verhinderung der Überlastung der lokalen Festplatte(A)

### SYS.2.4 Clients unter macOS
* SYS.2.4.A1 Planung des sicheren Einsatzes von macOS
* SYS.2.4.A2 Nutzung der integrierten Sicherheitsfunktionen von macOS
* SYS.2.4.A3 Verwaltung der Benutzerkonten
* SYS.2.4.A4 Verwendung der Festplattenverschlüsselung
* SYS.2.4.A5 Erhöhung des Schutzes von Daten
* SYS.2.4.A6 Verwendung aktueller Hardware
* SYS.2.4.A7 Zwei-Faktor-Authentisierung für Apple-ID
* SYS.2.4.A8 Keine Nutzung von iCloud für sensible Daten 
* SYS.2.4.A9 Verwendung von zusätzlichen Schutzprogrammen
* SYS.2.4.A10 Aktivierung der Personal Firewall
* SYS.2.4.A11 Geräteaussonderung
* SYS.2.4.A12 Aktivieren des Firmware-Kennworts (CI)
