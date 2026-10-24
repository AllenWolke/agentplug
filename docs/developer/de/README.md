# Einstieg für Entwickler

Neue gemeinsame Funktionen, SDK 2.1, Beispielagenten und Kompatibilität: [Änderungsübersicht auf Englisch](../../releases/public-capabilities-2.1.en.md).

[Deutsches README](../../../README_DE.md) · [简体中文](../zh/README.md) · [English](../en/README.md) · [日本語](../ja/README.md)

Verstehen Sie die Zuständigkeiten, führen Sie Geschäftscode aus und liefern Sie ihn für Unternehmen, Abteilungen und Benutzer aus. Vertiefende Dokumente sind chinesisch und englisch; die folgenden Links sind ausdrücklich englisch.

| Schritt | Anleitung | Abschluss |
| --- | --- | --- |
| 1 | [Architektur und Code, Englisch](../en/architecture.md) | Zuständigkeiten für Regeln, Rechte und Infrastruktur |
| 2 | [Installation, Englisch](../en/quickstart.md) | Gesunde Basisdienste und eigener Administrator |
| 3 | [Erster Agent, Englisch](../en/first-agent.md) | Geschäfts- und SDK-Tests, Image |
| 4 | [Gemeinsame Funktionen, Englisch](../en/capabilities.md) | SDK, Richtlinien und Autorisierung zuordnen |
| 5 | [Auslieferung, Englisch](../en/delivery.md) | Aktive Installation und korrekter Benutzerlauf |
| 6 | [Erweiterung, Englisch](../en/extending.md) | Verträge, Grenzen, Tests und Migration erhalten |

## Konfiguration und Auslieferung

`python scripts/prepare_local_development.py` erzeugt nach der Passworteingabe unabhängige Zugangsdaten und Signaturschlüssel. Bestehende `.env` bleibt unangetastet. Modelle, OIDC, MCP, Code Runtime und historische Variablen müssen nicht sofort eingerichtet werden. Die [Konfigurationsreferenz, Englisch](../en/configuration.md) erklärt Zeitpunkt und leere Werte.

Neue Umgebungen verwenden den [deutschen Schnellstart](../../../README_DE.md#schnellstart). Bestehende Datenbanken nutzen Migration und normale Verwaltung, keine erneute Erstinitialisierung.

Definition ist der stabile Agent, Version die unveränderliche Veröffentlichung, Installation die Nutzung im Unternehmensbereich, Deployment der reale Dienst und Policy Snapshot die sechs Richtlinien. Image, gesunder Dienst, aktive Installation und berechtigter Benutzer sind getrennte Tatsachen.

Menschen und Workloads benötigen getrennte Autorisierung. Administratoren erhalten keine automatische Ausführungsberechtigung. Unternehmensadministratoren bestimmen Abteilungsgrenzen; Abteilungsadministratoren vergeben darin Rechte an andere Mitglieder. Abnahme benötigt einen richtigen Lauf als gewöhnlicher Benutzer, Ablehnung unberechtigter Benutzer und die zugesagten Abbruch-/Wiederherstellungsnachweise.

[Drei Bereitstellungswege, Englisch](../en/deployment.md) · [Fehlersuche, Englisch](../en/troubleshooting.md) · [Skill installieren, Englisch](../en/skill.md)

## Anfrage an einen Coding-Assistenten

```text
Verwende agentplug-business-agent, um meinen Geschäftsagenten zu entwickeln und zu prüfen.
Prüfe SDK-Wiederverwendung, fehlende Funktionen und reale Tests. Bereite einen konkreten Plan
für meine tatsächlichen Unternehmens-, Abteilungs- und Benutzerdaten vor.
Führe Deployment und Rechte innerhalb meiner Genehmigung aus, prüfe berechtigte Benutzer
und die Ablehnung unberechtigter Benutzer. Berichte ohne Geheimnisse und ohne erfundene Erfolge.
```
