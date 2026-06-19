# ACL-Graph
"" ENG """
Recursive directory scanner for Windows that determines the **effective access permissions** of the
user running the program and displays them as an interactive, zoomable, and searchable
HTML node graph. Focus: quickly see **where you’re allowed to write** and
**which configuration files contain secrets** — for penetration testers (hijack vectors)
and administrators (misconfigurations).

U are welcome to expand the feature and to help improve the idea
"""

Rekursiver Verzeichnis-Scanner für Windows, der **effektive Zugriffsrechte** des
ausführenden Benutzers ermittelt und als interaktiven, zoom-/durchsuchbaren
HTML-Knotengraph ausgibt. Fokus: schnell sehen, **wo man schreiben darf** und
**welche Konfig-Dateien Secrets enthalten** — für Pentester (Hijack-Vektoren)
und Admins (Fehlkonfigurationen).

Reines PowerShell, keine Abhängigkeiten. Läuft ab Windows 10 / Server 2016.

---

## Schnellstart

```powershell
# Einfachster Aufruf: aktuelles Verzeichnis scannen, report neben dem Skript
.\Get-AclGraph.ps1

# Konkreten Pfad scannen, Ausgabedatei festlegen
.\Get-AclGraph.ps1 -Path 'C:\inetpub' -OutFile report.html
```

Danach die erzeugte HTML-Datei im Browser öffnen. Es wird kein Server benötigt —
die Datei ist eigenständig (HTML + CSS + JS in einer Datei).

> **Tipp:** Beim ersten Lauf auf großen Laufwerken `-Depth` setzen oder einen
> Unterordner als `-Path` wählen. Jede Datei kostet einen `Get-Acl`-Aufruf, ein
> voller `C:\`-Scan kann lange dauern.

---

## Was der Report zeigt

Beim Öffnen sind nur die **Funde** und die Pfade dorthin aufgeklappt — der Rest
bleibt eingeklappt, damit auch große Bäume lesbar sind.

| Darstellung | Bedeutung |
|---|---|
| Blauer Knoten | Verzeichnis |
| Gelber Knoten | beschreibbar (writable für dich) |
| Roter Knoten (2px Rand) | **Fund**: beschreibbar **und** in sensiblem Pfad (Hijack-Vektor) |
| Schlüssel-Badge `🔑 N` | Datei enthält N mögliche Secrets im Inhalt |
| Graue, gestrichelte Box | Default-/Systemordner, unverändert (eingeklappt) |
| Badge „n.gescannt" | Inhalt nicht auf Secrets geprüft (z.B. zu groß) |
| `… N weitere` | gebündelte, uninteressante Dateien — Klick entfaltet sie |

Das Rechte-Kürzel unter jedem Namen: `R` Lesen, `W` Schreiben, `X` Ausführen,
`D` Löschen, `P` Rechte ändern (WRITE_DAC), `O` Besitz übernehmen (TAKE_OWNERSHIP),
`FULL` Vollzugriff.

---

## Bedienung im Browser

**Navigation**
- Mausrad = zoomen, Ziehen mit der Maus = verschieben (pannen).
- `+` / `−` / „Alles" oben = zoomen bzw. ganzen Graph einpassen.
- Kompass-Kreuz unten rechts: der blaue Punkt zeigt, wo im Baum die Mitte deines
  Sichtfensters liegt; der Kasten daneben nennt `x`, `y` und Zoom (`z`).
  **Klick aufs Kreuz = zurück zur Gesamtansicht.**

**Aufklappen**
- Klick auf ein Verzeichnis = Detail-Panel öffnen **und** Kinder auf-/zuklappen.
  Der angeklickte Knoten bleibt dabei an seiner Bildschirmposition.
- „Pfade entfalten" = alles aufklappen · „Nur Funde" = zurück auf die Treffer.
- Klick auf `… N weitere` = die gebündelten Dateien einblenden.

**Filter** (Feld oben rechts)
- `config` → nur Knoten, deren Name „config" enthält.
- `config -test` → enthält „config", aber **nicht** „test".
- `-backup` → alles **außer** „backup".
- Mehrere Begriffe mit Leerzeichen kombinierbar: `config -backup -test`.
- Die Suche durchsucht auch **eingeklappte** Bereiche und klappt Treffer auf;
  Feld leeren stellt den Ausgangszustand wieder her.

**Default-Ordner**
- Unveränderte Systemordner sind grau und eingeklappt. Checkbox
  „Default-Ordner einblenden" holt sie bei Bedarf in die Ansicht.

**Secrets ansehen**
- Datei mit Schlüssel-Badge anklicken → im Detail-Panel erscheint der Treffer mit
  einer Zeile Kontext davor/danach und Zeilennummer. Der Secret-Wert ist
  **verdeckt** (Punkte); Button „einblenden" zeigt ihn, „verdecken" blendet ihn
  wieder aus.

> **⚠ Wichtig:** Wenn der Report Secrets enthält, steht der Klartext (verdeckt)
> im HTML. Die Datei **nur lokal öffnen, nicht weitergeben**. Eine rote Warnleiste
> im Report weist darauf hin.

---

## Parameter

| Parameter | Typ | Default | Beschreibung |
|---|---|---|---|
| `-Path` | string | aktuelles Verzeichnis | Wurzelverzeichnis des Scans. |
| `-OutFile` | string | `.\aclgraph.html` | Zieldatei für den HTML-Report. |
| `-Depth` | int | `0` (unbegrenzt) | Maximale Rekursionstiefe. `0` = kein Limit. |
| `-Skip` | string[] | leer | Regex-Muster für Ordner/Namen, die beim Scan **nicht betreten** werden. |
| `-ScanExtensions` | string[] | leer | **Zusätzliche** Dateiendungen (ohne Punkt) für den Secret-Inhalts-Scan. |
| `-SecretRegex` | string[] | leer | **Zusätzliche** eigene Regex-Muster für die Secret-Erkennung. |
| `-MaxScanMB` | int | `5` | Dateien größer als dieser Wert (MB) werden beim Inhalts-Scan übersprungen und markiert. |
| `-DefaultDirs` | string[] | Windows-Systemordner | Regex-Muster, die als „Default-/Standard-Ordner" gelten. |
| `-ExcludeReparse` | switch | an | Reparse-Points (Symlinks/Junctions) **nicht** verfolgen. |

### Standardwerte im Detail

**Secret-Scan-Endungen (immer aktiv):**
`config`, `env`, `ini`, `json`, `xml`, `ps1`, `bat`, `yaml`, `yml`
— `-ScanExtensions` ergänzt diese Liste.

**Secret-Muster (immer aktiv):**
Passwort · ConnectionString · API-Key · AWS-Key (`AKIA…`) · Private-Key
(`-----BEGIN … PRIVATE KEY-----`) · Token/Bearer
— `-SecretRegex` ergänzt diese Liste.

**Default-Ordner (Standard):**
`C:\Windows`, `WinSxS`, `System32`, `SysWOW64`, `Microsoft.NET`, `assembly`,
`Installer`, `Common Files`. Diese werden nur dann grau & eingeklappt dargestellt,
wenn in ihrem Teilbaum **kein** Fund, **kein** Secret und **keine** beschreibbare
Datei liegt — sonst bleiben sie normal sichtbar.

---

## Beispiele

```powershell
# Webserver-Verzeichnis prüfen, Report benennen
.\Get-AclGraph.ps1 -Path 'C:\inetpub' -OutFile inetpub-acl.html

# Ganzes Laufwerk, aber Tiefe begrenzen und Müll-Ordner überspringen
.\Get-AclGraph.ps1 -Path C:\ -Depth 4 -Skip 'WinSxS','node_modules','\.git$'

# Eigene Konfig-Endung und striktere Größengrenze für den Secret-Scan
.\Get-AclGraph.ps1 -Path 'D:\apps' -ScanExtensions 'conf','properties' -MaxScanMB 2

# Eigenes Secret-Muster ergänzen (internes Token-Format)
.\Get-AclGraph.ps1 -Path 'C:\svc' -SecretRegex 'INTERNAL_TOKEN\s*=\s*\S+'

# Mehrere Skip-Muster + eigene Default-Ordner-Definition
.\Get-AclGraph.ps1 -Path C:\ -Skip 'temp','logs','cache' `
    -DefaultDirs '\\Windows\\','\\Program Files\\Common Files\\'
```

---

## Konsolen-Ausgabe

Während des Laufs meldet das Skript:

- den Benutzer, unter dem gescannt wird, und die Wurzel,
- die aktive Skip-Liste (falls gesetzt),
- die Anzahl gescannter Knoten,
- wie viele Einträge per Skip-Liste übersprungen wurden,
- wie viele Dateien Secret-Verdacht haben,
- eine **rote Warnung**, falls der Report Klartext-Secrets enthält.

---

## Wie „effektive Rechte" berechnet werden

Das Skript liest pro Element die ACL und löst die Rechte gegen **alle SIDs aus
deinem Access-Token** auf (dein eigener SID + alle Gruppen). `Deny`-Einträge
gewinnen gegen `Allow`. Das Ergebnis ist also: *was du an diesem Objekt
tatsächlich darfst* — nicht eine rohe Auflistung aller ACEs.

**Grenzen:** Die Auflösung deckt normale Allow/Deny-ACEs ab, aber nicht jeden
Sonderfall der Windows-Autorisierung (z.B. Conditional ACEs / Claims oder
Privilegien wie `SeBackupPrivilege`, die ACLs umgehen). Für die Misconfig-Jagd
reicht das in nahezu allen Fällen; für forensische Genauigkeit wären zusätzliche
`AuthZ`-API-Checks nötig.

Der Secret-Scan ist bewusst pragmatisch: Die Regex fangen die häufigen Fälle gut
ab, sind aber nicht vollständig. Sehr individuelle Formate über `-SecretRegex`
ergänzen; bei minifizierten/base64-lastigen Dateien sind einzelne Fehlalarme
möglich.

---

## Sicherheitshinweis

Der HTML-Report kann **Klartext-Secrets** enthalten (verdeckt, per Klick
einblendbar). Behandle die Datei wie ein Geheimnis: lokal öffnen, nicht per Mail
oder Chat teilen, nach Gebrauch löschen.
