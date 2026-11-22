# Restic Server UI

Schlanke Weboberfläche zur Benutzerverwaltung für den
[restic REST-Server](https://github.com/restic/rest-server), inklusive
**Freigaben**: Ein Benutzer kann – mit seinen eigenen Zugangsdaten – auf
Repositories anderer Benutzer zugreifen (nur lesen, nur anhängen oder voll).

- rest-server läuft **immer** mit `--private-repos`
- Benutzer anlegen, deaktivieren, löschen, Passwörter setzen (Generator inklusive)
- Zugriffsmodus pro Benutzer: *Vollzugriff*, *Nur anhängen* (Schutz vor Ransomware) oder *Nur lesen*
- Freigaben pro Benutzer oder pro Unter-Repository (`/alice/` oder `/alice/laptop/`)
- Übersicht über Repositories: Größe, Anzahl Snapshots, letzter Snapshot, Locks
- Normale Benutzer können sich anmelden, ihre Zugangs-URLs sehen und ihr Passwort ändern
- Ein einziges Go-Binary (nur `golang.org/x/crypto/acme` als Abhängigkeit), Image auf Basis von distroless (~10 MB)
- Optional TLS für Oberfläche und Gateway mit Let's Encrypt (DNS-Challenge über PowerDNS), komplett in der Oberfläche konfigurierbar

## Architektur

```
restic-Client ──Basic-Auth──► ui :8000  (Gateway)            ──► rest-server :8000
                               • prüft Benutzer/Passwort          --private-repos
                               • prüft Besitz / Freigabe          --proxy-auth-username X-Restic-User
                               • prüft Modus (GET/POST/DELETE)    (nur internes Docker-Netz,
                               • setzt X-Restic-User = Besitzer    kein veröffentlichter Port)
Browser ─────────────────────► ui :8080  (Weboberfläche)

Mit TLS (getrennte Ports, siehe „TLS / Let's Encrypt“):
restic-Client ──HTTPS──► ui :8444  (Gateway)      ui :8000 ist dann geschlossen
Browser ───────HTTPS──► ui :8443  (Oberfläche)    ui :8080 leitet auf :8443 um
```

rest-server kann Freigaben selbst nicht abbilden: Im `--private-repos`-Modus darf
ein Benutzer nur auf `/<benutzername>/…` zugreifen. Seit rest-server **0.14.0**
gibt es `--proxy-auth-username`: Der Benutzername kommt dann aus einem HTTP-Header,
den ein vorgeschalteter Proxy setzt. Diese Rolle übernimmt das Gateway:

1. Es authentifiziert den Client (PBKDF2-SHA256-Hashes, kurzzeitiger Cache, Brute-Force-Sperre).
2. Es ermittelt das Ziel-Repository wie rest-server (max. 2 Pfadebenen).
3. Es erlaubt den Zugriff auf eigene Repositories oder auf Repositories mit Freigabe.
4. Es setzt den Header auf den **Besitzer** des Repositories. Ein vom Client mitgeschickter Header wird immer überschrieben.

rest-server prüft danach weiterhin `--private-repos`. Ein Fehler im Gateway kann
also höchstens Zugriff auf genau das Repository gewähren, dessen Besitzer im Header steht.

| Modus          | Erlaubt                                                                      |
|----------------|------------------------------------------------------------------------------|
| `read-only`    | GET/HEAD, Locks anlegen/entfernen (für `snapshots`, `restore`, `check`, `mount`) |
| `append-only`  | zusätzlich neue Daten/Snapshots (`backup`), kein Löschen außer Locks         |
| `full`         | alles inkl. `forget`/`prune`                                                 |

Eine Freigabe gewährt nie mehr als der Besitzer selbst hat. Ist z. B. carol auf
*Nur anhängen* gesetzt, kann auch eine *Vollzugriff*-Freigabe ihre Backups nicht löschen.

> Hinweis: Bei `restic forget` in einem Append-only-Repository meldet restic die
> 403-Fehler als Warnung (Exit-Code 0). Die Snapshots bleiben trotzdem erhalten.

## Schnellstart

```bash
cp .env.example .env      # Werte anpassen, v. a. ADMIN_PASSWORD und PUBLIC_URL
mkdir -p data config && sudo chown 568:568 data config
docker compose up -d --build
```

- Weboberfläche: `http://<host>:8080`, Anmeldung mit `ADMIN_USERNAME` / `ADMIN_PASSWORD`.
  Ohne `ADMIN_PASSWORD` steht ein zufällig erzeugtes Passwort im Log (`docker compose logs ui`).
- restic-Clients: `rest:http://<user>:<passwort>@<host>:8000/<user>/`

```bash
export RESTIC_REPOSITORY="rest:http://alice:geheim@nas:8000/alice/laptop/"
export RESTIC_PASSWORD="<Repository-Passwort>"   # Verschlüsselung, unabhängig vom Login!
restic init
restic backup ~/Dokumente
```

Freigabe von `alice/laptop` an bob: bob nutzt **seine** Zugangsdaten mit alices Pfad:
`rest:http://bob:<bobs-passwort>@nas:8000/alice/laptop/`

## TrueNAS SCALE

1. Zwei Datasets anlegen, z. B. `tank/apps/restic/data` und `tank/apps/restic/config`,
   Eigentümer `apps` (UID/GID 568).
2. Image bereitstellen. Einfachste Variante: das Repo auf GitHub pushen. Der Workflow
   `.github/workflows/docker.yml` baut `ghcr.io/<user>/<repo>:latest` für amd64/arm64.
   Alternativ auf dem NAS per `docker compose build` bauen.
3. *Apps → Discover Apps → ⋮ → Install via YAML* und folgende Compose-Datei einfügen
   (Pfade und Image anpassen):

```yaml
services:
  rest-server:
    image: restic/rest-server:0.14.0
    restart: unless-stopped
    user: "568:568"
    environment:
      OPTIONS: "--private-repos --proxy-auth-username X-Restic-User"
    volumes:
      - /mnt/tank/apps/restic/data:/data
    networks: [backend]
  ui:
    image: ghcr.io/<user>/restic-server-ui:latest
    restart: unless-stopped
    user: "568:568"
    depends_on: [rest-server]
    environment:
      ADMIN_USERNAME: admin
      ADMIN_PASSWORD: "bitte-ändern"
      PUBLIC_URL: "http://truenas.local:8000"
      BACKEND_URL: http://rest-server:8000
      # optional, Standardwerte:
      # UI_TLS_LISTEN: ":8443"
      # GATEWAY_TLS_LISTEN: ":8444"
      PROXY_AUTH_HEADER: X-Restic-User
      TZ: Europe/Berlin
    volumes:
      - /mnt/tank/apps/restic/config:/config
      - /mnt/tank/apps/restic/data:/data:ro
    ports:
      - "8000:8000"   # Gateway, HTTP (nur ohne TLS)
      - "8444:8444"   # Gateway, HTTPS (nur mit TLS)
      - "8080:8080"   # Oberfläche, HTTP (mit TLS: Weiterleitung)
      - "8443:8443"   # Oberfläche, HTTPS (nur mit TLS)
    networks: [backend, frontend]
networks:
  backend:
    internal: true
  frontend: {}
```

Für HTTPS gibt es zwei Wege: das eingebaute Let's-Encrypt-TLS (Abschnitt
[TLS / Let's Encrypt](#tls--lets-encrypt)) oder ein vorgeschalteter Reverse Proxy
(z. B. Nginx Proxy Manager, Traefik, Caddy) – dann `COOKIE_SECURE=true` und
`PUBLIC_URL=https://…` setzen.

> **Wichtig:** Den Port des rest-server-Containers niemals veröffentlichen. Wer
> rest-server direkt erreicht, kann den Header fälschen und so jedes Repository lesen.

## TLS / Let's Encrypt

Weboberfläche **und** restic-Gateway können direkt im Container per TLS abgesichert
werden. HTTP und HTTPS laufen auf **getrennten Ports**:

| Port (Standard) | Dienst | Ohne TLS | Mit TLS |
|-----------------|--------|----------|---------|
| `8080` (`UI_LISTEN`) | Oberfläche, HTTP | Oberfläche | **Weiterleitung** (307) auf `https://<Domain>:8443` |
| `8443` (`UI_TLS_LISTEN`) | Oberfläche, HTTPS | geschlossen | Oberfläche |
| `8000` (`GATEWAY_LISTEN`) | restic-Gateway, HTTP | Gateway | **geschlossen** (Port wird freigegeben) |
| `8444` (`GATEWAY_TLS_LISTEN`) | restic-Gateway, HTTPS | geschlossen | Gateway |

Das Umschalten geschieht zur Laufzeit, ein Neustart ist nicht nötig. Beim Gateway wird
der HTTP-Port wirklich geschlossen (Verbindung abgelehnt); bereits offene
Keep-Alive-Verbindungen bekommen nur noch `403`. Der Container-Healthcheck nutzt
`http://127.0.0.1:8080/healthz`, der von der Weiterleitung ausgenommen ist.
Das Zertifikat kommt von Let's Encrypt (oder einer
anderen ACME-CA) und wird per **DNS-01-Challenge über die PowerDNS-API** ausgestellt –
es muss also kein Port aus dem Internet erreichbar sein, und Wildcards
(`*.example.com`) sind möglich. Alles wird in der Oberfläche unter **TLS** eingestellt:

| Einstellung | Bedeutung |
|-------------|-----------|
| Domains | Eine pro Zeile, auch `*.example.com`. Ein Zertifikat gilt für beide Ports. |
| E-Mail, Zertifizierungsstelle | Let's Encrypt *Produktion*, *Staging* (zum Testen, Zertifikate sind nicht vertrauenswürdig) oder eigene ACME-URL. Nutzungsbedingungen müssen akzeptiert werden. |
| PowerDNS API-URL / API-Key | z. B. `http://pdns:8081` und der `api-key` aus `pdns.conf` |
| Server-ID, Zone | `localhost` ist üblich. Die Zone wird je Domain automatisch ermittelt (längste passende Zone), kann aber festgelegt werden. |
| TTL, Wartezeit, DNS-Server | TTL der TXT-Einträge, Mindestwartezeit vor der Prüfung; optional ein Nameserver, auf dem die Einträge sichtbar sein müssen, bevor Let's Encrypt prüft. |

Ablauf: Pro Domain wird `_acme-challenge.<domain>` per `PATCH /api/v1/servers/<id>/zones/<zone>`
als TXT-Eintrag gesetzt, validiert und anschließend wieder gelöscht. **DNS-Zugriff testen**
prüft API-URL, Key und Zonen, ohne etwas zu ändern. Das Zertifikat wird 30 Tage (einstellbar)
vor Ablauf automatisch erneuert; bei Fehlern wird mit wachsendem Abstand (1 h … 12 h)
erneut versucht, das Protokoll des letzten Laufs steht in der Oberfläche.

Wichtig zu wissen:

- **Umschalten ohne Neustart:** TLS wird erst aktiv, wenn ein Zertifikat vorliegt. Danach ist das
  Gateway **nur noch per HTTPS** auf `:8444` erreichbar, die Oberfläche auf `:8443`
  (`:8080` leitet dorthin um). restic-Clients müssen auf `rest:https://<Domain>:8444/…`
  umgestellt werden; die in der Oberfläche angezeigten URLs passen sich an (bei gesetzter
  `PUBLIC_URL` mit `http://` wird ein vom Zertifikat abgedeckter Host mit `https://` und dem
  HTTPS-Port verwendet, sonst die erste Domain des Zertifikats). Der Zielhost der Weiterleitung
  ist der Host der Anfrage, falls das Zertifikat ihn abdeckt, sonst die erste Domain des Zertifikats.
- Die Ports `8443`/`8444` müssen in Docker/TrueNAS veröffentlicht sein (siehe `docker-compose.yml`).
  Weiterleitung und angezeigte URLs verwenden den Port aus `UI_TLS_LISTEN`/`GATEWAY_TLS_LISTEN`
  – veröffentliche ihn daher **mit derselben Nummer** nach außen (kein Mapping wie `9443:8443`).
  Die mitgelieferte Compose-Datei macht das über `UI_TLS_PORT`/`GATEWAY_TLS_PORT` in der `.env`
  (z. B. `UI_TLS_PORT=443`).
- Der Hostname, unter dem Clients und Browser den Server erreichen, muss im Zertifikat
  stehen und auf den Server zeigen.
- Der Container braucht ausgehenden Zugriff auf die ACME-CA (HTTPS) und auf die PowerDNS-API.
- Der PowerDNS-API-Key ist nicht auf eine Zone beschränkt – die API nur im internen Netz
  erreichbar machen. Der Key liegt im Klartext in `CONFIG_DIR/tls.json` (Rechte `0600`),
  ebenso wie der ACME-Konto- und der Zertifikatsschlüssel in `CONFIG_DIR/tls/`. Die Oberfläche
  zeigt den Key nie wieder an; leer lassen heißt „unverändert“.
- Wird ein TXT-Eintrag per CNAME woandershin delegiert, funktioniert das Setzen über die API
  nicht – `_acme-challenge.<domain>` muss direkt in einer PowerDNS-Zone liegen. Vorhandene
  TXT-Einträge unter diesem Namen werden beim Setzen ersetzt und danach entfernt.
- **Notausstieg**, falls man sich ausgesperrt hat: `tls.json` im Konfigurationsverzeichnis
  löschen und neu starten – danach läuft alles wieder unverschlüsselt (oder `TLS_CERT`/`TLS_KEY`
  setzen).
- Feste Zertifikate (`TLS_CERT`/`TLS_KEY`) funktionieren weiterhin und haben Vorrang.

Beispiel für `pdns.conf` (API nur im internen Docker-Netz erreichbar machen):

```ini
api=yes
api-key=<langer-zufälliger-schlüssel>
webserver=yes
webserver-address=0.0.0.0
webserver-allow-from=<Netz der UI, z. B. 172.16.0.0/12>
```

## Konfiguration (Umgebungsvariablen des `ui`-Containers)

| Variable               | Standard                    | Beschreibung |
|------------------------|-----------------------------|--------------|
| `ADMIN_USERNAME`       | `admin`                     | Initialer Administrator (wird angelegt, wenn kein aktiver Admin existiert) |
| `ADMIN_PASSWORD`       | *(zufällig, im Log)*        | Passwort des initialen Admins |
| `RESET_ADMIN_PASSWORD` | `false`                     | `true` setzt das Passwort von `ADMIN_USERNAME` beim Start auf `ADMIN_PASSWORD` (Notfall) |
| `PUBLIC_URL`           | `<host der UI>:8000`        | Gateway-Adresse für die angezeigten Repository-URLs |
| `BACKEND_URL`          | `http://rest-server:8000`   | Interne Adresse des rest-servers |
| `PROXY_AUTH_HEADER`    | `X-Restic-User`             | Muss zu `--proxy-auth-username` passen |
| `CONFIG_DIR`           | `/config`                   | Enthält `users.json` (Benutzer, Hashes, Freigaben) sowie `tls.json` und `tls/` (TLS-Einstellungen, Zertifikat, Schlüssel) |
| `DATA_DIR`             | `/data`                     | rest-server-Daten (read-only) für die Statistik; optional |
| `UI_LISTEN` / `GATEWAY_LISTEN` | `:8080` / `:8000`   | Listen-Adressen für HTTP (Gateway-HTTP nur ohne TLS; Oberfläche leitet mit TLS um) |
| `UI_TLS_LISTEN` / `GATEWAY_TLS_LISTEN` | `:8443` / `:8444` | Listen-Adressen für HTTPS (nur mit TLS offen) |
| `TLS_CERT` / `TLS_KEY` | –                           | Optional: festes Zertifikat (PEM). Hat Vorrang vor Let's Encrypt; die TLS-Einstellungen in der Oberfläche sind dann gesperrt |
| `COOKIE_SECURE`        | `false`                     | Secure-Flag für das Session-Cookie erzwingen. Bei TLS im Container wird es automatisch gesetzt; nur nötig, wenn ein Reverse Proxy TLS terminiert |
| `SESSION_TTL`          | `12h`                       | Gültigkeit einer Anmeldung |
| `LOG_REQUESTS`         | `false`                     | Jede restic-Anfrage loggen |

## Hinweise

- **Löschen eines Benutzers** entfernt Konto und Freigaben, **nicht** die Backup-Daten.
  Wird später ein Benutzer mit gleichem Namen angelegt, erhält er Zugriff auf diese Daten.
  In der Repository-Übersicht sind solche Daten als „verwaist“ markiert.
- Benutzernamen sind gleichzeitig Pfade: `A–Z a–z 0–9 @ . _ -`, max. 64 Zeichen,
  Groß-/Kleinschreibung zählt, Namen dürfen sich aber nicht nur darin unterscheiden.
- Die `.htpasswd` von rest-server wird im Proxy-Modus nicht verwendet (daher die
  Warnung „No user exists“ im rest-server-Log, sie ist harmlos).
- Anmeldungen der Weboberfläche liegen nur im Speicher. Nach einem Neustart muss man sich neu anmelden.

## Entwicklung

```bash
go test ./...            # Unit- und API-Tests (Go ≥ 1.24; einzige Abhängigkeit: golang.org/x/crypto/acme)
go run .                 # UI auf :8080, Gateway auf :8000, CONFIG_DIR/DATA_DIR per Env setzen
```

Ohne lokales Go: `docker run --rm -v "$PWD:/src" -w /src golang:1.25-alpine go test ./...`

Der Test `internal/tlsmgr/e2e_test.go` (Build-Tag `e2e`) stellt ein Zertifikat gegen einen
echten [Pebble](https://github.com/letsencrypt/pebble)-ACME-Server und ein echtes PowerDNS aus;
Voraussetzungen stehen im Kopf der Datei.
