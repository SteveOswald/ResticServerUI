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
- Ein einziges Go-Binary ohne externe Abhängigkeiten, Image auf Basis von distroless (~10 MB)

## Architektur

```
restic-Client ──Basic-Auth──► ui :8000  (Gateway)            ──► rest-server :8000
                               • prüft Benutzer/Passwort          --private-repos
                               • prüft Besitz / Freigabe          --proxy-auth-username X-Restic-User
                               • prüft Modus (GET/POST/DELETE)    (nur internes Docker-Netz,
                               • setzt X-Restic-User = Besitzer    kein veröffentlichter Port)
Browser ─────────────────────► ui :8080  (Weboberfläche)
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
      PROXY_AUTH_HEADER: X-Restic-User
      TZ: Europe/Berlin
    volumes:
      - /mnt/tank/apps/restic/config:/config
      - /mnt/tank/apps/restic/data:/data:ro
    ports:
      - "8000:8000"
      - "8080:8080"
    networks: [backend, frontend]
networks:
  backend:
    internal: true
  frontend: {}
```

Für HTTPS den Gateway-Port (8000) und die Oberfläche (8080) hinter einen Reverse
Proxy hängen (z. B. Nginx Proxy Manager, Traefik, Caddy). Dann `COOKIE_SECURE=true`
und `PUBLIC_URL=https://…` setzen. Alternativ direkt `TLS_CERT`/`TLS_KEY` angeben.

> **Wichtig:** Den Port des rest-server-Containers niemals veröffentlichen. Wer
> rest-server direkt erreicht, kann den Header fälschen und so jedes Repository lesen.

## Konfiguration (Umgebungsvariablen des `ui`-Containers)

| Variable               | Standard                    | Beschreibung |
|------------------------|-----------------------------|--------------|
| `ADMIN_USERNAME`       | `admin`                     | Initialer Administrator (wird angelegt, wenn kein aktiver Admin existiert) |
| `ADMIN_PASSWORD`       | *(zufällig, im Log)*        | Passwort des initialen Admins |
| `RESET_ADMIN_PASSWORD` | `false`                     | `true` setzt das Passwort von `ADMIN_USERNAME` beim Start auf `ADMIN_PASSWORD` (Notfall) |
| `PUBLIC_URL`           | `<host der UI>:8000`        | Gateway-Adresse für die angezeigten Repository-URLs |
| `BACKEND_URL`          | `http://rest-server:8000`   | Interne Adresse des rest-servers |
| `PROXY_AUTH_HEADER`    | `X-Restic-User`             | Muss zu `--proxy-auth-username` passen |
| `CONFIG_DIR`           | `/config`                   | Enthält `users.json` (Benutzer, Hashes, Freigaben) |
| `DATA_DIR`             | `/data`                     | rest-server-Daten (read-only) für die Statistik; optional |
| `UI_LISTEN` / `GATEWAY_LISTEN` | `:8080` / `:8000`   | Listen-Adressen |
| `TLS_CERT` / `TLS_KEY` | –                           | Optional: TLS direkt im Container |
| `COOKIE_SECURE`        | `true` bei TLS              | Secure-Flag für das Session-Cookie |
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
go test ./...            # Unit- und API-Tests (Go ≥ 1.24, nur Standardbibliothek)
go run .                 # UI auf :8080, Gateway auf :8000, CONFIG_DIR/DATA_DIR per Env setzen
```

Ohne lokales Go: `docker run --rm -v "$PWD:/src" -w /src golang:1.25-alpine go test ./...`
