# Shared workspace deployment (pilot)

## What the team features do

When `TEAM_MODE=1`, Lantern asks users to sign in. The first account is the administrator configured by `ADMIN_USERNAME` and `ADMIN_PASSWORD`. From **Team accounts**, that administrator can add analyst, reviewer, and administrator accounts. All signed-in users work with the same saved project records on the server. Analysts prepare and edit drafts; reviewers review and approve; administrators manage accounts, backups, retention settings, and project archive/delete actions. Reviewers can approve only projects assigned to their username.

## Run the shared-mode pilot on a server

1. Choose a Linux server or private cloud VM controlled by Lantern. Install Docker Engine and the Docker Compose plugin.
2. Copy this project folder to the server. Create `.env` from `.env.example`, then set `TEAM_MODE=1`, a unique `ADMIN_USERNAME`, a unique `ADMIN_PASSWORD` of at least 14 characters, and the OpenAI key if live AI generation is required. Keep the `.env` file private. Do not put it in the ZIP, Git, or a web folder.
3. Start it with `docker compose up --build -d`. The app listens on `127.0.0.1:8000` on the server. Sign in from the server itself at `http://127.0.0.1:8000` for initial setup. Add each colleague under **Team accounts** and share their temporary credentials privately.
4. To let colleagues connect remotely, put a maintained reverse proxy such as Caddy or nginx in front of the app, configure HTTPS with a valid certificate, and proxy to `127.0.0.1:8000`. Set `COOKIE_SECURE=1` in `.env`, then restart with `docker compose up -d`. Point a domain name to the server and allow only HTTPS through the firewall. Do not expose port 8000 directly to the internet.
5. Preserve the Docker volume named `lantern_data`. It contains shared project JSON records, version history, team accounts, sessions, and settings. Keep regular encrypted off-server backups. Do not run multiple app replicas against this JSON-file storage.

## Updating and backing up

- Back up using the in-app administrator-only **Back up projects** control, and separately back up the persistent `lantern_data` volume so accounts and settings can be restored too.
- To update, back up first, replace the application files with the new version, then run `docker compose up --build -d`.
- Keep the OpenAI key only in the server's private `.env`. AI generation still uses the OpenAI API and may require API billing/credits.

## Scope and limitations

This is a small internal pilot, not a hardened production service. It uses Python's built-in threaded HTTP server and JSON files for project records (SQLite for accounts). Keep it behind HTTPS and a trusted reverse proxy, restrict access to Lantern's team, and use one server instance. It does not currently include SSO, MFA, password reset, account lockout/rate limiting, per-project permissions, database migrations, or conflict resolution for simultaneous edits. An admin can remove an account and create a replacement if its password is lost. Before using sensitive client data or broad deployment, have a developer review the hosting, privacy, backup, and security setup and consider moving project storage to PostgreSQL and the server to a production-grade application server.
