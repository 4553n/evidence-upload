# Evidence Upload

A secure forensic evidence data upload web application with session-based authentication, IP binding, activity tracking, and Chain of Custody PDF generation.

## User Manual

An illustrated user manual — installation, admin panel, uploader flow, Chain of
Custody, tunnels, HTTPS, and troubleshooting — is available at
[`docs/user-manual/Evidence-Upload-User-Manual-v2.2.7.pdf`](docs/user-manual/Evidence-Upload-User-Manual-v2.2.7.pdf)
(HTML source and screenshots in the same directory).

## Features

- **Secure Upload**: HMAC-signed session tokens with IP binding
- **Resumable Uploads**: Chunked upload support for large files (10GB+)
- **Drag & Drop**: Modern upload interface with progress bars
- **Session Management**: Create, monitor, and revoke upload sessions; links survive server restarts
- **Activity Tracking**: Full audit trail of all session activities
- **Chain of Custody PDF**: Automatic forensic documentation on session revocation/expiration
- **Triage Collection Package**: Upload and share triage packages with remote parties
- **IP Detection**: Records both the server's and the uploader's IPs for forensic documentation
- **Auto-open Browser**: Admin interface opens automatically on startup
- **Config File Support**: Persistent configuration via `~/.evidence-upload.conf`
- **Multi-channel Alerts**: Desktop, email, webhook, and log file notifications
- **Tunnel Support**: Built-in bore and Cloudflare Tunnel for internet access
- **Cross-platform**: Works on Windows, Linux, and macOS

## Quick Start

### Download Prebuilt Binaries

Grab the archive for your platform from the [Releases page](https://github.com/4553n/evidence-upload/releases). Unix builds ship as `.tar.gz` — extracting restores the executable bit:

```bash
# macOS (Apple Silicon)
tar -xzf evidence-upload-v2.2.0-macos-arm64.tar.gz
./evidence-upload-v2.2.0-macos-arm64

# macOS (Intel)
tar -xzf evidence-upload-v2.2.0-macos-amd64.tar.gz

# Linux
tar -xzf evidence-upload-v2.2.0-linux-amd64.tar.gz

# Windows: download evidence-upload-v2.2.0-windows-amd64.exe and run it
```

**macOS note**: if you downloaded a bare binary (not the archive) or macOS says
"cannot be opened because the developer cannot be verified", fix it with:

```bash
chmod +x evidence-upload-v2.2.0-macos-arm64            # restore executable bit
xattr -d com.apple.quarantine evidence-upload-v2.2.0-macos-arm64  # clear Gatekeeper quarantine
```

Or right-click the binary → **Open** → **Open** to bypass Gatekeeper once.

### Build

```bash
# Linux/macOS
go build -o evidence-upload .

# Windows
go build -o evidence-upload.exe .
```

### Basic Usage

```bash
# Start server on default port 8443 — with secure defaults:
# a public bore tunnel and HTTPS (self-signed certificate)
./evidence-upload

# Start with custom storage path
./evidence-upload -storage /path/to/evidence

# LAN only, no tunnel
./evidence-upload -tunnel=

# Plain HTTP (not recommended)
./evidence-upload -tls-selfsigned=false -tunnel=

# Start without auto-opening browser
./evidence-upload -no-browser

# Show version
./evidence-upload -version
```

## Command Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-port` | `8443` | Server port |
| `-storage` | `./evidence` | Local storage path for uploaded files |
| `-backup` | `""` | Network share backup path (optional) |
| `-expire` | `24h` | Default session expiration duration |
| `-secret` | auto-generated | HMAC secret key |
| `-admin-token` | auto-generated | Admin panel token (printed at startup) |
| `-tls-cert` | `""` | TLS certificate file for HTTPS (use with `-tls-key`) |
| `-tls-key` | `""` | TLS private key file for HTTPS |
| `-tls-selfsigned` | `true` | Serve HTTPS with an auto-generated self-signed certificate |
| `-max-size` | `10737418240` (10GB) | Maximum upload size in bytes |
| `-alert-email` | `""` | Email address for security alerts |
| `-alert-webhook` | `""` | Webhook URL for alerts (Slack/Discord/etc) |
| `-alert-desktop` | `true` | Enable desktop notifications |
| `-alert-log` | `./alerts.log` | Log file for security alerts |
| `-external-ip` | auto-detected | External/public IP for internet access |
| `-base-url` | auto-detected | Base URL for generated links |
| `-tunnel` | `bore` | Tunnel provider: `bore`, `cloudflare`, or `external` (empty value disables) |
| `-bore-path` | — | Deprecated: the bore tunnel client is built in, flag ignored |
| `-cloudflare-path` | auto-detected | Path to cloudflared binary |
| `-cloudflare-domain` | `""` | Custom domain for Cloudflare tunnel (e.g., yourdomain.com) |
| `-cloudflare-token` | `""` | Cloudflare tunnel token (from dashboard) |
| `-tunnel-name` | `""` | Named tunnel for Cloudflare (creates if missing) |
| `-tunnel-url` | `""` | External tunnel URL (for multi-analyst mode) |
| `-no-browser` | `false` | Don't automatically open browser on startup |
| `-version` | - | Show version and exit |

## Configuration File

Settings can be persisted in `~/.evidence-upload.conf` (Linux/macOS) or `%USERPROFILE%\.evidence-upload.conf` (Windows).

**Priority order:** CLI flags > Environment variables (`EVIDENCE_*`) > Config file > Defaults

```ini
# Evidence Upload Configuration
# Security: Set permissions to 600 after editing: chmod 600 ~/.evidence-upload.conf

# Cloudflare Tunnel Settings
CLOUDFLARE_TOKEN=eyJ...your-token-here...
CLOUDFLARE_DOMAIN=yourdomain.com
TUNNEL_NAME=evidence-upload

# Server Settings
PORT=8443
STORAGE=./evidence
BACKUP=/nas/backup/evidence

# Session Settings
EXPIRE=24h

# Security Settings
# SECRET=your-secret-key-here

# Alert Settings
ALERT_EMAIL=security@yourdomain.com
ALERT_WEBHOOK=https://hooks.slack.com/services/xxx

# External IP (auto-detected if empty)
# EXTERNAL_IP=203.0.113.45

# Base URL (auto-detected if empty)
# BASE_URL=https://evidence.yourdomain.com
```

## Usage Workflow

### 1. Start the Server

```bash
./evidence-upload -port 8443 -storage /evidence -alert-email admin@corp.com
```

The browser will automatically open to the admin interface at `http://localhost:8443/admin`. Use `-no-browser` to disable this behavior.

### 2. Access Admin Panel

Open browser to `http://<server-ip>:8443/admin`

### 3. Create Upload Session

- Click "Create New Session"
- Set duration (hours)
- Add description (case number, incident ID, etc.)
- Click "Generate Link"

### 4. Share Upload Link

Copy the generated link and send it to the uploading party.

### 5. Uploader Access

The uploader opens the link and sees:
- Case reference number
- IP detection section (must send IP info first)
- Drag & drop upload area
- File selection button
- Progress bar during upload
- List of uploaded files with sizes

### 6. Send Triage Package (Optional)

If you have a triage collection package to share:

- In the admin panel, click on the session token
- Click "Send Triage Package" in the session detail modal
- Select the triage package file
- A download link is generated: `http://host:8443/triage/<token>`
- Share this link with the remote party

### 7. Monitor Activity

In the admin panel, click on any token to see:
- Full token and secret
- Session status (locked IP)
- Uploaded files with sizes and hashes
- Complete activity history
- Triage package status and download link

### 8. Revoke Session

When evidence collection is complete:
- Click "Revoke" on the session
- Enter analyst name for Chain of Custody document
- CoC PDF is generated in the case folder

## Triage Collection Package

The triage package feature allows analysts to share a collection tool with remote parties.

### Workflow

1. **Analyst**: Creates a session in the admin panel
2. **Analyst**: Clicks "Send Triage Package" and selects the file
3. **Analyst**: Shares the generated download link with the remote party
4. **Remote Party**: Downloads the triage package via the link
5. **Remote Party**: Runs the triage package to collect and upload evidence

### Features

- **Per-session**: Each session can have its own triage package
- **Public download**: No authentication required to download the package
- **Replaceable**: Analyst can replace the package with a new version
- **Auto-named**: Files are stored as `TRIAGE_PACKAGE_<original_filename>`

### Download Link Format

```
http://<host>:<port>/triage/<session-token>
```

The link is public and does not require the session secret.

## Security Features

- **Admin token auth**: Admin panel and API require a token (`-admin-token` / `ADMIN_TOKEN`), auto-generated at startup
- **HMAC-signed tokens**: Each session has a unique token and secret
- **IP binding**: First access locks the session to the uploader's IP
- **IP detection**: Browser uploads IP information as first evidence file
- **No download capability**: Uploaders can only see filenames, not download
- **Session expiration**: Automatic cleanup of expired sessions
- **Chain of Custody PDF**: Generated on revocation/expiration with full audit trail
- **Alert system**: Notifications for unauthorized access attempts
- **File integrity**: SHA-256 hash computed for every uploaded file (saved as `.sha256` sidecar)

## Admin Authentication

The admin panel and its API are protected by an admin token. **Without it, anyone
who can reach the server — including the internet, if you run a tunnel — can list
sessions, take over upload links, and revoke sessions.**

- The token is **auto-generated at startup and printed to the console**:
  ```
  Admin token: 3f2a...  (keep private; set via -admin-token or ADMIN_TOKEN)
  ```
- Set your own with `-admin-token <token>` or `ADMIN_TOKEN=<token>` in the config file
- The admin panel prompts for the token once and remembers it in `sessionStorage`
- The auto-opened admin URL carries the token (`/admin?key=...`); it is removed
  from the address bar after loading
- API clients send it as `X-Admin-Token: <token>` or `Authorization: Bearer <token>`
- The upload flow (`/api/...`) does **not** use the admin token — uploaders
  authenticate with their session token+secret as before

**Treat the admin token like a password.** bore tunnels are plaintext TCP — pair
them with `-tls-selfsigned` (or your own certificate via `-tls-cert`/`-tls-key`)
so traffic is encrypted end-to-end, or use Cloudflare Tunnel (HTTPS), optionally
fronted with Cloudflare Access for SSO. Upload secrets are never returned by the
session list API — only the per-session detail endpoint provides them.

## Chain of Custody PDF

When a session is revoked or expires, a Chain of Custody PDF is automatically generated containing:

- Case information (description, token, dates, status)
- Collector IP information (from uploaded IP detection file)
- Evidence items table (filename, size, SHA-256 hash)
- Activity timeline (all actions with timestamps)
- Integrity verification details
- Certification statement with analyst signature block

The PDF is saved as `CHAIN_OF_CUSTODY.pdf` in the case folder with a `.sha256` sidecar file.

Text is rendered with embedded DejaVu Sans fonts (Bitstream Vera license), so case
descriptions and names in UTF-8 — em-dashes, umlauts, Cyrillic, Greek, Hebrew —
render correctly. Characters the fonts cannot display (emoji, CJK) are marked
with `�` rather than breaking document generation.

## HTTPS / TLS

HTTPS is **enabled by default** (auto-generated self-signed certificate), so
evidence and credentials are encrypted end-to-end between the uploader's browser
and your server — even through a plaintext tunnel like bore, only ciphertext
crosses the network.

```bash
# Zero-config: auto-generated self-signed certificate (stored in <storage>/.tls/)
./evidence-upload -tls-selfsigned

# Your own certificate (removes browser warnings for uploaders)
./evidence-upload -tls-cert /path/to/fullchain.pem -tls-key /path/to/privkey.pem
```

- With `-tls-selfsigned` the certificate is generated once and reused across
  restarts (stable browser exception), covers `localhost`, `127.0.0.1`, the
  machine hostname, and `-external-ip` if set, and its **SHA-256 fingerprint is
  printed at startup** for out-of-band verification
- Self-signed certificates trigger a one-time browser warning for uploaders —
  they can proceed after confirming the fingerprint; use `-tls-cert`/`-tls-key`
  with a real certificate (e.g. Let's Encrypt) to remove it
- Generated links automatically use `https://` when TLS is enabled

## Tunnel Support (bore)

For internet access without router configuration:

```bash
# Auto-installs bore if missing
./evidence-upload -tunnel bore

# Use custom bore binary
./evidence-upload -tunnel bore -bore-path /usr/local/bin/bore
```

The bore tunnel creates a public URL via `bore.pub` that forwards to your local server.
The tunnel client is **built into the application** — nothing is downloaded or
installed at startup; the single executable speaks the tunnel protocol itself.

**Note:** bore.pub domains may be blocked by corporate proxies. Consider Cloudflare Tunnel for trusted domain access.

**Security:** bore itself does not encrypt traffic — run the server with
`-tls-selfsigned` (or `-tls-cert`/`-tls-key`) so uploads and credentials are
encrypted end-to-end inside the tunnel.

## Tunnel Support (Cloudflare)

Cloudflare Tunnel provides a trusted domain that's less likely to be blocked by proxies.

### Prerequisites

1. Install cloudflared:
   ```bash
   # Linux
   curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared
   chmod +x /usr/local/bin/cloudflared

   # macOS
   brew install cloudflared

   # Windows: Download from https://github.com/cloudflare/cloudflared/releases
   ```

2. Authenticate with Cloudflare:
   ```bash
   cloudflared tunnel login
   # Opens browser - select your domain (e.g., yourdomain.com)
   ```

### Quick Tunnel (Temporary URL)

```bash
./evidence-upload -tunnel cloudflare
# Returns URL like: https://random-name.trycloudflare.com
```

### Named Tunnel (Stable Subdomain)

```bash
# Create tunnel (first time only)
cloudflared tunnel create evidence-upload

# Route DNS (first time only)
cloudflared tunnel route dns evidence-upload evidence.yourdomain.com

# Run with named tunnel
./evidence-upload -tunnel cloudflare -tunnel-name evidence-upload
```

### Custom Domain

```bash
# Use your domain for the tunnel
./evidence-upload -tunnel cloudflare -cloudflare-domain yourdomain.com -tunnel-name evidence-upload
```

This creates URLs like: `https://evidence.yourdomain.com`

### Full Example with yourdomain.com

```bash
# One-time setup
cloudflared tunnel login
cloudflared tunnel create evidence-upload
cloudflared tunnel route dns evidence-upload evidence.yourdomain.com

# Start server with tunnel
./evidence-upload \
  -port 8443 \
  -storage /evidence \
  -tunnel cloudflare \
  -tunnel-name evidence-upload \
  -cloudflare-domain yourdomain.com
```

Access at: `https://evidence.yourdomain.com`

### Benefits over bore

- **Trusted domain**: Your domain (yourdomain.com) is less likely blocked
- **HTTPS included**: Free valid certificate
- **Stable URLs**: No random ports or changing addresses
- **Corporate friendly**: Works with proxies that trust Cloudflare
- **Free**: No cost for personal use

## Multi-Analyst Setup

For teams where multiple forensic analysts need to use the app without accessing Cloudflare credentials.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Domain Owner (yourdomain.com)                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  cloudflared tunnel --url http://COORDINATOR:PORT      │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Coordinator Server                                         │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  evidence-upload -port 8443 -tunnel external            │ │
│  │  -tunnel-url https://evidence.yourdomain.com             │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Analyst Machines (no Cloudflare credentials needed)        │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  evidence-upload -port 8443 -tunnel external            │ │
│  │  -tunnel-url https://evidence.yourdomain.com             │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Setup Instructions

**Domain Owner (one-time setup):**

```bash
# 1. Install and authenticate cloudflared
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared
chmod +x /usr/local/bin/cloudflared
cloudflared tunnel login

# 2. Create tunnel
cloudflared tunnel create evidence-ops
cloudflared tunnel route dns evidence-ops evidence.yourdomain.com

# 3. Run tunnel (as a service or long-running process)
cloudflared tunnel run evidence-ops
```

**Analyst Setup (no credentials needed):**

```bash
# Just run the app with the shared tunnel URL
./evidence-upload \
  -port 8443 \
  -storage /path/to/evidence \
  -tunnel external \
  -tunnel-url https://evidence.yourdomain.com
```

### Benefits for Multi-Analyst

- **No credentials shared**: Analysts don't need Cloudflare login
- **No installation**: Analysts don't need cloudflared installed
- **Simple setup**: Just run the binary with a URL
- **Isolated storage**: Each analyst has their own local storage
- **Centralized access**: One domain for all analysts

### Coordination Options

**Option 1: Different ports**
```bash
# Analyst 1
./evidence-upload -port 8443 -tunnel external -tunnel-url https://evidence.yourdomain.com

# Analyst 2
./evidence-upload -port 8444 -tunnel external -tunnel-url https://evidence.yourdomain.com
```

**Option 2: Different subdomains**
```bash
# Domain owner runs multiple tunnels
cloudflared tunnel --url http://analyst1:8443  # analyst1.evidence.yourdomain.com
cloudflared tunnel --url http://analyst2:8443  # analyst2.evidence.yourdomain.com

# Analysts use their assigned subdomain
./evidence-upload -port 8443 -tunnel external -tunnel-url https://analyst1.evidence.yourdomain.com
./evidence-upload -port 8443 -tunnel external -tunnel-url https://analyst2.evidence.yourdomain.com
```

## Examples

### Local Network Deployment

```bash
./evidence-upload -port 8443 -storage /mnt/evidence
```

Access from any device on the network: `http://192.168.1.100:8443/admin`

### Internet Deployment with Tunnel

```bash
./evidence-upload -port 8443 -storage /evidence -tunnel bore
```

The server will output the public bore URL to share with uploaders.

### Full Production Setup

```bash
./evidence-upload \
  -port 8443 \
  -storage /mnt/data/evidence \
  -backup /nas/backup/evidence \
  -expire 48h \
  -alert-email ir-team@corp.com \
  -alert-webhook https://hooks.slack.com/services/xxx \
  -alert-log /var/log/evidence-upload.log
```

### Headless Setup (No Browser)

```bash
./evidence-upload -no-browser -port 8443 -storage /evidence
```

## Platform-Specific Notes

### Windows

- Desktop notifications use Windows Toast API
- Use `-alert-desktop=true` for system tray alerts
- bore.exe may trigger Windows Defender (false positive) - whitelist if needed
- Browser opens with `cmd /c start`

### Linux

- Desktop notifications use libnotify/D-Bus
- Install `libnotify-bin` for desktop alerts: `sudo apt install libnotify-bin`
- bore binary is installed to the current directory
- Browser opens with `xdg-open`

### macOS

- Desktop notifications use AppleScript
- bore binary is installed to the current directory
- Browser opens with `open`

## Architecture

```
evidence-upload/
├── main.go                    # Entry point + browser open logic
├── version.go                 # Version constant
├── go.mod
├── internal/
│   ├── config/config.go       # CLI flags and configuration
│   ├── models/session.go      # Session management with HMAC
│   ├── storage/storage.go     # Local + backup storage
│   ├── custody/custody.go     # Chain of Custody PDF generation
│   ├── alerts/manager.go      # Multi-channel alerts
│   ├── server/server.go       # HTTP handlers + web UI
│   └── tunnel/
│       ├── bore.go            # bore tunnel integration
│       └── cloudflare.go      # Cloudflare Tunnel integration
└── evidence-upload            # Compiled binary
```

## License

MIT License
