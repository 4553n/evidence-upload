# Evidence Upload

A secure forensic evidence data upload web application with session-based authentication, IP binding, and activity tracking.

## Features

- **Secure Upload**: HMAC-signed session tokens with IP binding
- **Resumable Uploads**: Chunked upload support for large files (10GB+)
- **Drag & Drop**: Modern upload interface with progress bars
- **Session Management**: Create, monitor, and revoke upload sessions
- **Activity Tracking**: Full audit trail of all session activities
- **Multi-channel Alerts**: Desktop, email, webhook, and log file notifications
- **Tunnel Support**: Built-in bore and Cloudflare Tunnel for internet access
- **Cross-platform**: Works on Windows, Linux, and macOS

## Quick Start

### Build

```bash
# Linux/macOS
go build -o evidence-upload .

# Windows
go build -o evidence-upload.exe .
```

### Basic Usage

```bash
# Start server on default port 8443
./evidence-upload

# Start with custom storage path
./evidence-upload -storage /path/to/evidence

# Start with bore tunnel for internet access
./evidence-upload -tunnel bore

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
| `-max-size` | `10737418240` (10GB) | Maximum upload size in bytes |
| `-alert-email` | `""` | Email address for security alerts |
| `-alert-webhook` | `""` | Webhook URL for alerts (Slack/Discord/etc) |
| `-alert-desktop` | `true` | Enable desktop notifications |
| `-alert-log` | `./alerts.log` | Log file for security alerts |
| `-external-ip` | auto-detected | External/public IP for internet access |
| `-base-url` | auto-detected | Base URL for generated links |
| `-tunnel` | `""` | Tunnel provider: `bore`, `cloudflare`, or `external` |
| `-bore-path` | auto-detected | Path to bore binary |
| `-cloudflare-path` | auto-detected | Path to cloudflared binary |
| `-cloudflare-domain` | `""` | Custom domain for Cloudflare tunnel (e.g., yourdomain.com) |
| `-tunnel-name` | `""` | Named tunnel for Cloudflare (creates if missing) |
| `-tunnel-url` | `""` | External tunnel URL (for multi-analyst mode) |
| `-version` | - | Show version and exit |

## Usage Workflow

### 1. Start the Server

```bash
./evidence-upload -port 8443 -storage /evidence -alert-email admin@corp.com
```

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
- Drag & drop upload area
- File selection button
- Progress bar during upload
- List of uploaded files with sizes

### 6. Monitor Activity

In the admin panel, click on any token to see:
- Full token and secret
- Session status (locked IP)
- Uploaded files with sizes and hashes
- Complete activity history

## Security Features

- **HMAC-signed tokens**: Each session has a unique token and secret
- **IP binding**: First access locks the session to the uploader's IP
- **No download capability**: Uploaders can only see filenames, not download
- **Session expiration**: Automatic cleanup of expired sessions
- **Alert system**: Notifications for unauthorized access attempts
- **File integrity**: SHA-256 hash computed for every uploaded file

## Tunnel Support (bore)

For internet access without router configuration:

```bash
# Auto-installs bore if missing
./evidence-upload -tunnel bore

# Use custom bore binary
./evidence-upload -tunnel bore -bore-path /usr/local/bin/bore
```

The bore tunnel creates a public URL via `bore.pub` that forwards to your local server.

**Note:** bore.pub domains may be blocked by corporate proxies. Consider Cloudflare Tunnel for trusted domain access.

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

## Platform-Specific Notes

### Windows

- Desktop notifications use Windows Toast API
- Use `-alert-desktop=true` for system tray alerts
- bore.exe may trigger Windows Defender (false positive) - whitelist if needed

### Linux

- Desktop notifications use libnotify/D-Bus
- Install `libnotify-bin` for desktop alerts: `sudo apt install libnotify-bin`
- bore binary is installed to the current directory

### macOS

- Desktop notifications use AppleScript
- bore binary is installed to the current directory

## Architecture

```
evidence-upload/
├── main.go                    # Entry point
├── version.go                 # Version constant
├── go.mod
├── internal/
│   ├── config/config.go       # CLI flags and configuration
│   ├── models/session.go      # Session management with HMAC
│   ├── storage/storage.go     # Local + backup storage
│   ├── alerts/manager.go      # Multi-channel alerts
│   ├── server/server.go       # HTTP handlers + web UI
│   └── tunnel/
│       ├── bore.go            # bore tunnel integration
│       └── cloudflare.go      # Cloudflare Tunnel integration
└── evidence-upload            # Compiled binary
```

## License

MIT License
