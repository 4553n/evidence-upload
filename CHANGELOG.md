# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - 2026-08-07

### Added
- **Cloudflare Tunnel support** - Full integration with Cloudflare tunnels
  - `-tunnel cloudflare` flag for Cloudflare tunnel mode
  - `-tunnel-token` flag for token-based authentication
  - Auto-install cloudflared binary
  - Named tunnel support
  - Custom domain support (e.g., yourdomain.com)
- **Multi-analyst mode** - `-tunnel external` for centralized tunnel deployment
  - Domain owner runs tunnel, analysts just use the URL
  - No cloudflared needed on analyst machines
- **Config file support** - `~/.evidence-upload.conf`
  - All settings can be stored in config file
  - Environment variable override with `EVIDENCE_*` prefix
  - Secure file permissions (chmod 600)
- **Incident-based folder naming** - Upload folders named after case/incident
  - Folders use sanitized description (e.g., `INC-2024-001/`)
  - Original token-based folders still supported
- **Filename sanitization** - Spaces and symbols replaced with underscores
  - `My Evidence (1).exe` → `My_Evidence_1.exe`
- **SHA-256 hash files** - Written after each successful upload
  - Compatible with `sha256sum -c` verification
  - Format: `hash  filename`
- **IP detection** - Shows both local and public IP on upload page
  - Public IP fetched from api.ipify.org
  - Download IP info as text file for documentation
- **IP detection endpoint** - `/api/my-ip` returns client IP details

### Changed
- Upload folders now use incident name instead of token hash
- Improved IP parsing for IPv6 addresses
- Updated README with Cloudflare Tunnel documentation

### Fixed
- `fmt.Fprintf` CSS/JS escaping bug
- `GetSession()` deadlock (removed delete under RLock)
- `handleUploadFile` ParseMultipartForm order
- bore binary path resolution for relative paths
- bore public port detection from stdout

## [1.0.0] - 2026-08-06

### Added
- Initial release
- Secure upload with HMAC-signed tokens
- IP binding and session locking
- Resumable chunked uploads (5MB chunks)
- Admin panel with session management
- Activity history tracking
- bore tunnel integration
- Multi-channel alerts (desktop, email, webhook, log)
- Local + network backup storage
- SHA-256 file hashing
