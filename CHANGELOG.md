# Changelog

All notable changes to this project will be documented in this file.

## [2.2.1] - 2026-11-04

### Added
- **Live admin panel updates** - Sessions table and open session detail now auto-refresh every 5 seconds
  - Upload counter and total size update without page reload
  - "updated" timestamp indicator; refresh pauses while the browser tab is hidden
- **File names and hashes in admin panel** - Sessions table lists every uploaded file with its SHA-256
  - Session detail shows the full 64-character SHA-256 per file with a copy button
- **Unix release archives** - Linux/macOS builds are now shipped as `.tar.gz` so the executable bit survives download (bare binaries downloaded over HTTP lose it and fail with "permission denied")

### Fixed
- **Data race in session list APIs** - `ListSessions`/`GetSessionDetail` return deep-copy snapshots, so admin JSON encoding no longer races with concurrent uploads
- **XSS via uploaded filenames in admin panel** - All uploader-controlled strings are now HTML-escaped before rendering
- **Clipboard copy over plain HTTP** - Copy buttons use a fallback where `navigator.clipboard` is unavailable (non-HTTPS contexts)

## [2.2.0] - 2026-08-11

### Added
- **Triage collection package support** - Analysts can upload a triage package via the admin panel
  - "Send Triage Package" button in session detail modal
  - File picker for selecting the triage package
  - Public download link generated: `http://host:8443/triage/<token>`
  - Link can be shared with remote parties for file download
  - Package replace option for updating existing triage packages
- **Auto-open browser** - Application automatically opens admin interface on startup
  - Opens `http://localhost:8443/admin` in default browser
  - Platform-specific browser open (macOS: `open`, Linux: `xdg-open`, Windows: `cmd /c start`)
  - Use `-no-browser` flag to disable auto-open

## [2.1.1] - 2026-08-10

### Added
- **IP info upload before evidence** - Uploader must send IP information before uploading files
  - "Send IP Info" button uploads browser-generated IP detection report as evidence
  - Upload form disabled until IP info is sent
  - IP info file parsed by Chain of Custody PDF for detailed collector IP section

### Fixed
- **File list not showing after upload** - `handleListFiles` now uses session FolderName instead of raw token
- **SHA-256 hash files in file list** - Filtered out from uploader's file list

### Changed
- CoC PDF now shows detailed IP information from browser-uploaded file (Local IP, Public IP, Forwarded For, User Agent, etc.)

## [2.1.0] - 2026-08-10

### Added
- **Chain of Custody PDF generation** - Automatic forensic documentation when sessions end
  - PDF generated on session revocation with analyst name prompt
  - PDF generated for expired sessions (background cleanup every 5 minutes)
  - Includes: case info, evidence items with SHA-256 hashes, activity timeline, integrity verification, signature block
  - Saved as `CHAIN_OF_CUSTODY.pdf` in the case folder with `.sha256` sidecar
- **Revoke modal with analyst name** - Admin panel prompts for analyst name before revoking
- **Session expiration cleanup** - Background goroutine now properly cleans up expired sessions

### Changed
- `RevokeSession()` now returns the session object before deletion (enables CoC generation)
- `CleanupExpired()` now returns list of expired sessions (enables CoC generation for expired sessions)

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
