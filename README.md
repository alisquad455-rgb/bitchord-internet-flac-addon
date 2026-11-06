# BitChord Internet Archive FLAC

A small BitChord HTTP addon that searches Internet Archive audio items and returns direct `.flac` files only when the item declares a Creative Commons or Creative Commons public-domain license URL.

## Important quality limits

- `Lossless FLAC` means the selected file is a FLAC file. FLAC is lossless, but this project does **not** assume every FLAC is 16-bit/44.1 kHz.
- `Hi-Res FLAC` is returned only if Internet Archive file metadata explicitly reports at least 24-bit and 88.2 kHz. Internet Archive often does not expose those fields, so the Hi-Res option may return no results.
- It never transcodes MP3/AAC into FLAC and never labels lossy files as lossless.
- Rights are checked conservatively using `metadata.licenseurl`; users should still review the item's license/terms before downloading or reusing it.

## Deploy on Render / Railway / any Node host

1. Upload this folder to a Git repository you control.
2. Create a new Web Service from that repository.
3. Runtime: Node 20 or newer. Build command: `npm install` (no third-party dependencies). Start command: `npm start`.
4. Set environment variable `PUBLIC_HOSTS` to the exact public hostname, without `https://`, port, or path. Example: `my-addon.onrender.com`.
5. Deploy and wait for the service to become healthy.

## Add to BitChord

In BitChord open **Settings → Sources → Add an addon** and paste:

`https://YOUR-HOSTNAME/manifest.json`

Replace `YOUR-HOSTNAME` with your deployed hostname.

## Local test

```bash
cp .env.example .env
# Edit PUBLIC_HOSTS to localhost only for local auth tests; official BitChord proof
# is host-bound, so actual BitChord use requires your deployed HTTPS hostname.
npm start
```

Open `http://localhost:8787/health` and `http://localhost:8787/manifest.json` in a browser. Search and stream routes require valid BitChord authentication and will return 401 to browsers/curl.

## Routes

- `GET /manifest.json` — public addon manifest.
- `GET /search?q=artist%20title&quality=lossless` — BitChord-authenticated search.
- `GET /stream/{id}?quality=lossless` — resolves the selected FLAC file.
- `GET /health` — simple health status.

## Authentication

The server implements BitChord's documented token + hardware-backed proof verification. It fetches and caches the official BitChord JWKS, checks the EdDSA token, validates claims and verifies the P-256 device proof for the configured hostname. The manifest is public; search and stream are protected.

If auth fails, check:
- `PUBLIC_HOSTS` exactly matches the hostname in the URL pasted into BitChord.
- The deployment host has outbound HTTPS access to `bitchord-auth.kushagrasingh.in`.
- Server clock is synchronized.

## Data source

Internet Archive Advanced Search API and public item metadata API:
- `https://archive.org/advancedsearch.php`
- `https://archive.org/metadata/{identifier}`

The addon uses public metadata and links directly to the archive's original FLAC file; it does not host or mirror audio.

## Disclaimer

This is an unofficial community addon, not affiliated with BitChord or Internet Archive. Availability and metadata quality depend on Internet Archive. Respect the license and terms for each item.
