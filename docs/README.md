# Marshall Extensions Documentation

## Overview

Marshall Extensions is the extension pack for the [Marshall](https://github.com/bad-antics/marshall) privacy browser. Extensions are sandboxed WebExtension-compatible plugins that enhance Marshall's privacy and security capabilities.

## Included Extensions

| Extension | Purpose |
|-----------|---------|
| NullSec Shield | Advanced tracker blocking |
| Privacy Redirect | Redirect to privacy-respecting frontends |
| Cookie Fortress | Intelligent cookie management |
| Fingerprint Guard | Enhanced anti-fingerprinting |
| HTTPS Everywhere | Force HTTPS connections |
| Decentraleyes | Local CDN emulation |
| Script Control | Fine-grained JavaScript control |
| Header Editor | HTTP header manipulation |

## Extension Architecture

Marshall extensions use the WebExtension API with additional privacy-focused APIs:

```javascript
// Marshall-specific APIs
browser.privacy.antiFingerprint.enable({
    canvas: true,
    webgl: true,
    audio: true
});

browser.privacy.tracking.block({
    lists: ["easylist", "easyprivacy", "nullsec-shield"],
    mode: "strict"
});
```

## Development

```bash
# Build an extension
cd extensions/my-extension
npm run build

# Load in Marshall for testing
marshall --load-extension=./dist

# Package for distribution
marshall-ext pack ./dist -o my-extension.mex
```

## Security Model

All extensions run in isolated sandboxes with minimal permissions. Each extension must declare required permissions in its manifest, and users are prompted before granting sensitive access.
