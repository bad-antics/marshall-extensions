/**
 * Forensic Screenshot Capture Extension for Marshall Browser
 * Capture pages with full metadata, timestamps, and hash verification
 * Part of Marshall Extensions Collection
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class ScreenshotCapture {
  constructor(outputDir = './captures') {
    this.version = '1.0.0';
    this.outputDir = outputDir;
    this.chain = [];

    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
  }

  /**
   * Create a forensic capture record
   */
  capture(url, pageContent, screenshotBuffer = null, metadata = {}) {
    const timestamp = new Date().toISOString();
    const captureId = crypto.randomUUID();

    // Hash all evidence
    const contentHash = crypto.createHash('sha256').update(pageContent).digest('hex');
    const screenshotHash = screenshotBuffer
      ? crypto.createHash('sha256').update(screenshotBuffer).digest('hex')
      : null;

    // Chain link
    const prevHash = this.chain.length > 0
      ? this.chain[this.chain.length - 1].evidenceHash
      : '0'.repeat(64);

    const record = {
      captureId,
      timestamp,
      url,
      metadata: {
        userAgent: metadata.userAgent || 'Marshall-Browser/1.0',
        viewport: metadata.viewport || { width: 1920, height: 1080 },
        networkConditions: metadata.networkConditions || 'unknown',
        cookies: metadata.cookies || [],
        headers: metadata.responseHeaders || {},
        statusCode: metadata.statusCode || 200,
        ...metadata,
      },
      content: {
        html: pageContent.substring(0, 1000) + (pageContent.length > 1000 ? '...[TRUNCATED]' : ''),
        fullLength: pageContent.length,
        hash: contentHash,
      },
      screenshot: screenshotHash ? {
        hash: screenshotHash,
        format: 'png',
        size: screenshotBuffer.length,
      } : null,
      chain: {
        index: this.chain.length,
        previousHash: prevHash,
      },
    };

    // Compute evidence hash
    const evidencePayload = JSON.stringify({
      captureId, timestamp, url, contentHash, screenshotHash, prevHash,
    });
    record.evidenceHash = crypto.createHash('sha256').update(evidencePayload).digest('hex');

    this.chain.push(record);

    // Save to disk
    this._saveRecord(record, pageContent, screenshotBuffer);

    return record;
  }

  _saveRecord(record, fullContent, screenshot) {
    const dir = path.join(this.outputDir, record.captureId);
    fs.mkdirSync(dir, { recursive: true });

    // Metadata
    fs.writeFileSync(
      path.join(dir, 'metadata.json'),
      JSON.stringify(record, null, 2)
    );

    // Full HTML
    fs.writeFileSync(path.join(dir, 'page.html'), fullContent);

    // Screenshot
    if (screenshot) {
      fs.writeFileSync(path.join(dir, 'screenshot.png'), screenshot);
    }

    // Hash manifest
    const manifest = [
      `SHA256(metadata.json) = ${crypto.createHash('sha256').update(JSON.stringify(record)).digest('hex')}`,
      `SHA256(page.html) = ${record.content.hash}`,
    ];
    if (record.screenshot) {
      manifest.push(`SHA256(screenshot.png) = ${record.screenshot.hash}`);
    }
    fs.writeFileSync(path.join(dir, 'MANIFEST.sha256'), manifest.join('\n'));
  }

  /**
   * Verify evidence chain integrity
   */
  verifyChain() {
    const errors = [];

    for (let i = 0; i < this.chain.length; i++) {
      const record = this.chain[i];

      // Verify chain link
      if (i > 0) {
        if (record.chain.previousHash !== this.chain[i - 1].evidenceHash) {
          errors.push({
            index: i,
            type: 'CHAIN_BREAK',
            detail: `Record ${i} does not link to record ${i - 1}`,
          });
        }
      }

      // Verify temporal order
      if (i > 0) {
        const prev = new Date(this.chain[i - 1].timestamp);
        const curr = new Date(record.timestamp);
        if (curr < prev) {
          errors.push({
            index: i,
            type: 'TEMPORAL_ANOMALY',
            detail: 'Timestamp precedes previous record',
          });
        }
      }
    }

    return {
      valid: errors.length === 0,
      records: this.chain.length,
      errors,
      latestHash: this.chain.length > 0
        ? this.chain[this.chain.length - 1].evidenceHash
        : null,
    };
  }

  /**
   * Export evidence package
   */
  exportPackage() {
    return {
      tool: 'Marshall Forensic Screenshot Capture',
      version: this.version,
      exportTime: new Date().toISOString(),
      totalCaptures: this.chain.length,
      chainIntegrity: this.verifyChain(),
      captures: this.chain,
    };
  }
}

module.exports = ScreenshotCapture;
