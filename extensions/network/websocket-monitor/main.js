/**
 * WebSocket Monitor Extension for Marshall Browser
 * Monitor, intercept, and analyze WebSocket connections
 * Part of Marshall Extensions Collection
 */

class WebSocketMonitor {
  constructor() {
    this.version = '1.0.0';
    this.connections = [];
    this.messages = [];
    this.maxMessages = 10000;
  }

  /**
   * Create a monitored WebSocket connection
   */
  createMonitored(url, protocols = []) {
    const ws = new WebSocket(url, protocols);
    const connectionId = `ws_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;

    const connection = {
      id: connectionId,
      url,
      protocols,
      openedAt: null,
      closedAt: null,
      state: 'CONNECTING',
      messageCount: { sent: 0, received: 0 },
      byteCount: { sent: 0, received: 0 },
      messages: [],
    };

    ws.addEventListener('open', () => {
      connection.openedAt = new Date().toISOString();
      connection.state = 'OPEN';
      this._recordEvent(connectionId, 'CONNECTED', { url });
    });

    ws.addEventListener('message', (event) => {
      const msg = {
        timestamp: new Date().toISOString(),
        direction: 'RECEIVED',
        type: typeof event.data === 'string' ? 'text' : 'binary',
        size: typeof event.data === 'string' ? event.data.length : event.data.byteLength,
        data: typeof event.data === 'string' ? event.data.substring(0, 4096) : '[BINARY]',
        analysis: this._analyzeMessage(event.data),
      };

      connection.messageCount.received++;
      connection.byteCount.received += msg.size;
      connection.messages.push(msg);
      this.messages.push({ connectionId, ...msg });

      // Trim if over limit
      if (this.messages.length > this.maxMessages) {
        this.messages = this.messages.slice(-this.maxMessages);
      }
    });

    ws.addEventListener('close', (event) => {
      connection.closedAt = new Date().toISOString();
      connection.state = 'CLOSED';
      connection.closeCode = event.code;
      connection.closeReason = event.reason;
      this._recordEvent(connectionId, 'DISCONNECTED', {
        code: event.code,
        reason: event.reason,
        wasClean: event.wasClean,
      });
    });

    ws.addEventListener('error', () => {
      connection.state = 'ERROR';
      this._recordEvent(connectionId, 'ERROR', { url });
    });

    // Intercept send
    const originalSend = ws.send.bind(ws);
    ws.send = (data) => {
      const msg = {
        timestamp: new Date().toISOString(),
        direction: 'SENT',
        type: typeof data === 'string' ? 'text' : 'binary',
        size: typeof data === 'string' ? data.length : data.byteLength,
        data: typeof data === 'string' ? data.substring(0, 4096) : '[BINARY]',
        analysis: this._analyzeMessage(data),
      };

      connection.messageCount.sent++;
      connection.byteCount.sent += msg.size;
      connection.messages.push(msg);
      this.messages.push({ connectionId, ...msg });

      originalSend(data);
    };

    this.connections.push(connection);
    return { ws, connectionId, connection };
  }

  _analyzeMessage(data) {
    if (typeof data !== 'string') {
      return { format: 'binary', parsed: false };
    }

    const analysis = { format: 'text', parsed: false };

    // Try JSON
    try {
      const json = JSON.parse(data);
      analysis.format = 'json';
      analysis.parsed = true;
      analysis.keys = Object.keys(json);

      // Detect common protocols
      if (json.type && json.data !== undefined) analysis.protocol = 'event-based';
      if (json.jsonrpc) analysis.protocol = 'json-rpc';
      if (json.action || json.event) analysis.protocol = 'action-based';
      if (json.op !== undefined) analysis.protocol = 'opcode-based';
      if (json.method && json.params) analysis.protocol = 'rpc';

      // Check for sensitive data
      const sensitivePatterns = ['password', 'token', 'secret', 'key', 'auth', 'session'];
      const jsonStr = JSON.stringify(json).toLowerCase();
      analysis.sensitiveData = sensitivePatterns.filter(p => jsonStr.includes(p));
    } catch {
      // Not JSON — check other formats
      if (data.startsWith('<?xml') || data.startsWith('<')) {
        analysis.format = 'xml';
      } else if (data.includes('\t') && data.split('\n').length > 1) {
        analysis.format = 'tsv';
      }
    }

    return analysis;
  }

  _recordEvent(connectionId, type, detail) {
    // Event logging for audit trail
  }

  /**
   * Get statistics for all connections
   */
  getStats() {
    const stats = {
      totalConnections: this.connections.length,
      active: this.connections.filter(c => c.state === 'OPEN').length,
      closed: this.connections.filter(c => c.state === 'CLOSED').length,
      errors: this.connections.filter(c => c.state === 'ERROR').length,
      totalMessages: this.messages.length,
      totalBytesSent: this.connections.reduce((sum, c) => sum + c.byteCount.sent, 0),
      totalBytesReceived: this.connections.reduce((sum, c) => sum + c.byteCount.received, 0),
    };

    // Protocol breakdown
    const protocols = {};
    for (const msg of this.messages) {
      const proto = msg.analysis?.protocol || 'unknown';
      protocols[proto] = (protocols[proto] || 0) + 1;
    }
    stats.protocols = protocols;

    return stats;
  }

  /**
   * Search messages
   */
  searchMessages(query, options = {}) {
    return this.messages.filter(msg => {
      if (options.direction && msg.direction !== options.direction) return false;
      if (options.connectionId && msg.connectionId !== options.connectionId) return false;
      if (query && !msg.data.toLowerCase().includes(query.toLowerCase())) return false;
      return true;
    });
  }

  /**
   * Export captured data
   */
  export() {
    return {
      tool: 'Marshall WebSocket Monitor',
      version: this.version,
      exportTime: new Date().toISOString(),
      stats: this.getStats(),
      connections: this.connections,
      messages: this.messages,
    };
  }
}

module.exports = WebSocketMonitor;
