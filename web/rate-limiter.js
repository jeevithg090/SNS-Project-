/**
 * Fixed-window, per-source-IP rate limiter with automatic bans.
 *
 * Each source IP may send `rateLimit` SYN packets per `windowMs`. Every packet
 * over the limit within a window counts as a violation; once an IP reaches
 * `banThreshold` violations it is banned for the rest of the session.
 *
 * Works as a classic browser script (exposes `RateLimitFirewall` on the global
 * object) and as a CommonJS module for Node's test runner.
 */
(function (root) {
  'use strict';

  class RateLimitFirewall {
    constructor({ rateLimit = 15, banThreshold = 3, windowMs = 1000 } = {}) {
      this.rateLimit = rateLimit;
      this.banThreshold = banThreshold;
      this.windowMs = windowMs;
      this.reset();
    }

    /**
     * Evaluate a packet from `ip` arriving at `timestamp` (ms).
     * @returns {{action: 'ALLOW'|'BLOCK', reason: string, ip: string}}
     */
    processPacket(ip, timestamp) {
      if (this.bannedIPs.has(ip)) {
        return { action: 'BLOCK', reason: 'IP PERMANENTLY BANNED', ip };
      }

      const entry = this.ipTable.get(ip);
      if (!entry || timestamp - entry.windowStart > this.windowMs) {
        // First packet from this IP, or the previous window has elapsed.
        this.ipTable.set(ip, {
          count: 1,
          windowStart: timestamp,
          violations: entry ? entry.violations : 0,
        });
        return { action: 'ALLOW', reason: 'SYN ACCEPTED', ip };
      }

      entry.count++;

      if (entry.count > this.rateLimit) {
        entry.violations++;
        if (entry.violations >= this.banThreshold) {
          this.bannedIPs.add(ip);
          return { action: 'BLOCK', reason: `BANNED after ${entry.violations} violations`, ip };
        }
        return { action: 'BLOCK', reason: `RATE EXCEEDED (${entry.count}/${this.rateLimit} pkt/s)`, ip };
      }

      return { action: 'ALLOW', reason: 'SYN ACCEPTED', ip };
    }

    reset() {
      /** @type {Map<string, {count: number, windowStart: number, violations: number}>} */
      this.ipTable = new Map();
      /** @type {Set<string>} */
      this.bannedIPs = new Set();
    }
  }

  if (typeof module === 'object' && module.exports) {
    module.exports = { RateLimitFirewall };
  } else {
    root.RateLimitFirewall = RateLimitFirewall;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
