'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { RateLimitFirewall } = require(path.join(__dirname, '..', '..', 'web', 'rate-limiter.js'));

function burst(fw, ip, count, timestamp = 0) {
  return Array.from({ length: count }, () => fw.processPacket(ip, timestamp));
}

test('allows traffic up to the rate limit within a window', () => {
  const fw = new RateLimitFirewall({ rateLimit: 5, banThreshold: 3 });
  const results = burst(fw, '10.0.0.1', 5);
  assert.ok(results.every((r) => r.action === 'ALLOW'));
});

test('blocks packets over the limit and reports the rate', () => {
  const fw = new RateLimitFirewall({ rateLimit: 2, banThreshold: 5 });
  burst(fw, '10.0.0.1', 2);
  const over = fw.processPacket('10.0.0.1', 10);
  assert.equal(over.action, 'BLOCK');
  assert.equal(over.reason, 'RATE EXCEEDED (3/2 pkt/s)');
  assert.equal(fw.bannedIPs.size, 0);
});

test('bans an IP once violations reach the threshold', () => {
  const fw = new RateLimitFirewall({ rateLimit: 1, banThreshold: 2 });
  fw.processPacket('6.6.6.6', 0);
  assert.equal(fw.processPacket('6.6.6.6', 1).reason, 'RATE EXCEEDED (2/1 pkt/s)');
  const banned = fw.processPacket('6.6.6.6', 2);
  assert.equal(banned.reason, 'BANNED after 2 violations');
  assert.ok(fw.bannedIPs.has('6.6.6.6'));
  // Bans are permanent, even after the window resets.
  assert.equal(fw.processPacket('6.6.6.6', 10_000).reason, 'IP PERMANENTLY BANNED');
});

test('counter resets after the window elapses but violations persist', () => {
  const fw = new RateLimitFirewall({ rateLimit: 1, banThreshold: 2, windowMs: 1000 });
  fw.processPacket('1.2.3.4', 0);
  assert.equal(fw.processPacket('1.2.3.4', 500).action, 'BLOCK'); // violation 1
  assert.equal(fw.processPacket('1.2.3.4', 1600).action, 'ALLOW'); // new window
  assert.equal(fw.processPacket('1.2.3.4', 1700).reason, 'BANNED after 2 violations');
});

test('rate limits are tracked independently per source IP', () => {
  const fw = new RateLimitFirewall({ rateLimit: 1, banThreshold: 1 });
  fw.processPacket('attacker', 0);
  fw.processPacket('attacker', 0);
  assert.ok(fw.bannedIPs.has('attacker'));
  assert.equal(fw.processPacket('legit', 0).action, 'ALLOW');
});

test('settings can be changed at runtime', () => {
  const fw = new RateLimitFirewall({ rateLimit: 1, banThreshold: 10 });
  fw.processPacket('a', 0);
  fw.rateLimit = 5;
  assert.equal(fw.processPacket('a', 1).action, 'ALLOW');
});

test('reset clears state and bans', () => {
  const fw = new RateLimitFirewall({ rateLimit: 1, banThreshold: 1 });
  burst(fw, 'x', 2);
  fw.reset();
  assert.equal(fw.bannedIPs.size, 0);
  assert.equal(fw.ipTable.size, 0);
  assert.equal(fw.processPacket('x', 0).action, 'ALLOW');
});
