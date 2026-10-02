/**
 * Continuity spending kernel — ORIGINAL OFFLINE REFERENCE MODEL, NOT A WALLET.
 * No signatures, custody, blockchain, real funds, networking, persistence, or issuer.
 * Admin operations and settlement evidence are assumed to come from trusted callers.
 * The model explores serialized budget/authority invariants; do not use for money.
 */
import { createHash } from 'node:crypto';

const MAX = (1n << 127n) - 1n;
const fail = (message) => { throw new Error(message); };
const copy = value => structuredClone(value);
function id(value) {
  if (typeof value !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,127}$/.test(value)) fail('invalid identifier');
  return value;
}
function units(value, positive = false) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,38})$/.test(value)) fail('amount must be canonical integer string');
  const amount = BigInt(value);
  if (amount > MAX || (positive && amount === 0n)) fail('amount outside bounds');
  return amount;
}
function clock(value) {
  if (!Number.isSafeInteger(value) || value < 0) fail('invalid trusted time');
  return value;
}
function choices(value) {
  if (!Array.isArray(value) || !value.length || value.length > 64) fail('explicit nonempty allowlist required');
  const result = value.map(id);
  if (new Set(result).size !== result.length) fail('duplicate allowlist entry');
  return result;
}
function subset(child, parent) { return child.every(item => parent.includes(item)); }

export class Kernel {
  #accounts = new Map();
  #grants = new Map();
  #intents = new Map();
  #lastTime = 0;
  #ledger;
  constructor(ledgerId = 'offline-simulation') { this.#ledger = id(ledgerId); }
  #account(name) { return this.#accounts.get(name) ?? fail('unknown account'); }
  #grant(name) { return this.#grants.get(name) ?? fail('unknown grant'); }
  #intent(name) { return this.#intents.get(name) ?? fail('unknown intent'); }
  #time(now) { clock(now); if (now < this.#lastTime) fail('clock regression'); }
  #chain(grant) {
    const result = [];
    let current = grant;
    while (current) {
      result.push(current);
      if (result.length > 8) fail('delegation too deep');
      current = current.parent ? this.#grant(current.parent) : null;
    }
    return result;
  }
  #usable(grant, account, now) {
    if (grant.epoch !== account.epoch || grant.revoked) fail('stale or revoked authority');
    if (now < grant.notBefore || now >= grant.expiresAt) fail('outside mandate window');
  }
  // TRUSTED OPERATOR ONLY. These are fictitious balances, not issued stablecoins.
  createAccount({ accountId, spendable, protectedContinuity = '0' }) {
    id(accountId); units(spendable); units(protectedContinuity);
    if (this.#accounts.has(accountId)) fail('account already exists');
    this.#accounts.set(accountId, { id: accountId, epoch: 0, opening: spendable,
      available: spendable, pending: '0', spent: '0', protectedContinuity });
    return this.account(accountId);
  }
  // TRUSTED OPERATOR ONLY. A child never increases its ancestor's authority.
  grant({ grantId, accountId, parent = null, limit, payees, rails, notBefore, expiresAt }, now) {
    this.#time(now); id(grantId); id(accountId); units(limit, true);
    clock(notBefore); clock(expiresAt);
    if (expiresAt <= notBefore || now < notBefore || now >= expiresAt) fail('invalid grant window');
    const allowedPayees = choices(payees), allowedRails = choices(rails);
    const account = this.#account(accountId);
    if (this.#grants.has(grantId)) fail('grant identifier cannot be reused');
    if (parent !== null) {
      id(parent);
      const ancestor = this.#grant(parent), chain = this.#chain(ancestor);
      if (chain.length >= 8) fail('delegation too deep');
      for (const item of chain) this.#usable(item, account, now);
      if (ancestor.accountId !== accountId || !subset(allowedPayees, ancestor.payees)
        || !subset(allowedRails, ancestor.rails) || units(limit) > units(ancestor.limit)
        || notBefore < ancestor.notBefore || expiresAt > ancestor.expiresAt) fail('delegation widens authority');
    }
    this.#grants.set(grantId, { id: grantId, accountId, parent, epoch: account.epoch,
      limit, pending: '0', spent: '0', payees: allowedPayees, rails: allowedRails,
      notBefore, expiresAt, revoked: false });
    this.#lastTime = now;
    return this.grantState(grantId);
  }
  reserve({ intentId, grantId, epoch, payee, rail, amount }, now) {
    this.#time(now); id(intentId); id(grantId); id(payee); id(rail); units(amount, true);
    if (!Number.isSafeInteger(epoch) || epoch < 0) fail('invalid epoch');
    // Canonical, ordered, domain-separated digest: not an authentication signature.
    const fields = { domain: 'continuity-spend/v0', ledger: this.#ledger, intentId, grantId, epoch, payee, rail, amount };
    const digest = createHash('sha256').update(JSON.stringify(fields)).digest('hex');
    const previous = this.#intents.get(intentId);
    if (previous) {
      if (previous.digest !== digest) fail('idempotency conflict');
      return { intent: copy(previous), created: false }; // Never dispatch merely on a retry.
    }
    const grant = this.#grant(grantId), account = this.#account(grant.accountId);
    if (epoch !== account.epoch) fail('stale authority epoch');
    const chain = this.#chain(grant), n = units(amount);
    for (const item of chain) {
      this.#usable(item, account, now);
      if (!item.payees.includes(payee) || !item.rails.includes(rail)) fail('not allowlisted');
      if (units(item.spent) + units(item.pending) + n > units(item.limit)) fail('shared mandate budget exceeded');
    }
    if (units(account.available) < n) fail('spendable funds insufficient');
    // Validate every precondition before any mutation. Calls are synchronous/serialized.
    account.available = (units(account.available) - n).toString();
    account.pending = (units(account.pending) + n).toString();
    for (const item of chain) item.pending = (units(item.pending) + n).toString();
    const intent = { ...fields, accountId: account.id, digest, state: 'reserved', receipt: null };
    this.#intents.set(intentId, intent); this.#lastTime = now;
    return { intent: copy(intent), created: true };
  }
  // Called before a hypothetical external send. Dispatch eligibility is checked again.
  dispatch(intentId, now) {
    this.#time(now);
    const intent = this.#intent(intentId);
    if (intent.state !== 'reserved') fail('intent is not dispatchable');
    const grant = this.#grant(intent.grantId), account = this.#account(intent.accountId);
    for (const item of this.#chain(grant)) this.#usable(item, account, now);
    intent.state = 'dispatched'; this.#lastTime = now;
    return copy(intent);
  }
  markUnknown(intentId) {
    const intent = this.#intent(intentId);
    if (!['dispatched', 'unknown'].includes(intent.state)) fail('intent was not dispatched');
    intent.state = 'unknown'; // Still reserved. Timeout is NOT proof of nonpayment.
    return copy(intent);
  }
  #release(intent) {
    const n = units(intent.amount), account = this.#account(intent.accountId);
    account.available = (units(account.available) + n).toString();
    account.pending = (units(account.pending) - n).toString();
    for (const grant of this.#chain(this.#grant(intent.grantId))) grant.pending = (units(grant.pending) - n).toString();
  }
  cancelBeforeDispatch(intentId) {
    const intent = this.#intent(intentId);
    if (intent.state !== 'reserved') fail('cannot cancel uncertain or sent payment');
    this.#release(intent); intent.state = 'cancelled'; return copy(intent);
  }
  // TRUSTED SETTLEMENT ADAPTER ONLY. receiptId is recorded, NOT cryptographically verified.
  reconcile(intentId, outcome, receiptId) {
    const intent = this.#intent(intentId); id(receiptId);
    if (!['settled', 'not-settled'].includes(outcome)) fail('invalid settlement outcome');
    const end = outcome === 'settled' ? 'settled' : 'released';
    if (intent.state === end && intent.receipt === receiptId) return copy(intent);
    if (!['dispatched', 'unknown'].includes(intent.state)) fail('not reconcilable');
    if (outcome === 'not-settled') this.#release(intent);
    else {
      const account = this.#account(intent.accountId), n = units(intent.amount);
      account.pending = (units(account.pending) - n).toString();
      account.spent = (units(account.spent) + n).toString();
      for (const grant of this.#chain(this.#grant(intent.grantId))) {
        grant.pending = (units(grant.pending) - n).toString();
        grant.spent = (units(grant.spent) + n).toString();
      }
    }
    intent.state = end; intent.receipt = receiptId; return copy(intent);
  }
  // TRUSTED OPERATOR ONLY. Revocation stops NEW dispatch, not earlier external payments.
  revoke(grantId) { this.#grant(grantId).revoked = true; }
  rotateAuthority(accountId) {
    const account = this.#account(accountId);
    if (!Number.isSafeInteger(account.epoch + 1)) fail('epoch overflow');
    account.epoch += 1; return account.epoch;
  }
  account(accountId) { return copy(this.#account(accountId)); }
  grantState(grantId) { return copy(this.#grant(grantId)); }
  intent(intentId) { return copy(this.#intent(intentId)); }
  snapshot() {
    return { schema: 'offline-continuity-kernel/v0', ledger: this.#ledger, lastTime: this.#lastTime,
      accounts: copy([...this.#accounts.values()]), grants: copy([...this.#grants.values()]),
      intents: copy([...this.#intents.values()]) };
  }
  assertInvariants() {
    for (const account of this.#accounts.values()) {
      if (units(account.available) + units(account.pending) + units(account.spent) !== units(account.opening)) fail('account conservation broken');
      const pending = [...this.#intents.values()].filter(i => i.accountId === account.id && ['reserved','dispatched','unknown'].includes(i.state)).reduce((s,i) => s + units(i.amount), 0n);
      const spent = [...this.#intents.values()].filter(i => i.accountId === account.id && i.state === 'settled').reduce((s,i) => s + units(i.amount), 0n);
      if (pending !== units(account.pending) || spent !== units(account.spent)) fail('account intent reconciliation broken');
    }
    for (const grant of this.#grants.values()) {
      if (units(grant.pending) + units(grant.spent) > units(grant.limit)) fail('grant conservation broken');
      const relevant = [...this.#intents.values()].filter(i => this.#chain(this.#grant(i.grantId)).some(g => g.id === grant.id));
      const pending = relevant.filter(i => ['reserved','dispatched','unknown'].includes(i.state)).reduce((s,i) => s + units(i.amount), 0n);
      const spent = relevant.filter(i => i.state === 'settled').reduce((s,i) => s + units(i.amount), 0n);
      if (pending !== units(grant.pending) || spent !== units(grant.spent)) fail('grant intent reconciliation broken');
    }
    return true;
  }
}
