"""Original durable multi-asset settlement model. No actual provider integration.

An authenticated adapter is NOT implemented. Method callers are trusted fixture
operators. Never expose these methods to an agent, public HTTP, or real money.
A balanced journal is an accounting property, not proof of reserves or solvency.
"""
from __future__ import annotations
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any
from native_core import Reject, require, integer, identifier, canonical, digest

class SettlementJournal:
    def __init__(self, path: str | Path):
        self.db = sqlite3.connect(str(path), isolation_level=None, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS assets(id TEXT PRIMARY KEY, decimals INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS balances(account TEXT NOT NULL, asset TEXT NOT NULL,
          units INTEGER NOT NULL, PRIMARY KEY(account,asset));
        CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS postings(event TEXT NOT NULL, line INTEGER NOT NULL,
          account TEXT NOT NULL, asset TEXT NOT NULL, units INTEGER NOT NULL,
          PRIMARY KEY(event,line));
        CREATE TABLE IF NOT EXISTS intents(id TEXT PRIMARY KEY, body TEXT NOT NULL,
          status TEXT NOT NULL, actual INTEGER NOT NULL DEFAULT 0,
          refunded INTEGER NOT NULL DEFAULT 0);
        ''')

    def close(self): self.db.close()

    def register_asset(self, asset: str, decimals: int):
        identifier(asset); integer(decimals); require(decimals <= 18, "unsupported decimals")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            old = self.db.execute("SELECT decimals FROM assets WHERE id=?", (asset,)).fetchone()
            if old: require(old[0] == decimals, "asset definition conflict")
            else: self.db.execute("INSERT INTO assets VALUES (?,?)", (asset,decimals))
            self.db.execute("COMMIT")
        except Exception: self.db.execute("ROLLBACK"); raise

    def balance(self, account: str, asset: str) -> int:
        row = self.db.execute("SELECT units FROM balances WHERE account=? AND asset=?", (account,asset)).fetchone()
        return row[0] if row else 0

    def _event(self, event_id: str, payload: dict[str, Any], postings: list[tuple[str,str,int]]) -> bool:
        identifier(event_id)
        encoded = canonical(payload).decode()
        old = self.db.execute("SELECT payload FROM events WHERE id=?", (event_id,)).fetchone()
        if old:
            require(old[0] == encoded, "event id reused with different evidence")
            return False
        totals = {}
        for account, asset, units in postings:
            identifier(account); identifier(asset)
            require(type(units) is int and abs(units) <= 2**53-1, "invalid posting")
            require(self.db.execute("SELECT 1 FROM assets WHERE id=?", (asset,)).fetchone() is not None, "unknown asset")
            totals[asset] = totals.get(asset,0)+units
        require(all(v == 0 for v in totals.values()), "unbalanced journal")
        self.db.execute("INSERT INTO events VALUES (?,?)", (event_id,encoded))
        for index, (account,asset,units) in enumerate(postings):
            balance = self.balance(account,asset)+units
            require(abs(balance) <= 2**53-1, "balance overflow")
            if account.startswith(("available:","held:")): require(balance >= 0, "insufficient funds")
            self.db.execute("INSERT INTO balances VALUES (?,?,?) ON CONFLICT(account,asset) DO UPDATE SET units=excluded.units", (account,asset,balance))
            self.db.execute("INSERT INTO postings VALUES (?,?,?,?,?)", (event_id,index,account,asset,units))
        return True

    def fixture_credit(self, event_id: str, owner: str, asset: str, units: int):
        """Test-only source of balances. NOT a bank deposit or mint API."""
        identifier(owner); integer(units, minimum=1)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self._event(event_id, {"type":"fixture_credit","owner":owner,"asset":asset,"units":units},
                        [("available:"+owner,asset,units),("fixture:external",asset,-units)])
            self.db.execute("COMMIT")
        except Exception: self.db.execute("ROLLBACK"); raise

    def reserve(self, intent_id: str, *, owner: str, asset: str, units: int, rail: str, beneficiary: str, provider: str):
        for value in (intent_id,owner,asset,rail,beneficiary,provider): identifier(value)
        integer(units,minimum=1)
        require(rail in ("card","x402","native","bank"), "unknown rail")
        body = {"owner":owner,"asset":asset,"units":units,"rail":rail,"beneficiary":beneficiary,"provider":provider}
        self.db.execute("BEGIN IMMEDIATE")
        try:
            old = self.db.execute("SELECT * FROM intents WHERE id=?", (intent_id,)).fetchone()
            if old:
                require(old["body"] == canonical(body).decode(), "intent conflict; no silent rerouting")
            else:
                require(not self.db.execute("SELECT 1 FROM balances WHERE account=? AND units<0 LIMIT 1", ("liability:"+owner,)).fetchone(), "unresolved liability; new reservations frozen")
                self._event("reserve:"+intent_id, body, [("available:"+owner,asset,-units),("held:"+intent_id,asset,units)])
                self.db.execute("INSERT INTO intents(id,body,status) VALUES (?,?,?)", (intent_id,canonical(body).decode(),"reserved"))
            self.db.execute("COMMIT")
        except Exception: self.db.execute("ROLLBACK"); raise
        return self.intent(intent_id)

    def intent(self, intent_id: str):
        row = self.db.execute("SELECT * FROM intents WHERE id=?", (intent_id,)).fetchone()
        require(row is not None, "unknown intent")
        return {**dict(row),"body":json.loads(row["body"])}

    def dispatch(self, intent_id: str):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            data = self.intent(intent_id)
            require(data["status"] in ("reserved","dispatched"), "cannot dispatch this state")
            self._event("dispatch:"+intent_id, {"type":"dispatch","intent":intent_id}, [])
            self.db.execute("UPDATE intents SET status='dispatched' WHERE id=?", (intent_id,))
            self.db.execute("COMMIT")
        except Exception: self.db.execute("ROLLBACK"); raise

    def unknown(self, intent_id: str):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            data = self.intent(intent_id)
            require(data["status"] in ("dispatched","unknown"), "cannot mark unknown")
            self._event("unknown:"+intent_id, {"type":"unknown","intent":intent_id}, [])
            self.db.execute("UPDATE intents SET status='unknown' WHERE id=?", (intent_id,))
            self.db.execute("COMMIT")
        except Exception: self.db.execute("ROLLBACK"); raise

    def reconcile(self, event_id: str, intent_id: str, *, provider: str, outcome: str, actual: int = 0):
        """Trusted fixture evidence only. Final aggregate capture, not partials.

        Over/late presentment is RECORDED as a liability exception; it is not
        rejected merely because the local permission/hold was insufficient.
        Real card incremental and multiple capture semantics remain unimplemented.
        """
        identifier(event_id); identifier(provider); integer(actual)
        require(outcome in ("settled","confirmed_not_settled"), "unsupported evidence")
        if outcome == "settled": integer(actual, minimum=1)
        else: require(actual == 0, "nonpayment cannot contain captured units")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            data = self.intent(intent_id); body = data["body"]
            require(provider == body["provider"], "provider mismatch")
            payload = {"type":"reconcile","intent":intent_id,"provider":provider,"outcome":outcome,"actual":actual}
            old = self.db.execute("SELECT payload FROM events WHERE id=?", (event_id,)).fetchone()
            if old:
                require(old[0] == canonical(payload).decode(), "event conflict")
                self.db.execute("COMMIT"); return self.intent(intent_id)
            require(data["status"] in ("dispatched","unknown","released"), "invalid reconciliation state")
            require(not (data["status"] == "released" and outcome != "settled"), "already released")
            held = self.balance("held:"+intent_id,body["asset"])
            postings = [("held:"+intent_id,body["asset"],-held)]
            if outcome == "confirmed_not_settled":
                postings.append(("available:"+body["owner"],body["asset"],held)); status = "released"
            else:
                released = max(held-actual,0); excess = max(actual-held,0)
                postings += [("available:"+body["owner"],body["asset"],released), ("settled:"+intent_id,body["asset"],actual)]
                if excess: postings.append(("liability:"+body["owner"],body["asset"],-excess))
                status = "exception" if excess else "settled"
            self._event(event_id,payload,postings)
            self.db.execute("UPDATE intents SET status=?,actual=? WHERE id=?", (status,actual,intent_id))
            self.db.execute("COMMIT")
            return self.intent(intent_id)
        except Exception: self.db.execute("ROLLBACK"); raise

    def refund(self, event_id: str, intent_id: str, *, provider: str, units: int):
        integer(units,minimum=1); identifier(provider)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            data = self.intent(intent_id); body=data["body"]
            require(provider == body["provider"], "provider mismatch")
            payload={"type":"refund","intent":intent_id,"provider":provider,"units":units}
            old=self.db.execute("SELECT payload FROM events WHERE id=?", (event_id,)).fetchone()
            if old:
                require(old[0] == canonical(payload).decode(), "event conflict")
                self.db.execute("COMMIT"); return
            # Exception debts need an explicit debt waterfall; do not pretend a
            # simple refund automatically cures an overcapture or late capture.
            require(data["status"] == "settled", "refund needs settled nonexception intent")
            require(data["refunded"]+units <= data["actual"], "refund exceeds capture")
            self._event(event_id,payload,[("settled:"+intent_id,body["asset"],-units),("available:"+body["owner"],body["asset"],units)])
            self.db.execute("UPDATE intents SET refunded=refunded+? WHERE id=?", (units,intent_id))
            self.db.execute("COMMIT")
        except Exception: self.db.execute("ROLLBACK"); raise

    def verify(self):
        for row in self.db.execute("SELECT event,asset,SUM(units) AS total FROM postings GROUP BY event,asset"):
            require(row["total"] == 0,"unbalanced historical event")
        for row in self.db.execute("SELECT * FROM balances"):
            total=self.db.execute("SELECT COALESCE(SUM(units),0) FROM postings WHERE account=? AND asset=?",(row["account"],row["asset"])).fetchone()[0]
            require(total == row["units"],"balance projection mismatch")
        return True
