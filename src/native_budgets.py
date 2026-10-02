"""Protocol-3 shared native spending limits; no new money, custody or consensus.

An owner may create several budgets. Every v3 agent grant belongs to exactly one
immutable budget. Grant caps may overlap, but actual debits must satisfy both
individual and aggregate limits. Owner-signed payments remain unrestricted by
agent budgets. This is not escrow, a balance reservation or a cross-rail limit.
"""
from __future__ import annotations
import json

from native_core import FEE_ACCOUNT, MAX_UNITS, fields, identifier, integer, require

BUDGET_COLUMNS = ('id', 'owner', 'epoch', 'cap', 'spent', 'expires', 'recipients', 'revoked')
LINK_COLUMNS = ('grant_id', 'budget_id')
MAX_BUDGETS_PER_OWNER = 128
MAX_GRANTS_PER_BUDGET = 128


class BudgetRules:
    def __init__(self, ledger):
        self.ledger = ledger
        self.db = ledger.db
        schema = '''
          CREATE TABLE IF NOT EXISTS budgets (
            id TEXT PRIMARY KEY, owner TEXT NOT NULL, epoch INTEGER NOT NULL,
            cap INTEGER NOT NULL CHECK(cap>0), spent INTEGER NOT NULL CHECK(spent>=0 AND spent<=cap),
            expires INTEGER NOT NULL, recipients TEXT NOT NULL, revoked INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS grant_budgets (
            grant_id TEXT PRIMARY KEY, budget_id TEXT NOT NULL);
        '''
        # Do not implicitly commit the caller's initialization transaction.
        for statement in schema.split(';'):
            if statement.strip(): self.db.execute(statement)

    def _recipients(self, recipients, owner):
        require(type(recipients) is list and 1 <= len(recipients) <= 64,
                'budget requires explicit recipients')
        for recipient in recipients:
            identifier(recipient)
            require(recipient not in (owner, FEE_ACCOUNT), 'invalid budget recipient')
            self.ledger._account(recipient)
        require(len(set(recipients)) == len(recipients), 'duplicate budget recipient')
        return sorted(recipients)

    def resolve(self, owner, label, height):
        key = self.ledger.grant_storage_id(owner['id'], label)
        row = self.db.execute('SELECT * FROM budgets WHERE id=?', (key,)).fetchone()
        require(row is not None and row['owner'] == owner['id'], 'unknown native budget')
        require(not row['revoked'] and row['epoch'] == owner['epoch'] and height <= row['expires'],
                'native budget is inactive')
        return row

    def create(self, owner, op, height):
        fields(op, {'type', 'id', 'cap', 'expires', 'recipients'})
        identifier(op['id']); integer(op['cap'], minimum=1); integer(op['expires'])
        require(op['expires'] >= height, 'budget already expired')
        recipients = self._recipients(op['recipients'], owner['id'])
        key = self.ledger.grant_storage_id(owner['id'], op['id'])
        require(self.db.execute('SELECT 1 FROM budgets WHERE id=?', (key,)).fetchone() is None,
                'budget label already used; budgets cannot be reset')
        count = self.db.execute('SELECT count(*) FROM budgets WHERE owner=?', (owner['id'],)).fetchone()[0]
        require(count < MAX_BUDGETS_PER_OWNER, 'development budget-count limit reached')
        self.db.execute('INSERT INTO budgets VALUES (?,?,?,?,0,?,?,0)',
            (key, owner['id'], owner['epoch'], op['cap'], op['expires'], json.dumps(recipients)))

    def bind(self, owner, grant_key, op, height):
        """Called in the native grant's transaction after creating its grant row."""
        identifier(op['budget_id'])
        budget = self.resolve(owner, op['budget_id'], height)
        require(op['cap'] <= budget['cap'], 'grant cap exceeds parent budget')
        require(op['expires'] <= budget['expires'], 'grant outlives parent budget')
        require(set(op['recipients']) <= set(json.loads(budget['recipients'])),
                'grant recipients exceed parent budget')
        count = self.db.execute('SELECT count(*) FROM grant_budgets WHERE budget_id=?', (budget['id'],)).fetchone()[0]
        require(count < MAX_GRANTS_PER_BUDGET, 'development budget-grant limit reached')
        self.db.execute('INSERT INTO grant_budgets VALUES (?,?)', (grant_key, budget['id']))

    def for_grant(self, owner, grant, height, recipient, amount):
        """Check total debit (payment plus native fee) without mutating state."""
        link = self.db.execute('SELECT budget_id FROM grant_budgets WHERE grant_id=?', (grant['id'],)).fetchone()
        require(link is not None, 'agent grant is missing its native budget')
        budget = self.db.execute('SELECT * FROM budgets WHERE id=?', (link[0],)).fetchone()
        require(budget is not None and budget['owner'] == owner['id'], 'invalid grant budget owner')
        require(not budget['revoked'] and budget['epoch'] == owner['epoch'] and height <= budget['expires'],
                'native budget is inactive')
        require(recipient in json.loads(budget['recipients']), 'recipient outside parent budget')
        require(budget['spent'] + amount <= budget['cap'], 'shared native budget exceeded')
        return budget

    def debit(self, budget, amount):
        # Application serialization/SQLite transaction and the guarded update both
        # defend this aggregate. Never reset or free spending when grants expire.
        cursor = self.db.execute('UPDATE budgets SET spent=spent+? WHERE id=? AND spent+?<=cap',
                                 (amount, budget['id'], amount))
        require(cursor.rowcount == 1, 'shared native budget debit failed')

    def revoke(self, owner, op):
        fields(op, {'type', 'id'}); identifier(op['id'])
        key = self.ledger.grant_storage_id(owner['id'], op['id'])
        row = self.db.execute('SELECT owner FROM budgets WHERE id=?', (key,)).fetchone()
        require(row is not None and row[0] == owner['id'], 'not the native budget owner')
        self.db.execute('UPDATE budgets SET revoked=1 WHERE id=?', (key,))

    def state(self):
        return {'budgets': [dict(r) for r in self.db.execute('SELECT * FROM budgets ORDER BY id')],
                'grant_budgets': [dict(r) for r in self.db.execute('SELECT * FROM grant_budgets ORDER BY grant_id')]}

    def invariants(self):
        owners = {r['id']: r for r in self.db.execute('SELECT * FROM accounts')}
        grants = {r['id']: r for r in self.db.execute('SELECT * FROM grants')}
        budgets = {r['id']: r for r in self.db.execute('SELECT * FROM budgets')}
        links = {r['grant_id']: r['budget_id'] for r in self.db.execute('SELECT * FROM grant_budgets')}
        require(set(links) == set(grants), 'every v3 grant must have exactly one budget')
        totals = {key: 0 for key in budgets}
        for key, budget in budgets.items():
            require(budget['owner'] in owners and budget['owner'] != FEE_ACCOUNT, 'invalid budget owner')
            integer(budget['cap'], minimum=1); integer(budget['spent']); integer(budget['epoch']); integer(budget['expires'])
            require(budget['spent'] <= budget['cap'] and budget['epoch'] <= owners[budget['owner']]['epoch'],
                    'invalid budget bounds')
            require(budget['revoked'] in (0, 1), 'invalid budget revocation')
            self._recipients(json.loads(budget['recipients']), budget['owner'])
        for grant_id, budget_id in links.items():
            require(budget_id in budgets, 'dangling native budget binding')
            grant, budget = grants[grant_id], budgets[budget_id]
            require(grant['owner'] == budget['owner'] and grant['epoch'] == budget['epoch'],
                    'grant/budget authority mismatch')
            require(0 <= grant['spent'] <= grant['cap'] <= budget['cap'] and grant['expires'] <= budget['expires'],
                    'grant/budget bounds mismatch')
            require(set(json.loads(grant['recipients'])) <= set(json.loads(budget['recipients'])),
                    'grant/budget recipient mismatch')
            totals[budget_id] += grant['spent']
        require(all(totals[key] == budget['spent'] for key, budget in budgets.items()),
                'aggregate native spending does not reconcile')
