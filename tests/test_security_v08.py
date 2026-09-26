"""Security regression tests: isolated files, mocked RPC/uploads, no secrets or network."""
import contextlib
import copy
import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
from decimal import Decimal

BIN = Path(__file__).resolve().parents[1] / 'bin'
sys.path.insert(0, str(BIN))
import xrpl_common as C

def load(name, path):
    loader = SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod

S = load('sign_v08', BIN / 'xrpl-sign')
T = load('trade_v08', BIN / 'xrpl-trade')
A = 'r9e34ga9YxYHYoCe7UtWWpuLjp4iKs3gkB'
B = 'rnkt27oqgJiRfsuwCogqrLwYx4NNooMFdB'

class Response:
    def __init__(self, result, ok=True):
        self.result, self.ok = result, ok
    def is_successful(self):
        return self.ok

class Node:
    def __init__(self, tx=None, error=None, history='1-200', validated=True):
        self.tx, self.error, self.history = tx, error, history
        self.validated = validated
        self.requests = []
    def request(self, req):
        name = type(req).__name__
        self.requests.append(name)
        if name == 'Ledger':
            return Response({'ledger_index': 200, 'validated': self.validated})
        if name == 'ServerInfo':
            return Response({'info': {'complete_ledgers': self.history}})
        if name == 'Tx':
            return Response({'error': self.error}, False) if self.error else Response(self.tx)
        raise AssertionError(name)

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for name, filename in {'XRPL_DIR':'', 'STATE_PATH':'state.json', 'STATE_LOCK_PATH':'state.lock',
              'AUDIT_PATH':'audit.log', 'POLICY_PATH':'policy.json', 'CONFIG_PATH':'config.json',
              'PROFILES_PATH':'profiles.json', 'PROPOSALS_DIR':'proposals', 'STAGE_DIR':'stage',
              'GIVEAWAY_PATH':'giveaway.json', 'GIVEAWAY_STATE_PATH':'giveaway_state.json',
              'GIVEAWAY_STATE_LOCK_PATH':'giveaway_state.lock', 'APPROVED_PATH':'approved.json'}.items():
            self.stack.enter_context(patch.object(C, name, self.root / filename))
        self.policy = copy.deepcopy(C.DEFAULT_POLICY)
        self.policy['spend_limits'] = {'XRP':{'per_tx':'25','per_day':'100'}}
        C.atomic_private_json(C.POLICY_PATH, self.policy)
        self.tr = C.SpentTracker()
    def reserve(self, spends=None):
        _, rid = self.tr.try_reserve(spends or {'XRP':Decimal('5')}, self.policy)
        self.tr.bind_reservation(rid, 'A'*64, 100, 50)
        return rid
    def test_corrupt_recovery_preserves_original(self):
        C.STATE_PATH.write_text('{truncated')
        with self.assertRaises(C.StateCorruptError):
            S.cmd_recover_state(NS(profile=None, restore_from=None))
        self.assertEqual(C.STATE_PATH.read_text(), '{truncated')
    def test_invalid_recovery_preserves_records(self):
        raw = {'entries':[{'amount':'-99'}]}
        C.STATE_PATH.write_text(json.dumps(raw))
        with self.assertRaises(C.StateCorruptError):
            S.cmd_recover_state(NS(profile=None, restore_from=None))
        self.assertEqual(json.loads(C.STATE_PATH.read_text()), raw)
    def test_missing_initialized_state_refused(self):
        self.reserve()
        C.STATE_PATH.unlink()
        with self.assertRaises(C.StateCorruptError): self.tr._load()
    def test_migrated_amounts_validated(self):
        for value in ['-90','NaN','Infinity']:
            C.STATE_PATH.write_text(json.dumps({'totals':{'XRP':value},'window_start':int(time.time())}))
            with self.assertRaises(C.StateCorruptError): self.tr._load()
    def test_invalid_entry_types(self):
        entry = dict(rid='a',ts=int(time.time()),asset='XRP',amount='1',status='pending')
        for bad in [dict(entry,ts=True),dict(entry,asset=[]),dict(entry,tx_hash='bad'),dict(entry,last_ledger=10)]:
            with self.assertRaises(C.StateCorruptError): self.tr._validate_entry(bad)
    def test_ambiguous_rpc_keeps_liability(self):
        self.reserve()
        for error in ['tooBusy','internal','lgrNotFound']:
            self.tr.sweep_pending(Node(error=error))
            self.assertEqual(len(self.tr._load()['entries']),1)
    def test_history_proven_notfound_releases(self):
        self.reserve()
        node=Node(error='txnNotFound')
        self.tr.sweep_pending(node)
        self.assertIn('ServerInfo',node.requests)
        self.assertEqual(self.tr._load()['entries'],[])
    def test_history_gap_keeps_liability(self):
        self.reserve()
        self.tr.sweep_pending(Node(error='txnNotFound',history='1-60,80-200'))
        self.assertEqual(len(self.tr._load()['entries']),1)
    def test_unvalidated_keeps_liability(self):
        self.reserve()
        self.tr.sweep_pending(Node(tx={'validated':False,'meta':{'TransactionResult':'tesSUCCESS'}}))
        self.assertEqual(self.tr._load()['entries'][0]['status'],'pending')
    def test_one_fee_per_transaction(self):
        self.policy['spend_limits']['USD']={'per_tx':'25','per_day':'100'}
        self.reserve({'XRP':Decimal('5'),'USD':Decimal('5')})
        node=Node(tx={'validated':True,'tx_json':{'Fee':'12'},'meta':{'TransactionResult':'tecPATH_DRY'}})
        self.tr.sweep_pending(node)
        entries=self.tr._load()['entries']
        self.assertEqual(len(entries),1)
        self.assertEqual(Decimal(entries[0]['amount']),Decimal('0.000012'))
        self.assertEqual(node.requests.count('Tx'),1)
    def test_missing_fee_keeps_liability(self):
        self.reserve()
        self.tr.sweep_pending(Node(tx={'validated':True,'meta':{'TransactionResult':'tecPATH_DRY'}}))
        self.assertEqual(self.tr._load()['entries'][0]['status'],'pending')
    def test_pending_never_ages_out(self):
        e=dict(rid='x',ts=0,asset='XRP',amount='1',status='pending')
        self.assertEqual(self.tr._prune([e],int(time.time())),[e])
    def test_policy_rejects_invalid_schema(self):
        for fields in [dict(max_fee_drops=float('inf')),dict(unknown=True),dict(min_book_depth='NaN')]:
            with self.assertRaises(C.PolicyError): C.validate_policy(dict(self.policy,**fields))
    def test_profile_fingerprint_binds_credential_and_state(self):
        pf=dict(account=A,network='mainnet',credential={'kind':'env','env_var':'XRPL_SEED'},state='default')
        prop=dict(profile='main',account=A,network='mainnet',profile_sha256=C.canonical_hash(pf))
        C.verify_profile_binding('main',pf,prop)
        for change in [dict(state='giveaway'),dict(credential={'kind':'env','env_var':'OTHER'})]:
            with self.assertRaises(C.ProposalError): C.verify_profile_binding('main',dict(pf,**change),prop)
    def test_stable_account_state_namespace(self):
        one=C.tracker_for_profile('main','mainnet',A)
        two=C.tracker_for_profile('renamed','mainnet',A)
        self.assertEqual(one.state_path,two.state_path)
        self.assertNotEqual(one.state_path,C.tracker_for_profile('main','testnet',A).state_path)
    def test_legacy_state_requires_explicit_reviewed_migration(self):
        self.reserve()
        with self.assertRaises(C.StateCorruptError): C.tracker_for_profile('main','mainnet',A)
        C.CONFIG_PATH.write_text(json.dumps({'address':A,'network':'mainnet'}))
        pf={'network':'mainnet','account':A,'credential':{'kind':'env','env_var':'XRPL_SEED'},
            'policy_path':str(C.POLICY_PATH),'policy_sha256':C._sha256_file(C.POLICY_PATH),'state':'default'}
        C.atomic_private_json(C.PROFILES_PATH,{'schema_version':1,'profiles':{'main':pf}})
        digest=C._sha256_file(C.STATE_PATH)
        with self.assertRaises(SystemExit):
            S.cmd_migrate_state(NS(profile='main',legacy_state='default',state_sha256=digest,approve_migration='0'*64))
        S.cmd_migrate_state(NS(profile='main',legacy_state='default',state_sha256=digest,approve_migration=digest))
        dest=C.tracker_for_profile('main','mainnet',A)
        self.assertEqual(dest._load()['entries'],self.tr._load()['entries'])
    def test_short_approval_refused_before_context(self):
        tx=dict(TransactionType='Payment',Account=A,Destination=B,Amount='1000000',Fee='12',Sequence=1,LastLedgerSequence=100)
        h,_=C.save_proposal(tx,'testnet',A,'send',profile='adhoc-testnet',policy_sha256=C._sha256_file(C.POLICY_PATH))
        with patch.object(S,'resolve_signing_context') as context:
            with self.assertRaises(SystemExit): S.cmd_sign(NS(hash=h[:1],approve=True))
            context.assert_not_called()
    def test_missing_seed_releases_unbound_reservations(self):
        prop=dict(proposal_hash='A'*64,network='testnet',action='send')
        with patch.object(S,'load_seed',side_effect=SystemExit('no seed')):
            with self.assertRaises(SystemExit):
                S._reserve_sign_bind(prop,{'Account':A},self.policy,self.tr,{'XRP':Decimal('1')},('env','NO_SEED'),None)
        self.assertEqual(self.tr._load()['entries'],[])
    def test_regular_key_authorized_disabled_master_refused(self):
        node=NS(request=lambda r:Response({'validated':True,'account_data':{'Flags':C.LSF_DISABLE_MASTER,'RegularKey':B}}))
        self.assertIsNone(C.check_ledger_key_authorization(node,A,B))
        self.assertIsNotNone(C.check_ledger_key_authorization(node,A,A))
    def test_mainnet_local_generation_refused_in_helper(self):
        with self.assertRaises(SystemExit): T.generate_wallet_into_config('mainnet')
        self.assertFalse(C.CONFIG_PATH.exists())
    def test_setup_mainnet_generation_refused(self):
        with patch('builtins.input',side_effect=['y','mainnet']),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):T.cmd_setup(None)
        self.assertFalse(C.CONFIG_PATH.exists())
    def test_backup_cannot_reclassify_mainnet_secret(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit):T.cmd_wallet(NS(wallet_cmd='backup',network='testnet'),{'network':'mainnet','seed':'FAKE_SECRET'})
        self.assertNotIn('FAKE_SECRET',output.getvalue())
    def test_local_test_wallet_config_has_no_seed(self):
        T.generate_wallet_into_config('testnet')
        self.assertNotIn('seed',json.loads(C.CONFIG_PATH.read_text()))
        stored=json.loads(C.local_wallet_path('testnet').read_text())
        self.assertEqual(stored['network'],'testnet')
        self.assertIn('seed',stored)
    def test_mainnet_giveaway_storage_refused(self):
        with self.assertRaises(SystemExit):C.write_giveaway_seed('FAKE',network='mainnet')
    def test_unvalidated_nft_read_refused(self):
        node=NS(request=lambda r:Response({'validated':False,'node':{'LedgerEntryType':'NFTokenOffer'}}))
        _,error=C.fetch_nft_offer_entry(node,'A'*64)
        self.assertIsNotNone(error)
    def test_terminal_controls_neutralized(self):
        value='\x1b[2J\u202e\nspoof'
        self.assertNotIn('\x1b',C.decode_nft_uri(value.encode().hex()))
        from xrpl_xrpresso import _text
        self.assertNotIn('\u202e',_text(value))
    def test_rewritten_stage_and_digest_require_fresh_approval(self):
        rec={'stage_digest':'B'*64}
        with patch.object(T,'load_stage_record',return_value=rec),patch.object(T.xrpl_pin,'pin_data') as upload:
            with self.assertRaises(SystemExit):T.pin_and_propose_stage('a'*16,{},None,approved_digest='A'*64)
            upload.assert_not_called()
    def test_no_stage_approval_no_file_or_secret_access(self):
        with patch.object(T,'load_stage_record') as read:
            with self.assertRaises(SystemExit):T.pin_and_propose_stage('a'*16,{},None)
            read.assert_not_called()

if __name__ == '__main__': unittest.main()
