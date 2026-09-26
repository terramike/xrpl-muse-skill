"""Discover every offline test in this checkout, each with an isolated home.

POSIX locking and file ownership are security properties: this release gate
must run on Linux, without fcntl/permission shims. Live suites are explicit.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LIVE = {'test_e2e_testnet.py', 'test_nft_send_e2e.py'}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--testnet', action='store_true', help='also run isolated live testnet suites')
    args = parser.parse_args()
    if sys.platform != 'linux':
        sys.exit('Release validation requires Linux; Windows logic probes do not certify POSIX isolation.')
    failed = []
    for test in sorted((ROOT / 'tests').glob('test_*.py')):
        if test.name in LIVE and not args.testnet:
            continue
        with tempfile.TemporaryDirectory(prefix='xrpl-test-home-') as home:
            env = dict(os.environ, HOME=home, USERPROFILE=home, PYTHONIOENCODING='utf-8')
            for key in list(env):
                if 'SEED' in key or key == 'PINATA_JWT':
                    env.pop(key)
            env['PYTHONPATH'] = str(ROOT / 'bin')
            result = subprocess.run([sys.executable, str(test)], cwd=ROOT, env=env,
                                    timeout=1200 if test.name in LIVE else 120)
            if result.returncode:
                failed.append(test.name)
    print('Failed suites: ' + (', '.join(failed) or 'none'))
    return bool(failed)

if __name__ == '__main__':
    sys.exit(main())
