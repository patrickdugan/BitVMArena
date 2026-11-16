"""Capture verified source bytes, then run the bounded CPA candidate campaign."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

MODULE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(MODULE/'scripts'))
from run import read_sources, checked_path

FILES=('scripts/fixed_target.py','scripts/candidate_search.py','scripts/search_worker.py',
       'tests/test_candidate_search.py','adapters/cpa_search_control.py','tests/test_candidate_sdk.py')
FIXED_TARGET_SHA='da1275823155260e8573eb0236cdac9d7bc94b57bf2bcf9c43f03193ab5aabc3'


def run(source: Path, output: Path, sdk: bool=False) -> dict:
    if not __debug__:
        raise ValueError('optimized Python is unsupported')
    lock=json.loads((MODULE/'fixtures/source-lock.json').read_bytes())
    upstream=read_sources(source.resolve(strict=True),lock['files'])
    owned={name:checked_path(MODULE,name).read_bytes() for name in FILES}
    if sha256(owned['scripts/fixed_target.py']).hexdigest()!=FIXED_TARGET_SHA:
        raise ValueError('review the fixed-target checker before changing its pin')
    output=output.resolve();output.mkdir(parents=True,exist_ok=False)
    receipt={'schema':'BA-CPA-04/run-v1','status':'running','upstream_commit':lock['commit'],
             'upstream_sha256':lock['files'],'research_sha256':{n:sha256(b).hexdigest() for n,b in owned.items()},
             'runner_sha256':sha256(Path(__file__).read_bytes()).hexdigest(),
             'native_node_run':False,'HF_verifier_run':False,'model_generated_run':False}
    try:
        with tempfile.TemporaryDirectory(prefix='cpa-candidate-search-') as tmp:
            root=Path(tmp)
            for relative,data in list(upstream.items())+[(str(Path('arena_cpa')/n),b) for n,b in owned.items()]:
                p=root/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
            env={k:v for k,v in os.environ.items() if k in ('PATH','SYSTEMROOT','WINDIR','TEMP','TMP','LANG','LC_ALL')}
            def stage(name,args,expected_tests=None,site=False):
                with (output/(name+'.log')).open('wb') as log:
                    result=subprocess.run([sys.executable,'-I','-B',*([] if site else ['-S']),*args],
                        cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=240,check=False)
                if result.returncode:
                    raise RuntimeError(f'{name} failed; inspect its log')
                if expected_tests is not None:
                    text=(output/(name+'.log')).read_text()
                    if not re.search(rf'Ran {expected_tests} tests? in ',text) or 'skipped=' in text:
                        raise RuntimeError(f'{name} did not execute all required tests')
            stage('upstream-study-tests',['-m','unittest','discover','-s',str(root/'scripts/tests'),
                  '-p','test_bitvm_authority_enumeration.py','-v'],14)
            stage('upstream-cpa-tests',['-m','unittest','discover','-s',str(root/'scripts/tests'),'-p','test_cpa*.py','-v'],42)
            stage('enumeration',[str(root/'scripts/research/bitvm_authority_enumeration.py'),
                  '--bitcoin-rs',str(root),'--out',str(output/'generated')])
            for name,expected in lock['outputs'].items():
                if sha256((output/'generated'/name).read_bytes()).hexdigest()!=expected:
                    raise ValueError('upstream evidence mismatch')
            worker=str(root/'arena_cpa/scripts/search_worker.py')
            args=[worker,'--bitcoin-rs',str(root),'--corpus',str(output/'generated/circuits.jsonl')]
            stage('candidate-tests',args+['--tests'],32)
            stage('candidate-campaign',args+['--out',str(output/'campaign')])
            if sdk:
                stage('candidate-sdk',args+['--sdk','--out',str(output/'sdk-logs')],10,site=True)
            receipt['summary']=json.loads((output/'campaign/summary.json').read_bytes())
            receipt['output_sha256']={p.name:sha256(p.read_bytes()).hexdigest()
                                      for p in sorted((output/'campaign').iterdir()) if p.is_file()}
            expected=json.loads((MODULE/'fixtures/search-lock.json').read_bytes())
            if receipt['output_sha256']!=expected['outputs'] or receipt['summary']!=expected['summary']:
                raise ValueError('candidate campaign differs from reviewed evidence')
            receipt.update(status='passed',candidate_tests=32,upstream_study_tests=14,
                           upstream_cpa_tests=42,sdk_tests=10 if sdk else 0,sdk_executed=sdk)
    except Exception as error:
        receipt.update(status='failed',error=f'{type(error).__name__}: {error}')
        raise
    finally:
        (output/'receipt.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
    return receipt


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bitcoin-rs',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--sdk',action='store_true')
    a=p.parse_args()
    print(json.dumps(run(a.bitcoin_rs,a.out,a.sdk),indent=2))

if __name__=='__main__':
    main()
