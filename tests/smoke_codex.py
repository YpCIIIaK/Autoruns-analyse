"""Opt-in integration check: sends only a generated harmless fixture report."""
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engine.core import analyze, explain, Store

root = Path(__file__).resolve().parent.parent / 'work' / 'smoke'
root.mkdir(parents=True, exist_ok=True)
sample = root / 'harmless-fixture.txt'
sample.write_text('Harmless Autoruns Lens test fixture. https://example.invalid/test', encoding='utf-8')
scan = analyze(str(sample))
print('Static analysis:', scan['signature']['status'], scan['sha256'], flush=True)
scan['ai'] = explain(scan)
store = Store(root)
store.save(scan)
(root / 'result.json').write_text(json.dumps(scan, ensure_ascii=False, indent=2), encoding='utf-8')
print('Codex verdict:', scan['ai']['verdict'])
print('Evidence references:', ', '.join(r['evidence_id'] for r in scan['ai']['reasons']))
print('Saved:', root / 'result.json')
