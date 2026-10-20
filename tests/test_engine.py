import csv
import hashlib
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
from engine.core import parse_autoruns, analyze, command_evidence, pe_metadata, Store, validate_ai, AI_SCHEMA, ai_payload, local_path, external_analysis, explain, run_process

class EngineTests(unittest.TestCase):
    def setUp(self):
        work = Path(__file__).resolve().parent.parent / 'work' / 'tests'
        work.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=work)
        self.root = Path(self.temp.name)
    def tearDown(self):
        self.temp.cleanup()
    def test_utf16_autoruns_with_banner_and_quoted_comma(self):
        p=self.root/'input.csv'
        p.write_text('Autoruns banner\n"Entry","Image Path","Launch String","Entry Location"\n"Example, Inc","C:\\Tools\\safe.exe","safe.exe --test","HKCU\\Run"\n',encoding='utf-16')
        rows=parse_autoruns(str(p))
        self.assertEqual(rows[0]['name'],'Example, Inc')
        self.assertEqual(rows[0]['location'],'HKCU\\Run')
    def test_no_header_is_error(self):
        p=self.root/'bad.csv';p.write_text('name,path\na,b')
        with self.assertRaises(ValueError):parse_autoruns(str(p))
    def test_launcher_not_confused_with_verified_payload(self):
        f=command_evidence({'path':r'C:\Windows\System32\rundll32.exe','command':r'rundll32.exe C:\test.dll,Entry'})
        self.assertEqual(f[0]['id'],'launcher')
        self.assertIn('test.dll',f[0]['evidence'])
    def test_network_path_rejected(self):
        with self.assertRaises(ValueError):local_path(r'\\server\share\sample.exe')
    def test_bad_pe_is_not_clean(self):
        self.assertEqual(pe_metadata(b'MZbroken')['status'],'error')
    def test_static_analysis_does_not_execute_sample(self):
        p=self.root/'sample.txt';data=b'This is a harmless fixture https://example.invalid/test';p.write_bytes(data)
        with patch('engine.core.signature',return_value={'status':'NotSigned'}),patch('engine.core.run_process') as process:
            scan=analyze(str(p))
            process.assert_not_called()
        self.assertEqual(scan['sha256'],hashlib.sha256(data).hexdigest())
        self.assertEqual(scan['status'],'partial')
        self.assertTrue(all(a['status']!='ok' for a in scan['analyzers']))
        self.assertIsNone(scan['ai'])
    def test_missing_file_is_error(self):
        with self.assertRaises(ValueError):analyze(str(self.root/'missing.exe'))
    def test_history_roundtrip(self):
        s=Store(self.root);scan={'id':'x','created_at':'2026-01-01','name':'тест'}
        s.save(scan);self.assertEqual(s.get('x'),scan);self.assertEqual(len(s.history()),1);s.db.close()
    def test_ai_cannot_cite_invented_evidence(self):
        result={'verdict':'needs_review','summary':'test','reasons':[{'evidence_id':'invented','explanation':'x'}],'limitations':[],'next_steps':[]}
        with self.assertRaises(ValueError):validate_ai(result,{'evidence':[{'id':'file'}]})
    def test_missing_analyzer_is_explicit(self):
        with patch('engine.core.shutil.which',return_value=None):
            self.assertEqual(external_analysis('capa',self.root/'x')['status'],'not_installed')
    def test_api_login_is_rejected_before_request(self):
        with patch('engine.core.codex_status', return_value={'subscription':False,'detail':'ChatGPT required'}),patch('engine.core.run_process') as proc:
            with self.assertRaises(ValueError):explain({})
            proc.assert_not_called()
    def test_ai_rejects_malicious_or_wrongly_typed_response(self):
        result={'verdict':'safe','summary':'test','reasons':[],'limitations':[],'next_steps':[]}
        with self.assertRaises(ValueError):validate_ai(result,{'evidence':[]})
        result['verdict']='needs_review';result['next_steps']='run a shell command'
        with self.assertRaises(ValueError):validate_ai(result,{'evidence':[]})
    def test_no_submitted_launch_command_is_executed(self):
        p=self.root/'sample.txt';p.write_bytes(b'fixture')
        entry={'path':str(p),'command':'powershell.exe -enc NEVER_EXECUTE'}
        with patch('engine.core.signature',return_value={'status':'NotSigned'}),patch('engine.core.run_process') as proc:
            s=analyze(str(p),entry)
            proc.assert_not_called()
        payload=json.dumps(ai_payload(s))
        self.assertNotIn('NEVER_EXECUTE',payload)
    def test_process_tree_timeout_returns_promptly(self):
        code = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); time.sleep(30)"
        start=time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            run_process([sys.executable,'-c',code],timeout=0.5)
        self.assertLess(time.monotonic()-start,16)

if __name__=='__main__':unittest.main()
