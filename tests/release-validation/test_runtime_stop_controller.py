import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('runtime_stop_controller',ROOT/'scripts/record_runtime_container_stop.py')
controller=importlib.util.module_from_spec(spec);spec.loader.exec_module(controller)

class RuntimeStopControllerSafetyTest(unittest.TestCase):
    def test_unrelated_and_counterfeit_projects_cannot_be_stopped(self):
        for project in ['other-project', 'agentplug-interview-rehearsal-fake', 'agentplug-with-ragplaform-fake']:
            with self.subTest(project=project), patch.object(controller,'inspect') as inspect:
                with self.assertRaises(ValueError):
                    controller.record({'compose_project':project},'a'*64,Path('unused'),Path('unused'),True)
                inspect.assert_not_called()

    def test_different_runtime_or_image_never_issues_stop_command(self):
        snapshot={'compose_project':'agentplug','compose_service':'example-java','endpoint':'http://example-java:8080',
                  'image_digest':'sha256:'+'b'*64,'created_at':'2026-10-04T00:00:00+00:00'}
        original={'Id':'a'*64,'Image':snapshot['image_digest'],'Config':{'Labels':{'com.docker.compose.project':'agentplug',
            'com.docker.compose.service':'example-java'}},'NetworkSettings':{'Networks':{'agentplug_default':{'Aliases':['example-java']}}},
            'State':{'StartedAt':'2026-10-03T00:00:00+00:00'}}
        import copy
        for mismatch in ['image','project','service','new-process']:
            candidate=copy.deepcopy(original)
            if mismatch=='image':candidate['Image']='sha256:'+'c'*64
            if mismatch=='project':candidate['Config']['Labels']['com.docker.compose.project']='agentplug-with-ragplaform'
            if mismatch=='service':candidate['Config']['Labels']['com.docker.compose.service']='postgres'
            if mismatch=='new-process':candidate['State']['StartedAt']='2026-10-05T00:00:00+00:00'
            with self.subTest(mismatch=mismatch),patch.object(controller,'inspect',return_value=candidate),patch.object(controller.subprocess,'run') as run:
                with self.assertRaises(ValueError):controller.record(snapshot,'a'*64,Path('unused'),Path('unused'),True)
                run.assert_not_called()

    def test_default_validation_does_not_stop_or_issue_receipt(self):
        for project in ['agentplug', 'agentplug-with-ragplaform', 'agentplug-interview-rehearsal']:
            with self.subTest(project=project):
                self.validate_owned_project(project)

    def validate_owned_project(self, project):
        snapshot={'compose_project':project,'compose_service':'example-java','endpoint':'http://example-java:8080',
                  'image_digest':'sha256:'+'b'*64,'created_at':'2026-10-04T00:00:00+00:00'}
        candidate={'Id':'a'*64,'Image':snapshot['image_digest'],'Config':{'Labels':{'com.docker.compose.project':project,
            'com.docker.compose.service':'example-java'}},'NetworkSettings':{'Networks':{'agentplug_default':{'Aliases':['example-java']}}},
            'State':{'StartedAt':'2026-10-03T00:00:00+00:00'}}
        with tempfile.TemporaryDirectory() as directory,patch.object(controller,'inspect',return_value=candidate),patch.object(controller.subprocess,'run') as run:
            key=Path(directory)/'key';key.write_bytes(b'k'*32)
            receipt_dir=Path(directory)/'receipts'
            result=controller.record(snapshot,'a'*64,key,receipt_dir)
            self.assertFalse(result['process_stopped']);self.assertFalse(result['receipt_written'])
            self.assertFalse(receipt_dir.exists());run.assert_not_called()

if __name__=='__main__':unittest.main()
