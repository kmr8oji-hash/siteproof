"""Offline source-only layer over an already present runtime image. NO RUN/pull."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

CLI=['C:/Program Files/Docker/Docker/resources/bin/docker.exe','--context','desktop-linux']


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--evidence',required=True);args=parser.parse_args()
    root=Path.cwd();evidence=Path(args.evidence);context=evidence/'build-context'
    context.mkdir(parents=True,exist_ok=False)
    base=json.loads(subprocess.run(CLI+['image','inspect','siteproof-m2-runtime:20261105'],capture_output=True,text=True,check=True).stdout)[0]
    inventory={}
    for folder in ('src','web','runtime/docker','tests/runtime'):
        for path in (root/folder).rglob('*'):
            if path.is_file() and path.suffix in ('.py','.html','.css','.js','.json','.svg') and '__pycache__' not in path.parts:
                rel=path.relative_to(root);dst=context/rel;dst.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(path,dst);inventory[rel.as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
    for rel in ('tests/__init__.py','tests/isolation/transport_fixtures.py'):
        dst=context/rel;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/rel,dst)
        inventory[rel]=hashlib.sha256((root/rel).read_bytes()).hexdigest()
    # The classic builder resolves a present IMAGE ID locally. BuildKit's remote
    # metadata resolver must not be used, even with --pull=false/--network=none.
    (context/'Dockerfile').write_text('FROM '+base['Id']+'\nCOPY src /opt/siteproof/src\nCOPY web /opt/siteproof/web\nCOPY runtime /opt/siteproof/runtime\nCOPY tests /opt/siteproof/tests\nUSER 1000:1000\n',encoding='utf8')
    (evidence/'build-inputs.json').write_text(json.dumps({'base_id':base['Id'],'files':inventory},indent=2),encoding='utf8')
    with (evidence/'offline-build.log').open('wb') as log:
        subprocess.run(CLI+['build','--pull=false','--force-rm=true','--network=none','-t','siteproof-m5-runtime:local',str(context)],
                       env={**os.environ,'DOCKER_BUILDKIT':'0'},stdout=log,stderr=subprocess.STDOUT,check=True)
    image=json.loads(subprocess.run(CLI+['image','inspect','siteproof-m5-runtime:local'],capture_output=True,text=True,check=True).stdout)[0]
    (evidence/'image.json').write_text(json.dumps({'id':image['Id'],'os':image['Os'],'architecture':image['Architecture'],'base_id':base['Id']},indent=2),encoding='utf8')
    print(json.dumps({'built':image['Id'],'files':len(inventory),'external_downloads':False}))


if __name__=='__main__':main()
