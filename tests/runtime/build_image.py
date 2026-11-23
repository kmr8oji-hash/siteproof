"""Build exact source allowlist; never send .git, user files or secrets as context."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def main():
    p=argparse.ArgumentParser();p.add_argument('--evidence',required=True);a=p.parse_args()
    root=Path.cwd();evidence=Path(a.evidence);context=evidence/'build-context';context.mkdir(parents=True,exist_ok=True)
    files=[]
    for directory in ('src','web','runtime/docker','tests/runtime'):
        for path in (root/directory).rglob('*'):
            if path.is_file() and (path.suffix in ('.py','.html','.css','.js','.json','.svg') or path.name=='Dockerfile') and '__pycache__' not in path.parts:
                files.append(path)
    files += [root/'tests/__init__.py',root/'tests/isolation/transport_fixtures.py']
    manifest={}
    for path in files:
        relative=path.relative_to(root);target=context/relative;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(path,target);manifest[relative.as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
    (evidence/'build-inputs.json').write_text(json.dumps(manifest,indent=2))
    cli=['C:/Program Files/Docker/Docker/resources/bin/docker.exe','--context','desktop-linux']
    with (evidence/'image-build.log').open('wb') as log:
        r=subprocess.run(cli+['build','--progress=plain','-f',str(context/'runtime/docker/Dockerfile'),
            '-t','siteproof-m2-runtime:20261105',str(context)],stdout=log,stderr=subprocess.STDOUT)
    print('build exit',r.returncode)
    print((evidence/'image-build.log').read_text(errors='replace')[-1800:])
    raise SystemExit(r.returncode)


if __name__=='__main__':main()
