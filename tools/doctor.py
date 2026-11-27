"""導入環境の確認: what this PC has for SiteProof and what to do next. Read only -- it starts, installs, registers and changes nothing.

    py -3.15 -B tools/doctor.py --data <app data folder> [--json] [--no-docker]

--no-docker skips the Docker probes (reported as UNKNOWN). Without it, the read-only `docker info` and `docker image inspect` are asked (never a pull or a build).
Windows tasks are only queried (`schtasks /Query`). The exit code is 0 whenever the report was made: the list is for you to read, not a gate.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.noxiworks import environment

MARK = {'OK': 'OK     ', 'MISSING': 'ない   ', 'WARN': '注意   ', 'UNKNOWN': '不明   '}


def lines(result):
    out = [f"SiteProof 導入環境の確認（読み取りだけ・何も変更していません）  データ：{result['data']}"]
    for it in result['items']:
        out.append(f"[{MARK[it['status']]}] {it['label']}：{it['detail']}")
        if it['next']:
            out.append(f"          → 次にすること：{it['next']}")
    c = result['counts']
    out.append(f"まとめ：OK {c['OK']}・ない {c['MISSING']}・注意 {c['WARN']}・不明 {c['UNKNOWN']}")
    return out


def main(argv=None, probes=None, out=print):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--json', action='store_true', help='print the report as JSON')
    parser.add_argument('--no-docker', action='store_true', help='skip the Docker probes (UNKNOWN)')
    args = parser.parse_args(argv)
    result = environment.report(args.data, probes, docker=not args.no_docker)
    if args.json:
        out(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        for line in lines(result):
            out(line)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
