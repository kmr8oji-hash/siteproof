"""Copy infra/aws_c/user_data.sh into the UserData of infra/aws_c/worker.template.json.

The shell script is the reviewed source of truth; the template must carry the same text.
tests/aws_c/test_template_contract.py fails when the two differ. Local file edit only.

    py -3.15 -B tools/embed_user_data.py
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "infra" / "aws_c" / "user_data.sh"
TEMPLATE = ROOT / "infra" / "aws_c" / "worker.template.json"


def main() -> None:
    template = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    script = SCRIPT.read_text(encoding="utf-8").replace("\r\n", "\n")
    template["Resources"]["WorkerInstance"]["Properties"]["UserData"] = {
        "Fn::Base64": {"Fn::Sub": script}}
    TEMPLATE.write_text(json.dumps(template, indent=2, ensure_ascii=True) + "\n",
                        encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
