"""Offline six-file copier and reviewer manifest; never uploads or authenticates.

Run in a controlled, quiescent local filesystem. Link/identity checks narrow
accidental boundary escapes; they are NOT a hostile concurrent filesystem sandbox.
Failures leave any partial new output intact, never repair/delete existing data.
"""
import argparse
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urljoin

KEYS = tuple(f"{page}/{name}" for page in ("home", "compare")
             for name in ("index.html", "styles.css", "app.js"))
MIMES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
         ".js": "text/javascript; charset=utf-8"}
LIMIT = 2 * 1024 * 1024
DEFAULT_TEMPLATE = Path(__file__).with_name("cloudformation.json")
ROOT_REDIRECT = "function handler(event) { var request = event.request; if (request.uri === '/') { return { statusCode: 302, statusDescription: 'Found', headers: { location: { value: '/home/index.html' }, 'cache-control': { value: 'no-store' } } }; } return request; }"


class PackageError(ValueError):
    """Unusable/unapproved input or partial output; no success is implied."""


def strict_json(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise PackageError("duplicate JSON member")
            result[k] = v
        return result
    def reject(_):
        raise PackageError("nonfinite JSON")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject)


def plain_path(path):
    path = Path(path)
    if ".." in path.parts or str(path).startswith(("\\\\", "//")):
        raise PackageError("traversal/network path refused")
    path = path.absolute()  # do not resolve/follow links before inspecting them
    for item in (*reversed(path.parents), path):
        s = item.lstat()
        if stat.S_ISLNK(s.st_mode) or getattr(s, "st_file_attributes", 0) & 0x400:
            raise PackageError("symlink/reparse path refused")
    return path


def identity(s):
    # Windows lstat and CRT fstat can expose different ctime semantics on a
    # newly written file. Compare their common identity/size/mtime fields;
    # compare ctime only between the two path lstats below.
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)


def read_regular(path):
    path = plain_path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= LIMIT:
        raise PackageError("not a bounded, single-link regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        if identity(os.fstat(stream.fileno())) != identity(before):
            raise PackageError("file replaced before read")
        data = stream.read(LIMIT + 1)
        if identity(os.fstat(stream.fileno())) != identity(before):
            raise PackageError("file changed during read")
    after = plain_path(path).lstat()
    if (len(data) != before.st_size or identity(after) != identity(before)
            or after.st_ctime_ns != before.st_ctime_ns or after.st_nlink != 1):
        raise PackageError("unstable input")
    return data


def exact_tree(root, expected):
    root = plain_path(root)
    if not root.is_dir():
        raise PackageError("directory required")
    directories = {str(Path(k).parent).replace("\\", "/") for k in expected}
    directories.discard(".")
    found = set()
    def walk(folder):
        for entry in folder.iterdir():
            entry = plain_path(entry)
            rel = entry.relative_to(root).as_posix()
            if entry.is_dir():
                if rel not in directories:
                    raise PackageError("unexpected directory: " + rel)
                walk(entry)
            elif rel in expected and stat.S_ISREG(entry.lstat().st_mode):
                found.add(rel)
            else:
                raise PackageError("unexpected file: " + rel)
    walk(root)
    if found != set(expected):
        raise PackageError("missing approved file")


class Markup(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.refs, self.ids, self.anchors = [], set(), []
    def handle_starttag(self, tag, attrs):
        if len({name.lower() for name, _ in attrs}) != len(attrs):
            raise PackageError("duplicate HTML attribute")
        attrs = dict(attrs)
        if attrs.get("id"):
            self.ids.add(attrs["id"])
        if tag == "base" or attrs.get("http-equiv", "").lower() == "refresh":
            raise PackageError("base/refresh refused")
        for attr in ("src", "href", "action", "formaction", "poster", "data", "srcset", "xlink:href"):
            if attr in attrs:
                if (tag, attr) not in (("a", "href"), ("link", "href"), ("script", "src")):
                    raise PackageError("unsupported static reference")
                self.refs.append((tag, attrs[attr]))
        if tag == "a":
            self.anchors.append(attrs.get("href"))


def validate_assets(files, require_navigation=True):
    if set(files) != set(KEYS):
        raise PackageError("exact six assets required")
    for data in files.values():
        if not 0 < len(data) <= LIMIT or b"\0" in data:
            raise PackageError("binary/empty/oversize asset refused")
        data.decode("utf-8")
        if re.search(rb"(?:AKIA|ASIA)[A-Z0-9]{16}|-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|aws_secret_access_key\s*[:=]", data, re.I):
            raise PackageError("credential-like content refused; USER content review still required")
    complete = True
    for page, other in (("home", "compare"), ("compare", "home")):
        html = Markup()
        html.feed(files[f"{page}/index.html"].decode("utf-8"))
        html.close()
        navigation = ["#main", f"../{other}/index.html"]
        if html.anchors != navigation:
            if require_navigation or html.anchors != ["#main"]:
                raise PackageError("unexpected/missing explicit navigation")
            complete = False
        if "main" not in html.ids:
            raise PackageError("missing skip target")
        if [(t, r) for t, r in html.refs if t != "a"] != [("link", "styles.css"), ("script", "app.js")]:
            raise PackageError("unexpected stylesheet/script dependency")
        for tag, ref in html.refs:
            if ref == "#main":
                continue
            if ref not in ("styles.css", "app.js", f"../{other}/index.html"):
                raise PackageError("unapproved reference")
            # The same URL resolution applies to local web/page/ and public /page/.
            resolved = urljoin("https://offline.invalid/" + page + "/index.html", ref)
            if resolved.removeprefix("https://offline.invalid/") not in KEYS:
                raise PackageError("reference escapes payload")
        css = files[f"{page}/styles.css"].decode("utf-8")
        js = files[f"{page}/app.js"].decode("utf-8")
        if re.search(r"@import|@font-face|url\s*\(", css, re.I):
            raise PackageError("CSS dependency refused")
        if re.search(r"\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts|\bimport\s*(?:\(|[{'\"])", js):
            raise PackageError("script dependency/network refused")
    return complete


def validate_template(doc):
    try:
        res = doc["Resources"]
        dist = res["Distribution"]["Properties"]["DistributionConfig"]
        policy = res["AssetsPolicy"]["Properties"]["PolicyDocument"]["Statement"]
        if doc["Metadata"]["ApprovedObjectKeys"] != list(KEYS) or len(policy) != 2:
            raise PackageError("template key/statement mismatch")
        allow = policy[0]
        if (allow["Effect"] != "Allow" or allow["Principal"] != {"Service": "cloudfront.amazonaws.com"}
                or allow["Action"] != "s3:GetObject" or allow["Resource"] != [{"Fn::Sub": "${AssetsBucket.Arn}/" + k} for k in KEYS]
                or allow["Condition"] != {"StringEquals": {"AWS:SourceArn": {"Fn::Sub": "arn:${AWS::Partition}:cloudfront::${AWS::AccountId}:distribution/${Distribution}"}}}):
            raise PackageError("unapproved public read boundary")
        if set(allow) != {"Sid", "Effect", "Principal", "Action", "Resource", "Condition"}:
            raise PackageError("unexpected read policy field")
        if {k: v for k, v in policy[1].items() if k != "Sid"} != {
                "Effect": "Deny", "Principal": "*", "Action": "s3:*",
                "Resource": [{"Fn::GetAtt": ["AssetsBucket", "Arn"]}, {"Fn::Sub": "${AssetsBucket.Arn}/*"}],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}}}:
            raise PackageError("TLS deny required")
        if dist["DefaultRootObject"] != "home/index.html" or any(o.get("OriginPath") for o in dist["Origins"]):
            raise PackageError("wrong public layout")
        if dist["Origins"] != [{"Id": "PrivateAssets", "DomainName": {"Fn::GetAtt": ["AssetsBucket", "RegionalDomainName"]},
                                "OriginAccessControlId": {"Ref": "OriginAccess"}, "S3OriginConfig": {"OriginAccessIdentity": ""}}]:
            raise PackageError("private OAC origin required")
        behavior = dist["DefaultCacheBehavior"]
        if behavior["FunctionAssociations"] != [{"EventType": "viewer-request", "FunctionARN": {"Fn::GetAtt": ["RootRedirect", "FunctionARN"]}}]:
            raise PackageError("root URL would not be canonicalized")
        redirect = res["RootRedirect"]["Properties"]
        if redirect["FunctionCode"] != ROOT_REDIRECT or redirect["AutoPublish"] is not True or redirect["FunctionConfig"]["Runtime"] != "cloudfront-js-2.0":
            raise PackageError("unreviewed redirect code/config")
        bpa = res["AssetsBucket"]["Properties"]["PublicAccessBlockConfiguration"]
        if set(bpa) != {"BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"} or any(v is not True for v in bpa.values()):
            raise PackageError("private bucket required")
        oac = res["OriginAccess"]["Properties"]["OriginAccessControlConfig"]
        if (oac["SigningBehavior"], oac["SigningProtocol"], oac["OriginAccessControlOriginType"]) != ("always", "sigv4", "s3") or behavior["ViewerProtocolPolicy"] != "redirect-to-https":
            raise PackageError("OAC/HTTPS required")
    except (KeyError, TypeError, IndexError) as exc:
        raise PackageError("invalid template layout") from exc


def records(files):
    return [{"key": k, "source": "web/" + k, "sha256": hashlib.sha256(files[k]).hexdigest(),
             "bytes": len(files[k]), "content_type": MIMES[Path(k).suffix]} for k in KEYS]


def inspect_sources(web_root, template=DEFAULT_TEMPLATE, *, require_navigation=True):
    web_root = plain_path(web_root)
    exact_tree(web_root, KEYS)
    files = {k: read_regular(web_root / k) for k in KEYS}
    raw_template = read_regular(template)
    validate_template(strict_json(raw_template))
    navigation = validate_assets(files, require_navigation)
    return files, {"schema_version": "siteproof.public-package.v1", "status": "OFFLINE_CANDIDATE",
                   "navigation_complete": navigation, "aws_live": "NO-GO", "files": records(files),
                   "template_sha256": hashlib.sha256(raw_template).hexdigest()}


def write_new(path, data):
    plain_path(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    if read_regular(path) != data:
        raise PackageError("output readback mismatch")


def create_package(web_root, output, template=DEFAULT_TEMPLATE, *, require_navigation=True):
    files, manifest = inspect_sources(web_root, template, require_navigation=require_navigation)
    web_root = plain_path(web_root)
    output = Path(output)
    if ".." in output.parts:
        raise PackageError("output traversal refused")
    output = output.absolute()
    plain_path(output.parent)
    if output.is_relative_to(web_root) or web_root.is_relative_to(output):
        raise PackageError("output overlaps source")
    if os.path.lexists(output):
        raise PackageError("output must be NEW and absent (even empty existing refused)")
    output.mkdir()  # exclusive; leave partial output on any subsequent failure
    (output / "payload").mkdir()
    for page in ("home", "compare"):
        (output / "payload" / page).mkdir()
    for key in KEYS:
        write_new(output / "payload" / key, files[key])
    write_new(output / "review_manifest.json", (json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    if verify_package(output, template) != manifest:
        raise PackageError("package readback mismatch")
    return manifest


def verify_package(output, template=DEFAULT_TEMPLATE):
    output = plain_path(output)
    if {p.name for p in output.iterdir()} != {"payload", "review_manifest.json"}:
        raise PackageError("unexpected package root content")
    exact_tree(output / "payload", KEYS)
    files = {k: read_regular(output / "payload" / k) for k in KEYS}
    manifest = strict_json(read_regular(output / "review_manifest.json"))
    raw_template = read_regular(template)
    validate_template(strict_json(raw_template))
    expected = {"schema_version": "siteproof.public-package.v1", "status": "OFFLINE_CANDIDATE",
                "navigation_complete": validate_assets(files, require_navigation=False), "aws_live": "NO-GO",
                "files": records(files), "template_sha256": hashlib.sha256(raw_template).hexdigest()}
    if json.dumps(manifest, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise PackageError("manifest/content/template mismatch")
    return manifest  # hashes are not signatures or USER approval


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("web_root", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--pre-integration", action="store_true", help="allow missing cross-page links; explicitly NOT release-ready")
    args = parser.parse_args()
    try:
        manifest = create_package(args.web_root, args.output, require_navigation=not args.pre_integration)
    except (OSError, ValueError) as exc:
        parser.exit(1, "REFUSED / partial output must not be published: " + str(exc) + "\n")
    print(json.dumps(manifest, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
