"""In-memory stand-ins for the low-level AWS clients used by src/aws_b and src/aws_c.

Offline test doubles only. They implement the small subset of request semantics the code
relies on (conditional writes, write-once puts, tag-scoped instance calls) so that tests
run through the real request builders and their real expressions. They are NOT evidence
of how the AWS services behave; every such behaviour stays LIVE-unverified.
"""
import base64
import copy
import hashlib
import re


class FakeClientError(Exception):
    def __init__(self, code, item=None, message=""):
        super().__init__(code + (": " + message if message else ""))
        self.response = {"Error": {"Code": code, "Message": message}}
        if item is not None:
            self.response["Item"] = item


class Faults:
    """Queue failures per operation. mode 'before' = not applied; 'after' = applied, ack lost."""

    def __init__(self):
        self._queue = {}
        self.calls = []

    def fail(self, operation, exc, mode="before", times=1, skip=0):
        """Let `skip` calls of `operation` through, then fail the next `times` calls."""
        self._queue.setdefault(operation, []).extend(
            [(None, None)] * skip + [(mode, exc)] * times)

    def take(self, operation):
        self.calls.append(operation)
        queue = self._queue.get(operation)
        return queue.pop(0) if queue else (None, None)


_TOKEN = re.compile(r"\s*(attribute_not_exists|attribute_exists|AND|OR|<>|<=|>=|=|<|>|\(|\)|"
                    r"#[A-Za-z0-9_]+|:[A-Za-z0-9_]+)")


def _tokens(text):
    out, pos = [], 0
    while pos < len(text):
        if text[pos:].strip() == "":
            break
        match = _TOKEN.match(text, pos)
        if not match:
            raise ValueError("unsupported expression near: " + text[pos:pos + 20])
        out.append(match.group(1))
        pos = match.end()
    return out


class _Condition:
    def __init__(self, text, names, values, item):
        self.t, self.i = _tokens(text), 0
        self.names, self.values, self.item = names or {}, values or {}, item or {}

    def _next(self):
        token = self.t[self.i]
        self.i += 1
        return token

    def _peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def evaluate(self):
        value = self._or()
        if self._peek() is not None:
            raise ValueError("trailing tokens in expression")
        return value

    def _or(self):
        value = self._and()
        while self._peek() == "OR":
            self._next()
            right = self._and()
            value = value or right
        return value

    def _and(self):
        value = self._atom()
        while self._peek() == "AND":
            self._next()
            right = self._atom()
            value = value and right
        return value

    def _operand(self, token):
        if token.startswith("#"):
            return self.item.get(self.names[token])       # KeyError = undeclared name
        if token.startswith(":"):
            return self.values[token]                     # KeyError = undeclared value
        raise ValueError("operand expected, got " + token)

    def _atom(self):
        token = self._next()
        if token == "(":
            value = self._or()
            if self._next() != ")":
                raise ValueError("missing )")
            return value
        if token in ("attribute_exists", "attribute_not_exists"):
            if self._next() != "(":
                raise ValueError("missing (")
            present = self.names[self._next()] in self.item
            if self._next() != ")":
                raise ValueError("missing )")
            return present if token == "attribute_exists" else not present
        left, op, right = self._operand(token), self._next(), self._operand(self._next())
        if left is None or right is None or set(left) != set(right):
            return op == "<>"
        (kind, a), (_, b) = next(iter(left.items())), next(iter(right.items()))
        if kind == "N":
            a, b = float(a), float(b)
        return {"=": a == b, "<>": a != b, "<": a < b, "<=": a <= b,
                ">": a > b, ">=": a >= b}[op]


def _check(request, item):
    text = request.get("ConditionExpression")
    if text is None:
        return True
    return _Condition(text, request.get("ExpressionAttributeNames"),
                      request.get("ExpressionAttributeValues"), item).evaluate()


def _used(request):
    """DynamoDB rejects unused name/value placeholders; mirror that to catch typos."""
    text = " ".join(str(request.get(k, "")) for k in (
        "ConditionExpression", "UpdateExpression", "KeyConditionExpression"))
    for name in request.get("ExpressionAttributeNames", {}):
        if not re.search(re.escape(name) + r"(?![A-Za-z0-9_])", text):
            raise FakeClientError("ValidationException", message="unused " + name)
    for name in request.get("ExpressionAttributeValues", {}):
        if not re.search(re.escape(name) + r"(?![A-Za-z0-9_])", text):
            raise FakeClientError("ValidationException", message="unused " + name)


class FakeDynamo:
    """Single-table fake keyed by (pk, sk). Item values keep DynamoDB's typed form."""

    def __init__(self):
        self.items = {}
        self.faults = Faults()
        self.before = {}      # operation -> callable(request), runs just before applying

    @staticmethod
    def _id(key):
        return key["pk"]["S"], key["sk"]["S"]

    def _guard(self, operation, request, apply):
        _used(request)
        mode, exc = self.faults.take(operation)
        if mode == "before":
            raise exc
        hook = self.before.get(operation)
        if hook:
            hook(request)
        result = apply()
        if mode == "after":
            raise exc
        return result

    def put_item(self, **request):
        def apply():
            key = self._id(request["Item"])
            old = self.items.get(key)
            if not _check(request, old):
                raise FakeClientError("ConditionalCheckFailedException", copy.deepcopy(old))
            self.items[key] = copy.deepcopy(request["Item"])
            return {}
        return self._guard("put_item", request, apply)

    def update_item(self, **request):
        def apply():
            key = self._id(request["Key"])
            old = self.items.get(key)
            if not _check(request, old):
                returned = (copy.deepcopy(old) if request.get(
                    "ReturnValuesOnConditionCheckFailure") == "ALL_OLD" else None)
                raise FakeClientError("ConditionalCheckFailedException", returned)
            item = copy.deepcopy(old) if old else copy.deepcopy(request["Key"])
            expression = request["UpdateExpression"]
            if not expression.startswith("SET "):
                raise ValueError("fake supports SET only")
            names = request.get("ExpressionAttributeNames", {})
            values = request.get("ExpressionAttributeValues", {})
            for part in expression[4:].split(","):
                left, right = (x.strip() for x in part.split("="))
                item[names[left]] = copy.deepcopy(values[right])
            self.items[key] = item
            if request.get("ReturnValues") == "ALL_NEW":
                return {"Attributes": copy.deepcopy(item)}
            return {}
        return self._guard("update_item", request, apply)

    def get_item(self, **request):
        def apply():
            item = self.items.get(self._id(request["Key"]))
            return {"Item": copy.deepcopy(item)} if item else {}
        return self._guard("get_item", request, apply)

    def query(self, **request):
        def apply():
            if request["KeyConditionExpression"] != "#pk = :pk":
                raise ValueError("fake supports partition-key queries only")
            pk = request["ExpressionAttributeValues"][":pk"]["S"]
            rows = sorted((v for (p, _), v in self.items.items() if p == pk),
                          key=lambda item: item["sk"]["S"],
                          reverse=not request.get("ScanIndexForward", True))
            return {"Items": copy.deepcopy(rows[:request.get("Limit", len(rows))])}
        return self._guard("query", request, apply)


class FakeS3:
    """Write-once aware object store: If-None-Match '*' and SHA-256 checksum validation."""

    def __init__(self, require_if_none_match=True):
        self.objects = {}
        self.faults = Faults()
        self.require_if_none_match = require_if_none_match

    def put_object(self, **request):
        mode, exc = self.faults.take("put_object")
        if mode == "before":
            raise exc
        key = (request["Bucket"], request["Key"])
        if self.require_if_none_match and request.get("IfNoneMatch") != "*":
            raise FakeClientError("AccessDenied", message="bucket policy requires If-None-Match")
        if request.get("IfNoneMatch") == "*" and key in self.objects:
            raise FakeClientError("PreconditionFailed")
        body = request["Body"]
        digest = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
        if request.get("ChecksumSHA256") not in (None, digest):
            raise FakeClientError("BadDigest")
        self.objects[key] = {"Body": bytes(body), "ChecksumSHA256": digest,
                             "Metadata": dict(request.get("Metadata", {})),
                             "ContentType": request.get("ContentType")}
        if mode == "after":
            raise exc
        return {"ChecksumSHA256": digest}

    def get_object_attributes(self, **request):
        mode, exc = self.faults.take("get_object_attributes")
        if mode:
            raise exc
        stored = self.objects.get((request["Bucket"], request["Key"]))
        if stored is None:
            raise FakeClientError("NoSuchKey")
        return {"Checksum": {"ChecksumSHA256": stored["ChecksumSHA256"]},
                "ObjectSize": len(stored["Body"])}

    def get_object(self, **request):
        mode, exc = self.faults.take("get_object")
        if mode:
            raise exc
        stored = self.objects.get((request["Bucket"], request["Key"]))
        if stored is None:
            raise FakeClientError("NoSuchKey")
        return {"Body": _Stream(stored["Body"]), "ContentLength": len(stored["Body"])}


class _Stream:
    def __init__(self, data):
        self._data = data

    def read(self, amount=None):
        data, self._data = self._data, b""
        return data


class FakeKms:
    """Wiring stand-in only: an HMAC, not ECDSA. Says nothing about real KMS signatures."""

    def __init__(self, secret=b"offline-fake-kms"):
        self.secret, self.faults, self.sign_calls = secret, Faults(), []

    def _mac(self, key_id, message):
        import hmac
        return hmac.new(self.secret, key_id.encode() + b"|" + message, hashlib.sha256).digest()

    def sign(self, **request):
        self.sign_calls.append(request)
        mode, exc = self.faults.take("sign")
        if mode:
            raise exc
        if request["MessageType"] != "DIGEST" or len(request["Message"]) != 32:
            raise FakeClientError("ValidationException")
        return {"Signature": self._mac(request["KeyId"], request["Message"])}

    def verify(self, **request):
        mode, exc = self.faults.take("verify")
        if mode:
            raise exc
        if request["Signature"] != self._mac(request["KeyId"], request["Message"]):
            raise FakeClientError("KMSInvalidSignatureException")
        return {"SignatureValid": True}


class FakeEc2:
    """Instances with tags and a state; terminate is tracked per call for assertions."""

    def __init__(self):
        self.instances = {}
        self.faults = Faults()
        self.terminate_calls = []

    def add(self, instance_id, state="running", **tags):
        self.instances[instance_id] = {"state": state, "tags": dict(tags)}

    def describe_instances(self, **request):
        mode, exc = self.faults.take("describe_instances")
        if mode:
            raise exc
        wanted = {f["Name"]: set(f["Values"]) for f in request.get("Filters", [])}
        found = []
        for instance_id, data in sorted(self.instances.items()):
            ok = True
            for name, values in wanted.items():
                if name.startswith("tag:"):
                    ok = ok and data["tags"].get(name[4:]) in values
                elif name == "instance-state-name":
                    ok = ok and data["state"] in values
                else:
                    raise ValueError("fake does not support filter " + name)
            if ok:
                found.append({"InstanceId": instance_id, "State": {"Name": data["state"]},
                              "Tags": [{"Key": k, "Value": v}
                                       for k, v in sorted(data["tags"].items())]})
        return {"Reservations": [{"Instances": found}] if found else []}

    def terminate_instances(self, **request):
        self.terminate_calls.append(list(request["InstanceIds"]))
        mode, exc = self.faults.take("terminate_instances")
        if mode == "before":
            raise exc
        changes = []
        for instance_id in request["InstanceIds"]:
            if instance_id not in self.instances:
                raise FakeClientError("InvalidInstanceID.NotFound")
            previous = self.instances[instance_id]["state"]
            if previous != "terminated":
                self.instances[instance_id]["state"] = "shutting-down"
            changes.append({"InstanceId": instance_id,
                            "PreviousState": {"Name": previous},
                            "CurrentState": {"Name": self.instances[instance_id]["state"]}})
        if mode == "after":
            raise exc
        return {"TerminatingInstances": changes}
