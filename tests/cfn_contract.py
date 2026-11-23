"""Shared helpers for offline CloudFormation contract tests (AWS-B / AWS-C).

Local structural checks only: NOT AWS schema, IAM or service validation. Standard library.
"""
import json
import re

PSEUDO = {"AWS::AccountId", "AWS::Partition", "AWS::Region", "AWS::StackId",
          "AWS::StackName", "AWS::NoValue"}
INTRINSICS = {"Fn::GetAtt", "Fn::Sub", "Fn::Join", "Fn::Select", "Fn::Split", "Fn::If",
              "Fn::Equals", "Fn::And", "Fn::Or", "Fn::Base64"}


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate member")
        out[key] = value
    return out


def strict_json(raw):
    def reject(_value):
        raise ValueError("non-finite JSON constant")
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=reject)


def load(path):
    return strict_json(path.read_text(encoding="utf-8"))


def walk(value):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def reference_errors(template, getatt):
    """Every Ref / GetAtt / Sub / If / Condition / DependsOn must resolve locally."""
    errors = []
    resources = set(template.get("Resources", {}))
    symbols = resources | set(template.get("Parameters", {})) | PSEUDO
    conditions = set(template.get("Conditions", {}))

    def visit(value):
        if isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, dict):
            for key, child in value.items():
                if key.startswith("Fn::") and key not in INTRINSICS:
                    errors.append("unsupported intrinsic " + key)
                if key == "Ref" and child not in symbols:
                    errors.append("unknown Ref %r" % (child,))
                if key == "Fn::GetAtt" and (
                        not isinstance(child, list) or len(child) != 2
                        or child[0] not in resources
                        or child[1] not in getatt.get(child[0], set())):
                    errors.append("unknown GetAtt %r" % (child,))
                if key == "Fn::Sub":
                    if not isinstance(child, str):
                        errors.append("unsupported Sub form")
                    else:
                        for name in re.findall(r"\$\{([^}]+)\}", child):
                            head, _, attr = name.partition(".")
                            if head not in symbols or (
                                    attr and attr not in getatt.get(head, set())):
                                errors.append("unknown Sub symbol " + name)
                if key == "Fn::If" and (not isinstance(child, list) or len(child) != 3
                                        or child[0] not in conditions):
                    errors.append("unknown Condition in Fn::If")
                visit(child)
    try:
        visit(template)
        for resource in template.get("Resources", {}).values():
            condition = resource.get("Condition")
            if condition is not None and condition not in conditions:
                errors.append("unknown resource Condition")
            depends = resource.get("DependsOn", [])
            for name in [depends] if isinstance(depends, str) else depends:
                if name not in resources:
                    errors.append("unknown DependsOn " + str(name))
    except (TypeError, KeyError, IndexError, AttributeError):
        errors.append("invalid reference structure")
    return errors


def rule_assertion_errors(template, overrides=None):
    """Check/evaluate this project's scalar Rules subset, not the AWS service schema.

    Number parameter Refs are strings in Rules. Numeric *literals* must be rejected
    before evaluation, rather than coerced and accidentally accepting the LIVE bug.
    """
    errors = []
    parameters = template.get("Parameters", {})
    values = {name: spec.get("Default") for name, spec in parameters.items()}
    values.update(overrides or {})

    def scalar(operand):
        if type(operand) is str:
            return operand
        if (type(operand) is dict and set(operand) == {"Ref"}
                and operand["Ref"] in parameters
                and parameters[operand["Ref"]].get("Type") in ("String", "Number")):
            value = values[operand["Ref"]]
            if type(value) in (str, int, float):
                return str(value)
        raise ValueError("Fn::Equals requires two string operands (literal or scalar parameter Ref)")

    def evaluate(node):
        if type(node) is not dict or len(node) != 1:
            raise ValueError("unsupported Rule expression")
        name, args = next(iter(node.items()))
        if name == "Fn::Equals":
            if type(args) is not list or len(args) != 2:
                raise ValueError("Fn::Equals requires exactly two operands")
            return scalar(args[0]) == scalar(args[1])
        if name in ("Fn::And", "Fn::Or") and type(args) is list and 2 <= len(args) <= 10:
            results = [evaluate(arg) for arg in args]  # validate every branch
            return all(results) if name == "Fn::And" else any(results)
        raise ValueError("unsupported Rule expression")

    for name, rule in template.get("Rules", {}).items():
        for assertion in rule.get("Assertions", []):
            try:
                if not evaluate(assertion["Assert"]):
                    errors.append(name + ": assertion rejected parameter combination")
            except (ValueError, KeyError, TypeError) as exc:
                errors.append(name + ": " + str(exc))
    return errors


def statements(document):
    """Policy statements; a conditional statement (Fn::If) contributes both branches."""
    found = document.get("Statement", [])
    out = []
    for statement in found if isinstance(found, list) else [found]:
        if isinstance(statement, dict) and set(statement) == {"Fn::If"}:
            out.extend(branch for branch in statement["Fn::If"][1:]
                       if branch != {"Ref": "AWS::NoValue"})
        else:
            out.append(statement)
    return out


def actions(statement):
    value = statement.get("Action", [])
    return [value] if isinstance(value, str) else list(value)


def iam_wildcard_errors(template, allowed_star_actions=frozenset(), exempt_sids=frozenset()):
    """No Action '*', no service-wide 'svc:*', no Resource '*' except for listed actions,
    no NotAction/NotResource, no '*' principal in an Allow statement. Statements whose Sid
    is in `exempt_sids` must be audited explicitly by the caller instead."""
    errors = []
    for node in walk(template.get("Resources", {})):
        if not (isinstance(node, dict) and "Statement" in node):
            continue
        for statement in statements(node):
            if statement.get("Sid") in exempt_sids:
                continue
            if "NotAction" in statement or "NotResource" in statement \
                    or "NotPrincipal" in statement:
                errors.append("Not* element")
            acts = actions(statement)
            if statement.get("Effect") == "Allow":
                if any(a == "*" or a.endswith(":*") for a in acts):
                    errors.append("wildcard action")
                if statement.get("Principal") in ("*", {"AWS": "*"}):
                    errors.append("wildcard principal")
                resource = statement.get("Resource")
                if "Principal" not in statement and (resource == "*" or resource == ["*"]):
                    if not set(acts) <= set(allowed_star_actions):
                        errors.append("wildcard resource for " + ",".join(sorted(acts)))
    return errors


def render_sub(text, values):
    """Evaluate a string-form Fn::Sub with supplied parameter values (test helper)."""
    return re.sub(r"\$\{([^}]+)\}", lambda m: str(values[m.group(1)]), text)
