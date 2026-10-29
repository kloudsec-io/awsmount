# Writing a provider

A provider describes one AWS service as data: which list call fills each
collection, how resources are keyed and named, which files and links each
resource directory has, and which API operations it is allowed to call. The
tree, caching, budget, masking, error handling and every adapter (shell,
WebDAV, FUSE, export) come for free.

The protocol lives in `src/awsmount/providers/base.py`. For the wider picture
(layers, the read-only guard, how directories are built from a provider) see
[ARCHITECTURE.md](ARCHITECTURE.md).

## 1. Rules

1. **Read-only.** Only call operations whose model name starts with
   `Describe`, `List`, `Get`, `Search` or `Lookup`, and that are not in
   `DENIED_OPS` (`session/clients.py`).
2. **Declare every operation.** `CollectionSpec.ops` lists the CamelCase
   model names of **every** call made by that collection's lister, files,
   tags and links, for example `ListFunctions` for `list_functions`. The
   client guard refuses anything else before any HTTP request; such a call
   shows up as an error in `errors.log`.
3. **One list call per collection.** A lister makes one (paginated) call
   through `ListCtx.paginate` / `ListCtx.call`. Batched describes, as in
   ECS (100 clusters or 10 services per call), are acceptable. Never call
   per item in a lister.
4. **No N+1.** Files derived from the listed item use `lazy=False` and make
   no call. Anything that needs a call is `lazy=True` and runs only when the
   file is read or stat'ed. If the list API returns names only, set
   `describe=` so that `describe.json` itself becomes lazy.
5. **Go through the context.** Always use `lc.call`/`lc.paginate` and
   `rc.call`/`rc.paginate`, never a boto3 client directly. These calls are
   cached, single-flight, concurrency-limited, budgeted and classified.
6. **Operation names are snake_case.** `op` arguments are boto3 method
   names (`describe_instances`), and they must really exist in boto3.
   `paginate` needs an operation that has a paginator.

## 2. Building blocks

| Class | Purpose |
|---|---|
| `ServiceSpec(dirname, scope, collections)` | One service directory. `scope` is `"region"` or `"global"`. |
| `CollectionSpec(...)` | One collection (see the fields below). |
| `FileSpec(name, render, lazy=False, redact=None, whole=None, not_configured=frozenset())` | An extra file. `render(rc)` returns `bytes`, `str` (a newline is added) or a JSON value (rendered sorted, indent 2). |
| `SubdirSpec(name, entries, lazy=True, redact=None)` | A directory of files. `entries(rc)` returns `{filename: callable}`; filenames are escaped. |
| `LinkSpec(name, target, values, by="key", many=False)` | Symlink(s) under `links/`. `values(rc)` returns one value, several values, or `None`. With `many=True` the name is a directory of links. |
| `RefSource(source, values)` | For `referenced_by`: `values(item)` returns the target keys referenced by an item of the `source` collection (same scope). |
| `TagSpec(inline=None, style="list", fetch=None)` | Tags inline in the item (`[{Key, Value}]` or a map), or fetched lazily by `fetch(rc)`. `TagSpec.none()` means no tags. |
| `CollectionRef(scope, service, collection)` | Address of a collection. Shared constants live in `providers/refs.py`. Nested collections use `"parent/child"`. |

`CollectionSpec` fields:

| Field | Meaning |
|---|---|
| `name` | Directory name of the collection. |
| `client` | boto3 client name (`"ec2"`, `"lambda"`, ...). |
| `lister(lc) -> list[dict]` | The single list call. `lc.parent` is set for nested collections. |
| `key(item) -> str` | Stable unique id. |
| `ops` | Allow-listed model operation names (rule 2). |
| `display(item)` | Human name used for the directory. Collisions get `~<key>`. `None` means the key is the name ("id-keyed"; links then need no listing). |
| `arn(item, scope)` | Content of the `arn` file. |
| `name_of(item)` | Content of the `name` file (defaults to the inline `Name` tag). |
| `describe(rc) -> dict` | Lazy detail call. It feeds `describe.json` and `rc.detail()`. |
| `redact` | Rule set id applied to `describe.json`. |
| `tags`, `files`, `links`, `referenced_by`, `children` | As above; `children` are nested collections. |
| `lookup` | `{"arn": fn, "name": fn}` used to resolve `by="arn"`/`by="name"` links pointing at this collection. |
| `key_from_arn(arn) -> str` | Fast path for `by="arn"` links (no listing needed). |

`ResourceCtx` (`rc`) gives `item`, `key`, `dirname`, `path`, `scope`,
`parent`, `ctx`, `call`, `paginate` and `detail()`.

## 3. Failure behaviour you get for free

- **Lister failure.** The directory is empty and the failure is logged to
  `_meta/errors.log`. NOT_CONFIGURED errors are not logged.
- **Lazy file failure.**
  - NOT_CONFIGURED, or an error code listed in `FileSpec.not_configured`:
    the content is `null`.
  - NOT_FOUND: `null`, plus a log entry.
  - ACCESS_DENIED: EACCES, plus a log entry.
  - Anything else: EIO, plus a log entry.
- **Budget exhausted.** `BudgetExceeded` always propagates as EIO and is
  never cached.

## 4. Masking

- Add JSON rule sets to `RULES` in `session/redact.py` and reference them
  with `redact=` on a `CollectionSpec`, `FileSpec` or `SubdirSpec`.
  - Pattern syntax: `.` separates keys, `*` matches any key, `[]` matches
    every list element, `[?K=V]` filters list elements, `[?K~SECRET]`
    filters on the generic secret regex, and `**` matches any depth.
- For files that must not even be fetched without `--reveal`, add a
  whole-file rule to `WHOLE_RULES` and set `FileSpec(whole=...)`.
- The generic heuristics (secret-looking keys, environment lists) run on
  every JSON file automatically.

## 5. Example: Step Functions state machines

This example is illustrative and not shipped.

```python
"""AWS Step Functions provider: state machines."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from awsmount.providers import refs
from awsmount.providers.base import (
    CollectionSpec,
    FileSpec,
    LinkSpec,
    ListCtx,
    ResourceCtx,
    ServiceSpec,
    TagSpec,
)
from awsmount.providers.common import name_from_arn, parse_json_text
from awsmount.providers.ec2 import field_text
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = ["SERVICE", "STATE_MACHINES"]


def _list(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListStateMachines call for the region."""
    return [m for m in lc.paginate("list_state_machines", "stateMachines")
            if isinstance(m, dict) and m.get("stateMachineArn")]


def _describe(rc: ResourceCtx) -> dict[str, Any]:
    """describe.json (lazy DescribeStateMachine)."""
    return rc.call("describe_state_machine",
                   stateMachineArn=rc.item["stateMachineArn"])


def _definition(rc: ResourceCtx) -> Content:
    """definition.json: the parsed ASL definition (from describe)."""
    result: Content = parse_json_text(rc.detail().get("definition"))
    return result


def _tags(rc: ResourceCtx) -> dict[str, str]:
    """Tags from ListTagsForResource (``[{key, value}]``)."""
    resp = rc.call("list_tags_for_resource",
                   resourceArn=rc.item["stateMachineArn"])
    return {str(t["key"]): str(t.get("value", ""))
            for t in resp.get("tags", []) or []
            if isinstance(t, dict) and "key" in t}


def _arn(item: dict[str, Any], scope: Scope) -> str | None:
    """ARN as listed."""
    return str(item.get("stateMachineArn") or "") or None


STATE_MACHINES = CollectionSpec(
    name="state-machines",
    client="stepfunctions",
    lister=_list,
    key=lambda i: str(i["name"]),
    ops=frozenset({"ListStateMachines", "DescribeStateMachine",
                   "ListTagsForResource"}),
    arn=_arn,
    describe=_describe,
    tags=TagSpec(fetch=_tags),
    files=(
        FileSpec("type", field_text("type")),
        FileSpec("definition.json", _definition, lazy=True),
    ),
    links=(
        LinkSpec("role", refs.IAM_ROLES,
                 lambda rc: rc.detail().get("roleArn"), by="arn"),
    ),
    lookup={"arn": lambda i: str(i.get("stateMachineArn", ""))},
    key_from_arn=name_from_arn,
)

SERVICE = ServiceSpec(dirname="stepfunctions", scope="region",
                      collections=(STATE_MACHINES,))
```

The example applies the rules as follows:

- `type` is derived from the listing and costs nothing.
- `describe.json`, `definition.json`, the role link and the tags are lazy.
  `definition.json` and the role link reuse the cached describe call.

## 6. Registering

1. Save the module as `src/awsmount/providers/<name>.py`, exposing
   `SERVICE`.
2. Append the module name to `PROVIDER_MODULES` in
   `providers/__init__.py`. The order there is the order of
   `awsmount services`.
3. Add `CollectionRef` constants for your collections to `providers/refs.py`
   if other providers link to them. Add CloudFormation types to
   `providers/cfn_types.py` if stack resources should link to them.
4. Regenerate the coverage docs:

   ```
   awsmount services --markdown > docs/coverage.md
   ```

   Update the count and the table in `README.md` to match. `test_cli`
   checks that the README count equals the registry.

## 7. Testing

- `ProviderRegistry().validate()` must return `[]`. It checks names, that
  `ops` are non-empty, read-only and not denied, link targets,
  referenced-by sources, and duplicate links.
- Add `tests/providers/test_<name>.py` using moto (`mock_aws`) and the
  seeding in `tests/fixtures/seed.py`. Assert the expected files exist,
  that `describe.json` equals the canonical render of the response, that
  masking markers are present, and that links resolve with
  `vfs.resolve`.
- The registry test checks that the calls made during a full-tree walk are
  a subset of the declared `ops`.
- Mark moto gaps with `pytest.mark.xfail(strict=True)`.
