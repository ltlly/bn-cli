"""Filter, order and project rows from the bridge's read-only list operations."""

from __future__ import annotations

import operator
import re

FIELDS = {
    "functions": ("name", "address", "raw_name"),
    "strings": ("address", "length", "type", "value"),
    "imports": ("name", "address", "library"),
}
NUMERIC = {"address", "length"}
COMPARE = {"=": operator.eq, "!=": operator.ne, ">": operator.gt, "<": operator.lt,
           ">=": operator.ge, "<=": operator.le}


def _field(name, available):
    if name not in available:
        raise ValueError(f"Unknown field {name!r}; choose from {', '.join(available)}")
    return name


def _number(value):
    text = str(value)
    return int(text, 16 if text.lower().startswith("0x") else 10)


def _predicate(expression, available):
    match = re.fullmatch(r"\s*(\w+)\s*(!=|>=|<=|=|~|>|<)\s*(.*?)\s*", expression)
    if not match:
        raise ValueError(f"Invalid filter {expression!r}; expected FIELD OP VALUE")
    field, op, literal = match.groups()
    _field(field, available)
    if op == "~":
        needle = literal.casefold()
        return lambda row: needle in str(row[field]).casefold()
    compare = COMPARE[op]
    if field in NUMERIC:
        value = _number(literal)
        return lambda row: compare(_number(row[field]), value)
    return lambda row: compare(str(row[field]), literal)


def query_rows(rows, dataset, *, filters=(), fields=None, sort=None, offset=0, limit=1000, count=False):
    available = FIELDS[dataset]
    if offset < 0 or limit < 0:
        raise ValueError("Query offset and limit must be nonnegative")
    columns = [_field(k.strip(), available) for k in fields.split(",")] if fields is not None else available
    order = []
    if sort is not None:
        for item in sort.split(","):
            key = item.strip()
            order.append((_field(key.removeprefix("-"), available), key.startswith("-")))
    predicates = [_predicate(expr, available) for expr in filters]
    matched = (row for row in rows if all(test(row) for test in predicates))
    if count:
        return {"count": sum(1 for _ in matched)}
    matches = list(matched)
    for field, descending in reversed(order):
        if field in NUMERIC:
            matches.sort(key=lambda row: _number(row[field]), reverse=descending)
        else:
            matches.sort(key=operator.itemgetter(field), reverse=descending)
    return [{key: row[key] for key in columns} for row in matches[offset:offset + limit if limit else None]]
