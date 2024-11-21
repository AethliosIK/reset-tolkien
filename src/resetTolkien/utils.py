# -*- coding: utf-8 -*-
# Author: Aethlios <contact@aeth.cc>

import uuid
import math
import random
import datetime
import argparse
import ast

from threading import Lock
from yaml import safe_load
from typing import Generator, Callable, Any, Optional, TypeAlias, Protocol
from typing_extensions import Self
from functools import partial
from urllib.parse import unquote_plus
from decimal import Decimal

import dateparser  # type: ignore
import hidateinfer  # type: ignore

from resetTolkien.constants import (
    NB_DAYS_LIMIT,
    TIMESTAMP_HEX_LENGTH,
    MIN_DEPTH_LEVEL,
    MAX_DEPTH_LEVEL,
    MIN_LENGTH_OF_FLOATING_TIMESTAMP_HEX,
    MAX_LENGTH_OF_FLOATING_TIMESTAMP_HEX,
    SERVER_DATE_FORMAT,
    UUID_DECIMAL_LENGTH,
)


# EXCEPTION


class NotAHash(Exception):
    pass


# GENERATOR

TimestampGenerator: TypeAlias = Generator[tuple[str, str], None, None]


class AlternativeGen:
    """Generic class for defining the generator by alternative trial
    [0, 1, -1, 2, -2, ...]"""

    def __init__(self, range: int) -> None:
        self.range = range
        self.flipper = True
        self.n = 0

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> int:
        return self.next()

    def next(self) -> int:
        if self.n > self.range - 1:
            raise StopIteration()

        self.n += 1
        self.flipper = not self.flipper

        return (-1 if self.flipper else 1) * math.floor(self.n / 2)


class GeneratorLen(object):
    """Generic class for defining the length of a finite generator"""

    def __init__(self, gen: TimestampGenerator, length: int) -> None:
        self.gen = gen
        self.length = length

    def __type__(self) -> type:
        return type(self.gen)

    def __len__(self) -> int:
        return self.length

    def __iter__(self) -> TimestampGenerator:
        return self.gen


# TYPE


class SplitArgs(argparse.Action):
    """Action class to parse str with delimiter to list"""

    delimiter = ","

    def __call__(self, parser, namespace, values, option_string=None) -> None:  # type: ignore
        setattr(namespace, self.dest, [value.strip() for value in values.split(self.delimiter)])  # type: ignore


class EncodingType(Protocol):
    """Type for Encoding functions"""

    def __call__(self, token: str, encode: bool = True, **kwargs: Any) -> str: ...

    def __name__(self) -> str:
        return self.__call__.__name__


class HashingType(Protocol):
    """Type for Hashing functions"""

    def __call__(
        self,
        token: str,
        **kwargs: Any,
    ) -> str: ...

    def __name__(self) -> str:
        return self.__call__.__name__


FormatType: TypeAlias = EncodingType | HashingType | partial[Any]
HashIdentifierType: TypeAlias = Callable[[str], Optional[HashingType]]


# Function


# Credit to https://github.com/intruder-io/guidtool
def uuid1(node: int, clock_seq: int, timestamp: Decimal) -> uuid.UUID:
    """Generates a UUID from a host ID, sequence number, and the current time.
    If 'node' is not given, getnode() is used to obtain the hardware
    address.  If 'clock_seq' is given, it is used as the sequence number;
    otherwise a random 14-bit sequence number is chosen."""

    t = int(timestamp * 10**UUID_DECIMAL_LENGTH) + 0x01B21DD213814000

    time_low = t & 0xFFFFFFFF
    time_mid = (t >> 32) & 0xFFFF
    time_hi_version = (t >> 48) & 0x0FFF
    clock_seq_low = clock_seq & 0xFF
    clock_seq_hi_variant = (clock_seq >> 8) & 0x3F
    return uuid.UUID(
        fields=(
            time_low,
            time_mid,
            time_hi_version,
            clock_seq_hi_variant,
            clock_seq_low,
            node,
        ),
        version=1,
    )


def to_uuidv1(timestamp: str, init_token: str) -> str:
    """Converts a timestamp to a UUID via a provided UUID"""

    try:
        u = uuid.UUID(init_token)
    except (ValueError, AttributeError):
        raise ValueError("Not a UUID")
    if u.version != 1:
        raise ValueError("Not a UUIDv1")
    return str(uuid1(u.node, u.clock_seq, Decimal(timestamp)))


def from_uuidv1(token: str) -> str:
    """Extracts a timestamp from an UUID"""

    try:
        u = uuid.UUID(token)
    except (ValueError, AttributeError):
        raise ValueError("Not a UUID")
    if u.version != 1:
        raise ValueError("Not a UUIDv1")
    return str((u.time - 0x01B21DD213814000) / 10000000)


class MongoDBObjectID:
    def __init__(self, s: str) -> None:
        if len(s) != 24:
            raise ValueError("Wrong length")
        self.timestamp = int(s[:8], 16)
        self.machine = int(s[8:14], 16)
        self.process = int(s[14:18], 16)
        self.counter = int(s[18:24], 16)

    def set_timestamp(self, timestamp: int) -> None:
        self.timestamp = timestamp

    def __str__(self) -> str:
        return "%08x%06x%04x%06x" % (
            self.timestamp,
            self.machine,
            self.process,
            self.counter,
        )


def to_mongodb_objectid(timestamp: str, init_token: str) -> str:
    try:
        u = MongoDBObjectID(init_token)
    except (ValueError, AttributeError):
        raise ValueError("Not a MongoDBObjectID")
    u.set_timestamp(int(timestamp))
    return str(u)


def from_mongodb_objectid(token: str) -> str:
    try:
        u = MongoDBObjectID(token)
    except (ValueError, AttributeError):
        raise ValueError("Not a MongoDBObjectID")
    return str(u.timestamp)


# Credit to https://github.com/Riamse/python-uniqid
def uniqid(timestamp: Decimal, prefix: str = "", more_entropy: bool = False) -> str:
    """uniqid([prefix=''[, more_entropy=False]]) -> str
    Gets a prefixed unique identifier based on the current
    time in microseconds.
    prefix
        Can be useful, for instance, if you generate identifiers
        simultaneously on several hosts that might happen to generate
        the identifier at the same microsecond.
        With an empty prefix, the returned string will be 13 characters
        long. If more_entropy is True, it will be 23 characters.
    more_entropy
        If set to True, uniqid() will add additional entropy (using
        the combined linear congruential generator) at the end of
        the return value, which increases the likelihood that
        the result will be unique.
    Returns the unique identifier, as a string."""

    sec, usec = divmod(timestamp, 1)
    sec = int(sec)
    usec = int(usec * 1000000)
    while usec != 0 and usec % 10 == 0:
        usec = int(usec / 10)
    if more_entropy:
        lcg = random.random()
        the_uniqid = "%08x%05x%.8F" % (sec, usec, lcg * 10)
    else:
        the_uniqid = "%8x%05x" % (sec, usec)

    the_uniqid = prefix + the_uniqid
    return the_uniqid


def deuniqid(value: str) -> str:
    """Converts the timestamp from an uniqid value"""

    if (
        len(value) < MIN_LENGTH_OF_FLOATING_TIMESTAMP_HEX
        or len(value) > MAX_LENGTH_OF_FLOATING_TIMESTAMP_HEX
    ):
        raise ValueError("The input is too short")
    return (
        str(int(value[:TIMESTAMP_HEX_LENGTH], 16))
        + "."
        + str(int(value[TIMESTAMP_HEX_LENGTH:], 16))
    )


def urlencode(value: str) -> str:
    """URL-encodes all values"""

    return "".join("%{0:0>2x}".format(ord(char)) for char in str(value))


def urldecode(value: str) -> str:
    """URL-decodes all URL-encoded values - trigger an exception if no value is encoded"""

    decoded = unquote_plus(value)
    if decoded == value:
        raise ValueError("data is not urlencoded")
    return decoded


def from_microsecond_timestamp(
    token: Decimal | int,
    timezone: int = 0,
    date_format_of_token: str | None = None,
    verify: bool = False,
) -> str:
    """Converts a timestamp to a standard string of datetime or formated by date_format_of_token"""

    timezone_delta = datetime.timedelta(hours=timezone)
    d = (
        datetime.datetime.fromtimestamp(
            float(str(token)), datetime.timezone.utc
        ).replace(tzinfo=datetime.timezone(timezone_delta))
        + timezone_delta
    )
    now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=timezone)))
    if (
        verify
        and d < now - datetime.timedelta(days=NB_DAYS_LIMIT)
        or d > now + datetime.timedelta(days=NB_DAYS_LIMIT)
    ):
        raise ValueError("Not a timestamp")
    if date_format_of_token:
        return d.strftime(date_format_of_token)
    return d.isoformat()


def to_microsecond_timestamp(d: str) -> str:
    """Converts a standard string of datetime to a timestamp"""

    return str(datetime.datetime.fromisoformat(d).timestamp())


def detect_datetime(token: str) -> datetime.datetime:
    """Extracts a date from a string - trigger an exception if it is not a date"""

    date = dateparser.parse(token)
    if not date:
        raise ValueError("Not a date")
    return date


def possible_date_format_of_token(token: str) -> Any:
    """Tries to extract possible datetime formats from a datetime string"""

    return hidateinfer.infer([token])  # type: ignore


# FORMAT


def import_format_with_args(
    format: str, formats: dict[str, EncodingType]
) -> tuple[FormatType, dict[str, Any]]:
    """Function to import the format function with args"""

    class FunctionNamePrinter(ast.NodeVisitor):
        def __init__(self, formats: dict[str, EncodingType]) -> None:
            self.formats: dict[str, EncodingType] = formats
            super().__init__()

        def visit_Module(self, node: ast.Module) -> Any:
            if (
                len(node.body) > 0
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Call)
            ):
                return self.visit_Call(node.body[0].value)
            raise ValueError(f"No good expression : {node.body}")

        def visit_Call(self, node: ast.Call) -> Any:
            name = None
            if isinstance(node.func, ast.Name):
                name = self.visit_Name(node.func)
            if not name:
                raise ValueError(f"No name : {node.func}")
            args: dict[str, str] = {}
            for keyword in node.keywords:
                k: dict[str, str] = self.visit_keyword(keyword)
                args.update(k)
            return name, args

        def visit_Name(self, node: ast.Name) -> Any:
            func_name: str = str(node.id)
            for f in self.formats:
                if func_name == f:
                    return self.formats[f]
            raise ValueError(f"{node.id} doesn't exist")

        def visit_Constant(self, node: ast.Constant) -> Any:
            return node.value

        def visit_keyword(self, node: ast.keyword) -> Any:
            if isinstance(node.value, ast.Constant):
                return {node.arg: self.visit_Constant(node.value)}
            raise ValueError(f"No constant : {node.value}")

    module: ast.Module = ast.parse(format)
    visitor = FunctionNamePrinter(formats)
    return visitor.visit(module)


# TimestampHashFormat


class TimestampHashFormat:
    """Class used to define the timestamp format parameters
    provided to decrypt a hash."""

    def __init__(
        self,
        description: str,
        timestamp_type: type,
        level: int = MIN_DEPTH_LEVEL,
        formats_output: Optional[list[FormatType]] = None,
    ) -> None:
        self.description = description
        self.timestamp_type = timestamp_type
        self.level = level
        self.formats_output: list[FormatType] = (
            [] if formats_output is None else formats_output
        )

    def __repr__(self) -> str:
        return f"({self.level}) {self.description}"


class TimestampFormatType:
    """"""

    def __init__(
        self,
        timestamp_type: type,
        timestamp_type_func: Callable[[str], Decimal | int],
        range_limit: int,
    ) -> None:
        self.timestamp_type = timestamp_type
        self.timestamp_type_func = timestamp_type_func
        self.range_limit = range_limit

    def __repr__(self) -> str:
        return f"{self.timestamp_type}"


def import_from_yaml(
    filename: str,
    selected_level: int,
    allEncoding: dict[str, EncodingType],
) -> list[TimestampHashFormat]:
    """From a YAML file, imports a TimestampHashFormat list"""

    r: list[TimestampHashFormat] = []
    with open(filename) as f:
        hashFormats = safe_load(f)
        for f in hashFormats:
            hashFormat = hashFormats[f]
            level = (
                int(hashFormat["level"]) if "level" in hashFormat else MIN_DEPTH_LEVEL
            )
            if level > MAX_DEPTH_LEVEL:
                raise ValueError(f"Please set a value < {MAX_DEPTH_LEVEL}")
            if selected_level < level:
                continue
            description = (
                str(hashFormat["description"])
                if "description" in hashFormat
                else "Not described"
            )
            if hashFormat["timestamp_type"] == "int":
                timestamp_type = int
            elif hashFormat["timestamp_type"] == "float":
                timestamp_type = float
            else:
                raise ValueError('Please set "int" or "float" types.')
            formats: list[FormatType] = []
            if "formats" in hashFormat:
                for f in [str(f) for f in hashFormat["formats"]]:
                    if not f in allEncoding.keys():
                        raise ValueError(
                            f"Please set a valid format : {allEncoding.keys()}."
                        )
                    else:
                        formats.append(allEncoding[f])
            r.append(
                TimestampHashFormat(
                    description=description,
                    timestamp_type=timestamp_type,
                    level=level,
                    formats_output=formats,
                )
            )
    return sorted(r, key=lambda x: x.level)


# EXAMPLE VALUE

server_date_example = datetime.datetime.now(datetime.timezone.utc).strftime(
    SERVER_DATE_FORMAT
)
