# -*- coding: utf-8 -*-
# Author: Aethlios <contact@aeth.cc>

import datetime
import base64
from binascii import hexlify
import hashlib
import uuid
import time
from decimal import Decimal, getcontext

from resetTolkien.resetTolkien import ResetTolkien, FormatType
from resetTolkien.utils import uuid1, uniqid, urlencode, MongoDBObjectID
from resetTolkien.constants import TIMESTAMP_STR_LENGTH, UUID_DECIMAL_LENGTH

import sys

verbosity = 0
if len(sys.argv) == 3 and sys.argv[1] == "-v":
    verbosity = int(sys.argv[2])

threads = 8
DECIMAL_LENGTH = UUID_DECIMAL_LENGTH

getcontext().prec = TIMESTAMP_STR_LENGTH + DECIMAL_LENGTH

TIMEDELTA_WITH_FLOAT_VALUE = Decimal(0.1)
TIMEDELTA_WITH_INT_VALUE = 30

OK = "\033[92mOK\033[0m"
NOK = "\033[91mNOK\033[0m"
PROGRESS_ACTIVE = True


def benchmark_multithread() -> None:
    timestamp_input = getFloatTimestamp()
    token = hashlib.md5("value".encode()).hexdigest()
    print("native")
    tolkien = ResetTolkien(
        token=token,
        verbosity=2,
    )
    t = time.time()
    result = tolkien.detectFormat(timestamp=timestamp_input, nb_threads=1)
    t2 = time.time()
    print(result)
    print(f"Time : {t2-t}")
    print("multithread")
    tolkien = ResetTolkien(
        token=token,
        verbosity=2,
        prefixes=["a", "c"],
        suffixes=["b", "d"],
    )
    t = time.time()
    result = tolkien.detectFormat(timestamp=timestamp_input, nb_threads=8)
    t2 = time.time()
    print(result)
    print(f"Time : {t2-t}")


def _check(
    tolkien: ResetTolkien,
    value: str,
    init_token: str,
    results: list[tuple[tuple[str, str | None, str | None], list[FormatType], bool]],
) -> tuple[bool, list[list[FormatType]]]:
    for _, formats, isBasedOnTimestamp in results:
        if isBasedOnTimestamp:
            try:
                result = tolkien.encode(value, formats=formats)
                if result != init_token and len(results) > 0:
                    print(formats)
                    print(
                        f"result : {result} - expected result : {init_token} - value : {value}"
                    )
                return (
                    result == init_token,
                    [formats for _, formats, _ in results if isBasedOnTimestamp],
                )
            except:
                pass
    return (False, [])


def check(
    value: str | Decimal | int,
    init_token: str,
    description: str = "Generic test",
    timestamp_input: Decimal | int | None = None,
    prefixes: list[str] | None = None,
    suffixes: list[str] | None = None,
    date_format_of_token: str | None = None,
    timezone: int = 0,
) -> None:
    prefixes = prefixes if prefixes else []
    suffixes = suffixes if suffixes else []

    if verbosity >= 1:
        print(f"Value : {value}")
        print(f"Token : {init_token}")

    if isinstance(value, int) or isinstance(value, Decimal):
        value = str(value)

    tolkien = ResetTolkien(
        token=init_token,
        timezone=timezone,
        verbosity=verbosity,
        prefixes=prefixes,
        suffixes=suffixes,
        date_format_of_token=date_format_of_token,
        decimal_length=DECIMAL_LENGTH,
        progress_active=PROGRESS_ACTIVE,
    )
    start = time.time()
    results = tolkien.detectFormat(timestamp=timestamp_input, nb_threads=threads)
    end = time.time()
    if not results:
        print(f"[{round(end - start, 3)}s] {description} : {NOK}")
        raise Exception("No defined token")
    if verbosity >= 1:
        print(f"Partial results : {results}")
    success, possible_formats = _check(tolkien, value, init_token, results)
    print(
        f"[{round(end - start, 3)}s] {description} : {(OK if success else NOK)} -> {results[0][0][0]} (possibles formats : {len(possible_formats)})"
    )


def getIntTimestamp() -> int:
    return int(datetime.datetime.now().timestamp())


def getFloatTimestamp() -> Decimal:
    return Decimal.from_float(time.time()) + Decimal(0)


print("[+] Check formats")

timestamp = getIntTimestamp()
token = base64.b32encode(str(timestamp).encode()).decode()
check(timestamp, token, description="Int timestamp with base32")

timestamp = getIntTimestamp()
token = base64.b64encode(str(timestamp).encode()).decode()
check(timestamp, token, description="Int timestamp with base64")

timestamp = getIntTimestamp()
token = urlencode(str(timestamp))
check(timestamp, token, description="Int timestamp with urlencode")

timestamp = getIntTimestamp()
token = hex(timestamp)[2:]
check(timestamp, token, description="Int timestamp with hexint")

timestamp = getIntTimestamp()
token = hexlify(str(timestamp).encode()).decode()
check(timestamp, token, description="Int timestamp with hexstr")

timestamp = getIntTimestamp()
token = str(uniqid(Decimal(timestamp)))
check(
    timestamp,
    token,
    description="Int timestamp with uniqid",
)

timestamp = getIntTimestamp()
mongoOID_example = "65b23087d5888f1392d74c95"
u = MongoDBObjectID(mongoOID_example)
u.set_timestamp(timestamp)
token = str(u)
check(timestamp, token, description="Int timestamp with mongodb_objectid")

timestamp = getIntTimestamp()
u = uuid.uuid1()
token = str(uuid1(u.node, u.clock_seq, Decimal(timestamp)))
check(timestamp, token, description="Int timestamp with uuidv1")

timestamp = getIntTimestamp()
token = base64.b64encode(hex(timestamp)[2:].encode()).decode()
check(timestamp, token, description="Int timestamp with hexint and base64")

timestamp = getIntTimestamp()
token = base64.b64encode(hexlify(str(timestamp).encode())).decode()
check(timestamp, token, description="Int timestamp with hexstr and base64")

timestamp = getFloatTimestamp()
token = base64.b64encode(uniqid(timestamp).encode()).decode()
check(timestamp, token, description="Float timestamp with uniqid and base64")

timestamp = getFloatTimestamp()
token = hexlify(str(timestamp).encode()).decode()
check(timestamp, token, description="Float timestamp with hexstr")

timestamp = getFloatTimestamp()
token = base64.b64encode(hexlify(str(timestamp).encode())).decode()
check(timestamp, token, description="Float timestamp with hexstr and base64")

timestamp = getFloatTimestamp()
token = uniqid(timestamp)
check(timestamp, token, description="Float timestamp with uniqid")


print("[+] Inmport/Export checks")

timestamp = getIntTimestamp()
u = uuid.uuid1()
token = str(uuid1(u.node, u.clock_seq, Decimal(timestamp)))
token2 = str(uuid1(u.node, u.clock_seq + 1, Decimal(timestamp)))
tolkien = ResetTolkien(token=token, formats=["uuidv1"], alternative_tokens=[token2])
tokens = list(
    tolkien.generate_possible_token(timestamp, range_limit=1, formats=tolkien.formats)
)
success = token2 in token2
print(f"Alternative tokens with uuidv1 : {(OK if success else NOK)}")

timestamp = getIntTimestamp()
token = base64.b64encode(
    hashlib.sha1(str(timestamp).encode()).hexdigest().encode()
).decode()

tolkien = ResetTolkien(token=token, formats=["base64", "sha1"])
success = token == tolkien.encode(str(timestamp))
print(f"Format importation : {(OK if success else NOK)}")

tokens = list(
    tolkien.generate_possible_token(timestamp, range_limit=4, formats=tolkien.formats)
)
success = len(tokens) == 4 and len(set(tokens)) == len(tokens) and tokens[0][0] == token
print(f"Possible token exportation : {(OK if success else NOK)}")

print("[+] Check prefix/suffix")

timestamp = getIntTimestamp()
timestamp_input = timestamp - TIMEDELTA_WITH_INT_VALUE
value = str(timestamp)
token = hashlib.md5(value.encode()).hexdigest()
check(
    timestamp,
    token,
    description="Check prefix/suffix from native value with md5",
    timestamp_input=timestamp_input,
    prefixes=["hello", "you"],
    suffixes=["1", "2"],
)

timestamp = getIntTimestamp()
timestamp_input = timestamp - TIMEDELTA_WITH_INT_VALUE
value = "%s%s" % ("you", str(timestamp))
token = hashlib.md5(value.encode()).hexdigest()
check(
    timestamp,
    token,
    description="Check prefix with md5",
    timestamp_input=timestamp_input,
    prefixes=["hello", "you"],
    suffixes=["1", "2"],
)

timestamp = getIntTimestamp()
timestamp_input = timestamp - TIMEDELTA_WITH_INT_VALUE
value = "%s%s" % (str(timestamp), "2")
token = hashlib.md5(value.encode()).hexdigest()
check(
    timestamp,
    token,
    description="Check suffix with md5",
    timestamp_input=timestamp_input,
    prefixes=["hello", "you"],
    suffixes=["1", "2"],
)

print("[+] Check datetime")

date = datetime.datetime.now(tz=datetime.timezone(datetime.timedelta(hours=-7)))
timestamp = Decimal.from_float(date.timestamp())
timestamp_input = timestamp - TIMEDELTA_WITH_FLOAT_VALUE
token = date.strftime("%a, %d %b %Y %H:%M:%S %Z")
check(
    timestamp,
    token,
    description="Datetime RFC2822 with timezone",
    timestamp_input=timestamp_input,
    date_format_of_token="%a, %d %b %Y %H:%M:%S %Z",
    timezone=-7,
)

date = datetime.datetime.now(tz=datetime.timezone(datetime.timedelta(hours=-7)))
timestamp = Decimal.from_float(date.timestamp())
timestamp_input = timestamp - TIMEDELTA_WITH_FLOAT_VALUE
d = date.strftime("%a, %d %b %Y %H:%M:%S -0700")
token = hashlib.sha1(str(d).encode()).hexdigest()
check(
    timestamp,
    token,
    description="Datetime RFC2822 with timezone and sha1",
    timestamp_input=timestamp_input,
    timezone=-7,
)

date = datetime.datetime.now(tz=datetime.timezone.utc)
timestamp = Decimal.from_float(date.timestamp())
timestamp_input = timestamp - TIMEDELTA_WITH_FLOAT_VALUE
token = base64.b64encode(date.isoformat().encode()).decode()
check(
    timestamp,
    token,
    description="Datetime with base64",
    timestamp_input=timestamp_input,
    date_format_of_token="%Y-%m-%dT%H:%M:%S.%f+00:00",
)

print("[+] Check hashes")

timestamp = getIntTimestamp()
timestamp_input = timestamp + TIMEDELTA_WITH_INT_VALUE
token = hashlib.md5(str(timestamp).encode()).hexdigest()
check(
    timestamp,
    token,
    description="Int timestamp with md5 for token after the timestamp",
    timestamp_input=timestamp_input,
)

timestamp = getIntTimestamp()
timestamp_input = timestamp - TIMEDELTA_WITH_INT_VALUE
token = base64.b64encode(
    hashlib.md5(str(timestamp).encode()).hexdigest().encode()
).decode()
check(
    timestamp,
    token,
    description="Int timestamp with md5 and base64",
    timestamp_input=timestamp_input,
)

timestamp = getIntTimestamp()
timestamp_input = timestamp - TIMEDELTA_WITH_INT_VALUE
token = hexlify(hashlib.md5(str(timestamp).encode()).hexdigest().encode()).decode()
check(
    timestamp,
    token,
    description="Int timestamp with md5 and hexstr",
    timestamp_input=timestamp_input,
)

timestamp = getIntTimestamp()
timestamp_input = timestamp - TIMEDELTA_WITH_INT_VALUE
token = hashlib.md5(str(timestamp).encode()).hexdigest()
check(
    timestamp,
    token,
    description="Int timestamp with md5",
    timestamp_input=timestamp_input,
)

timestamp = getIntTimestamp()
timestamp_input = timestamp - TIMEDELTA_WITH_INT_VALUE
token = hashlib.sha1(str(timestamp).encode()).hexdigest()
check(
    timestamp,
    token,
    description="Int timestamp with sha1",
    timestamp_input=timestamp_input,
)

timestamp = getIntTimestamp()
timestamp_input = timestamp - TIMEDELTA_WITH_INT_VALUE
token = hashlib.sha224(str(timestamp).encode()).hexdigest()
check(
    timestamp,
    token,
    description="Int timestamp with sha224",
    timestamp_input=timestamp_input,
)

timestamp = getIntTimestamp()
timestamp_input = timestamp - TIMEDELTA_WITH_INT_VALUE
token = hashlib.sha256(str(timestamp).encode()).hexdigest()
check(
    timestamp,
    token,
    description="Int timestamp with sha256",
    timestamp_input=timestamp_input,
)

timestamp = getIntTimestamp()
timestamp_input = timestamp - TIMEDELTA_WITH_INT_VALUE
token = hashlib.sha384(str(timestamp).encode()).hexdigest()
check(
    timestamp,
    token,
    description="Int timestamp with sha384",
    timestamp_input=timestamp_input,
)

timestamp = getIntTimestamp()
timestamp_input = timestamp - TIMEDELTA_WITH_INT_VALUE
token = hashlib.sha512(str(timestamp).encode()).hexdigest()
check(
    timestamp,
    token,
    description="Int timestamp with sha512",
    timestamp_input=timestamp_input,
)

timestamp = getIntTimestamp()
timestamp_input = timestamp - TIMEDELTA_WITH_INT_VALUE
token = hashlib.sha3_224(str(timestamp).encode()).hexdigest()
check(
    timestamp,
    token,
    description="Int timestamp with sha3_224",
    timestamp_input=timestamp_input,
)

timestamp = getIntTimestamp()
timestamp_input = timestamp - TIMEDELTA_WITH_INT_VALUE
token = hashlib.sha3_256(str(timestamp).encode()).hexdigest()
check(
    timestamp,
    token,
    description="Int timestamp with sha3_256",
    timestamp_input=timestamp_input,
)

timestamp = getIntTimestamp()
timestamp_input = timestamp - TIMEDELTA_WITH_INT_VALUE
token = hashlib.sha3_384(str(timestamp).encode()).hexdigest()
check(
    timestamp,
    token,
    description="Int timestamp with sha3_384",
    timestamp_input=timestamp_input,
)

timestamp = getIntTimestamp()
timestamp_input = timestamp - TIMEDELTA_WITH_INT_VALUE
token = hashlib.sha3_512(str(timestamp).encode()).hexdigest()
check(
    timestamp,
    token,
    description="Int timestamp with sha3_512",
    timestamp_input=timestamp_input,
)

timestamp = getIntTimestamp()
timestamp_input = timestamp - TIMEDELTA_WITH_INT_VALUE
token = hashlib.blake2s(str(timestamp).encode()).hexdigest()
check(
    timestamp,
    token,
    description="Int timestamp with blake_256",
    timestamp_input=timestamp_input,
)

timestamp = getIntTimestamp()
timestamp_input = timestamp - TIMEDELTA_WITH_INT_VALUE
token = hashlib.blake2b(str(timestamp).encode()).hexdigest()
check(
    timestamp,
    token,
    description="Int timestamp with blake_512",
    timestamp_input=timestamp_input,
)

timestamp = getFloatTimestamp()
timestamp_input = timestamp + TIMEDELTA_WITH_FLOAT_VALUE
u = uuid.uuid1()
token = str(uuid1(u.node, u.clock_seq, timestamp))
check(
    timestamp,
    token,
    description="Float timestamp with uuidv1",
    timestamp_input=timestamp_input,
)

timestamp = getFloatTimestamp()
timestamp_input = timestamp + TIMEDELTA_WITH_FLOAT_VALUE
token = hashlib.blake2b(str(timestamp).encode()).hexdigest()
check(
    timestamp,
    token,
    description="Float timestamp with blake_512",
    timestamp_input=timestamp_input,
)

timestamp = getFloatTimestamp()
timestamp_input = timestamp + TIMEDELTA_WITH_FLOAT_VALUE
token = hashlib.sha1(uniqid(timestamp).encode()).hexdigest()
check(
    timestamp,
    token,
    description="Uniqid timestamp with sha1",
    timestamp_input=timestamp_input,
)

timestamp = getFloatTimestamp()
timestamp_input = timestamp - TIMEDELTA_WITH_FLOAT_VALUE
value = "%s%s%s" % ("you", str(timestamp), "2")
token = hashlib.md5(value.encode()).hexdigest()
check(
    timestamp,
    token,
    description="Check prefix/suffix from float value with md5",
    timestamp_input=timestamp_input,
    prefixes=["hello", "you"],
    suffixes=["1", "2"],
)

date = datetime.datetime.now(tz=datetime.timezone.utc)
timestamp = Decimal.from_float(date.timestamp())
timestamp_input = timestamp - TIMEDELTA_WITH_FLOAT_VALUE
token = hashlib.md5(date.isoformat().encode()).hexdigest()
check(
    timestamp,
    token,
    description="Datetime with md5",
    timestamp_input=timestamp_input,
    date_format_of_token="%Y-%m-%dT%H:%M:%S.%f+00:00",
)

print("[+] Check not working")

timestamp = getFloatTimestamp()
timestamp_input = timestamp + TIMEDELTA_WITH_FLOAT_VALUE
token = hashlib.sha3_256("fusbevuisbevuiesbvuiesbvsie".encode()).hexdigest()
check(
    timestamp,
    token,
    description="Unknown token with sha3_256",
    timestamp_input=timestamp_input,
)
