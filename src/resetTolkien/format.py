# -*- coding: utf-8 -*-
# Author: Aethlios <tom.chambaretaud@protonmail.com>

import base64
import re
import concurrent.futures

from functools import partial
from typing import Callable, Any, Optional

import shortuuid
import uuid

from resetTolkien.utils import (
    FormatType,
    EncodingType,
    HashingType,
    HashIdentifierType,
    NotAHash,
    GeneratorLen,
    to_microsecond_timestamp,
    from_microsecond_timestamp,
    uniqid,
    deuniqid,
    detect_datetime,
    to_uuidv1,
    from_uuidv1,
    to_mongodb_objectid,
    from_mongodb_objectid,
    urlencode,
    urldecode,
    import_format_with_args,
)
from resetTolkien.constants import (
    DEFAULT_THREAD_NUMBER,
    DATE_SLASH_REGEX,
    DATE_DASH_REGEX,
    TIME_REGEX,
    MONTH_REGEX,
    PARTIAL_FUNC_NAME_REGEX,
)
from resetTolkien.hashes import Hashes


class Formatter:
    """Class for encoding, hashing and decrypting a timestamp-based value"""

    ### Utils
    def import_formats(self, formats: list[str]) -> list[FormatType]:
        """Converts a list of strings into a list of corresponding encoding and hash functions."""

        results: list[FormatType] = []
        format_funcs: dict[str, EncodingType | HashingType] = self.allFormat()

        for func_name in formats:
            if (
                "(" in func_name
                and func_name.split("(")[0] in self.allEncodingWithArgs()
            ):
                func, args = import_format_with_args(
                    func_name, self.allEncodingWithArgs()
                )
                format_func = partial(func, **args)
                results.append(format_func)
            else:
                if not func_name in format_funcs:
                    raise ValueError(f"{func_name} is not in available formats")
                results.append(format_funcs[func_name])
        return results

    def export_formats(self, formats: list[FormatType]) -> str:
        """Converts a list of encoding and hash functions into a list of strings."""

        formats_name: list[str] = []
        for format in formats:
            if isinstance(format, partial):
                elems = re.search(PARTIAL_FUNC_NAME_REGEX, str(format))
                if not elems:
                    raise ValueError(f"No partial name found : {format}")
                args = [
                    elem
                    for elem in elems.groups()[1].split(",")
                    if elem.split("=")[1] != "None"
                ]
                for arg in args:
                    name = f"{elems.groups()[0]}({arg})"
                    formats_name.append(name)
            else:
                formats_name.append(format.__name__)
        return ",".join(formats_name)

    def isLiteralIntegerOrFloat(self, token: str) -> bool:
        """Confirms that the value is numeric."""

        try:
            float(token)
            return True
        except (ValueError, OverflowError, TypeError):
            return False

    def getNumbers(self, token: str) -> list[str]:
        """Extracts numeric values from the string value."""

        matches = re.findall(r"(\d+)", str(token))
        return [match for match in matches if self.isLiteralIntegerOrFloat(match)]

    def isDatetime(self, token: str) -> bool:
        """Confirms that the value is datetime format."""

        return (
            re.search(DATE_SLASH_REGEX, token) != None
            or re.search(DATE_DASH_REGEX, token) != None
            or re.search(TIME_REGEX, token) != None
            or re.search(MONTH_REGEX, token) != None
        )

    ### Format

    def allFormat(self) -> dict[str, EncodingType | HashingType]:
        """Returns all functions."""

        formats: dict[str, EncodingType | HashingType] = {}
        formats.update(self.allEncoding())
        formats.update(self.allHashing())
        return formats

    ### Encoding

    def allEncoding(self) -> dict[str, EncodingType]:
        """Returns all encoding functions."""

        return {
            "prefix_suffix": self.prefix_suffix,
            "base32": self.base32,
            "base64": self.base64,
            "urlencode": self.urlencode,
            "hexint": self.hexint,
            "hexstr": self.hexstr,
            "uniqid": self.uniqid,
            "shortuuid": self.shortuuid,
            "uuidv1": self.uuidv1,
            "mongodb_objectid": self.mongodb_objectid,
            "datetime": self.datetime,
            "datetimeRFC2822": self.datetimeRFC2822,
        }

    def allEncodingWithArgs(self) -> dict[str, EncodingType]:
        """Returns all encoding functions with required arguments."""

        return {"prefix_suffix": self.prefix_suffix}

    def availableEncoding(self) -> dict[str, EncodingType]:
        """Returns the encoding functions available to try out."""

        return {
            "base32": self.base32,
            "base64": self.base64,
            "urlencode": self.urlencode,
            "hexint": self.hexint,
            "hexstr": self.hexstr,
            "uniqid": self.uniqid,
            "shortuuid": self.shortuuid,
            "mongodb_objectid": self.mongodb_objectid,
            "uuidv1": self.uuidv1,
        }

    ### Encoding function list

    def prefix_suffix(
        self, token: str, encode: Optional[bool] = True, **kwargs: Any
    ) -> str:
        """Adds prefix and suffix if provided to a string value."""

        if encode:
            prefix = ""
            if "prefix" in kwargs and kwargs["prefix"]:
                prefix = kwargs["prefix"]
            suffix = ""
            if "suffix" in kwargs and kwargs["suffix"]:
                suffix = kwargs["suffix"]
            return f"{prefix}{token}{suffix}"
        raise ValueError("No possible to decode with prefix_suffix function.")

    def datetime(self, token: str, encode: Optional[bool] = True, **kwargs: Any) -> str:
        """Converts from a timestamp to a date or vice versa"""

        if encode:
            timezone = kwargs["timezone"]
            date_format_of_token = kwargs["date_format_of_token"]
            return from_microsecond_timestamp(
                float(token),
                timezone=timezone,
                date_format_of_token=date_format_of_token,
            )
        return str(detect_datetime(token))

    def datetimeRFC2822(
        self, token: str, encode: Optional[bool] = True, **kwargs: Any
    ) -> str:
        """Converts from a string RFC2822 datetime to a date or vice versa"""

        if encode:
            timezone = kwargs["timezone"]
            date = from_microsecond_timestamp(
                float(token),
                timezone=timezone,
                date_format_of_token="%a, %d %b %Y %H:%M:%S %Z",
            )
            # No existing method with datetime to get the RFC2822, so we go with regex :
            # "UTC(+|-)07:00" -> "(+|-)0700"
            date = re.sub(r"UTC(.)(\d{2}):(\d{2})", r"\1\2\3", date)
            # "UTC" -> "+0000"
            date = re.sub(r"UTC$", r"+0000", date)
            return date
        return str(detect_datetime(token))

    def timestamp(
        self, token: str, encode: Optional[bool] = True, **kwargs: Any
    ) -> str:
        """Check if it's a timestamp value"""

        if encode:
            return to_microsecond_timestamp(token)
        return from_microsecond_timestamp(float(token))

    def mongodb_objectid(
        self, token: str, encode: Optional[bool] = True, **kwargs: Any
    ) -> str:
        """Converts from an PostgreSQL to a timestamp or vice versa"""

        if encode:
            init_token = kwargs["init_token"]
            return to_mongodb_objectid(token, init_token)
        return from_mongodb_objectid(token)

    def uuidv1(self, token: str, encode: Optional[bool] = True, **kwargs: Any) -> str:
        """Converts from an UUID to a timestamp or vice versa"""

        if encode:
            init_token = kwargs["init_token"]
            return to_uuidv1(token, init_token)
        return from_uuidv1(token)

    def base32(self, token: str, encode: Optional[bool] = True, **kwargs: Any) -> str:
        """Converts from a base32-encoded value to a string or vice versa"""

        if encode:
            return base64.b32encode(str(token).encode()).decode()
        return base64.b32decode(str(token).encode()).decode()

    def base64(self, token: str, encode: Optional[bool] = True, **kwargs: Any) -> str:
        """Converts from a base64-encoded value to a string or vice versa"""

        if encode:
            return base64.b64encode(str(token).encode()).decode()
        return base64.b64decode(str(token).encode()).decode()

    def urlencode(
        self, token: str, encode: Optional[bool] = True, **kwargs: Any
    ) -> str:
        """Converts from a URL-encoded value to a string or vice versa"""

        if encode:
            return urlencode(token)
        return urldecode(token)

    def shortuuid(
        self, token: str, encode: Optional[bool] = True, **kwargs: Any
    ) -> str:
        """Converts from a shortuuid value to a UUID or vice versa"""

        if encode:
            return shortuuid.encode(uuid.UUID(str(token)))
        return str(shortuuid.decode(token))

    def uniqid(self, token: str, encode: Optional[bool] = True, **kwargs: Any) -> str:
        """Converts from a uniqid value to a timestamp or vice versa"""

        if encode:
            return uniqid(float(token))
        return deuniqid(token)

    def hexint(self, token: str, encode: Optional[bool] = True, **kwargs: Any) -> str:
        """Converts from a int-hex value to a timestamp or vice versa"""

        if encode:
            return hex(int(float(token))).replace("0x", "")
        return str(int(token, 16))

    def hexstr(self, token: str, encode: Optional[bool] = True, **kwargs: Any) -> str:
        """Converts from a str-hex value to a timestamp or vice versa"""

        if encode:
            return str(token).encode().hex()
        return bytes.fromhex(str(token)).decode()

    # Hashing

    def allHashIdentifiers(self) -> dict[str, HashIdentifierType]:
        """Returns all hash identifier functions."""

        return {
            "md5": self.is_md5,
            "sha1": self.is_sha1,
            "sha224": self.is_sha224,
            "sha256": self.is_sha256,
            "sha384": self.is_sha384,
            "sha512": self.is_sha512,
            "sha3_224": self.is_sha3_224,
            "sha3_256": self.is_sha3_256,
            "sha3_384": self.is_sha3_384,
            "sha3_512": self.is_sha3_512,
            "blake_256": self.is_blake_256,
            "blake_512": self.is_blake_512,
        }

    def allHashing(self) -> dict[str, HashingType]:
        """Returns all hash functions in dict with name as key."""

        return {
            "md5": self.md5,
            "sha1": self.sha1,
            "sha224": self.sha224,
            "sha256": self.sha256,
            "sha384": self.sha384,
            "sha512": self.sha512,
            "sha3_224": self.sha3_224,
            "sha3_256": self.sha3_256,
            "sha3_384": self.sha3_384,
            "sha3_512": self.sha3_512,
            "blake_256": self.blake_256,
            "blake_512": self.blake_512,
        }

    def intHashing(self) -> dict[str, HashingType]:
        """Returns all hash functions for a integer timestamp."""

        return self.allHashing()

    def floatHashing(self) -> dict[str, HashingType]:
        """Returns all hash functions for a integer timestamp."""

        return self.allHashing()

    def availableHashingDict(
        self, token: Optional[str] = None
    ) -> dict[str, HashingType]:
        """Returns the hash functions available by identifying the input hash."""

        if not token:
            return self.allHashing()
        hashes: dict[str, HashingType] = {}
        identifiers = self.allHashIdentifiers()
        for h in identifiers:
            is_hash = identifiers[h]
            hash = is_hash(str(token))
            if hash != None:
                hashes[h] = hash
        return hashes

    def hashing_with_prefix(
        self,
        hash_func: Callable[[str], str],
        prefixes: list[str],
        suffixes: list[str],
        token: str,
        values: tuple[str, str],
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """Returns timestamp and encoded value if hashed value from various provided prefixes and suffixes"""

        encoded_timestamp, timestamp = values
        if token == hash_func(encoded_timestamp):
            return timestamp, None, None
        for prefix in prefixes:
            value = "%s%s" % (prefix, encoded_timestamp)
            if token == hash_func(value):
                return timestamp, prefix, None
        for suffix in suffixes:
            value = "%s%s" % (encoded_timestamp, suffix)
            if token == hash_func(value):
                return timestamp, None, suffix
        for prefix in prefixes:
            for suffix in suffixes:
                value = "%s%s%s" % (prefix, encoded_timestamp, suffix)
                if token == hash_func(value):
                    return timestamp, prefix, suffix
        return None, None, None

    def _multithread_decrypt(
        self,
        token: str,
        possibleTokens: GeneratorLen,
        hash_func: Callable[[str], str],
        prefixes: list[str],
        suffixes: list[str],
        nb_threads: int = DEFAULT_THREAD_NUMBER,
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """Decrypts a timestamp-based value by using multithreading"""

        data = None, None, None
        chunksize = round(pow(len(possibleTokens) / nb_threads, 0.5))
        with concurrent.futures.ProcessPoolExecutor(max_workers=nb_threads) as executor:
            for timestamp, prefix, suffix in executor.map(
                partial(self.hashing_with_prefix, hash_func, prefixes, suffixes, token),
                possibleTokens,
                chunksize=chunksize,
            ):
                if timestamp:
                    data = timestamp, prefix, suffix
                    break
        return data

    def _native_decrypt(
        self,
        token: str,
        possibleTokens: GeneratorLen,
        hash_func: Callable[[str], str],
        prefixes: list[str],
        suffixes: list[str],
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """Decrypts a timestamp-based value by using naive method"""

        for value, timestamp in possibleTokens:
            timestamp, prefix, suffix = self.hashing_with_prefix(
                hash_func, prefixes, suffixes, token, (value, timestamp)
            )
            if timestamp:
                return timestamp, prefix, suffix
        raise NotAHash(f"It is not a hash")

    def is_hash(self, hash: str, hash_func: HashingType) -> Optional[HashingType]:
        """Generic function to detect a hash value"""

        if (
            hash.isdigit() == False
            and hash.isalpha() == False
            and hash.isalnum() == True
            and len(hash) == len(hash_func("FIXED_VALUE", encode=True))
        ):
            return hash_func
        return None

    def hash(
        self,
        hash_func: Callable[[str], str],
        token: str,
        possibleTokens: Optional[GeneratorLen] = None,
        encode: Optional[bool] = True,
        multithreading: Optional[int] = None,
        **kwargs: Any,
    ) -> str | tuple[Optional[str], Optional[str], Optional[str]]:
        """Generic function for hashing or decrypting a value based on a timestamp."""

        if encode:
            return hash_func(token)
        if not possibleTokens:
            raise ValueError("No possibleTokens")
        prefixes: list[str] = (
            kwargs["prefixes"]
            if "prefixes" in kwargs and isinstance(kwargs["prefixes"], list)
            else []
        )
        suffixes: list[str] = (
            kwargs["suffixes"]
            if "suffixes" in kwargs and isinstance(kwargs["suffixes"], list)
            else []
        )
        if multithreading and multithreading > 1:
            return self._multithread_decrypt(
                token,
                possibleTokens,
                hash_func,
                prefixes,
                suffixes,
                nb_threads=multithreading,
            )
        return self._native_decrypt(
            token,
            possibleTokens,
            hash_func,
            prefixes,
            suffixes,
        )

    ### Hash function list

    def is_md5(self, hash: str) -> Optional[HashingType]:
        return self.is_hash(hash, self.md5)

    def md5(
        self,
        token: str,
        possibleTokens: Optional[GeneratorLen] = None,
        encode: Optional[bool] = True,
        multithreading: Optional[int] = None,
        **kwargs: Any,
    ) -> str | tuple[Optional[str], Optional[str], Optional[str]]:
        return self.hash(
            Hashes.md5,
            token,
            possibleTokens=possibleTokens,
            encode=encode,
            multithreading=multithreading,
            **kwargs,
        )

    def is_sha1(self, hash: str) -> Optional[HashingType]:
        return self.is_hash(hash, self.sha1)

    def sha1(
        self,
        token: str,
        possibleTokens: Optional[GeneratorLen] = None,
        encode: Optional[bool] = True,
        multithreading: Optional[int] = None,
        **kwargs: Any,
    ) -> str | tuple[Optional[str], Optional[str], Optional[str]]:
        return self.hash(
            Hashes.sha1,
            token,
            possibleTokens=possibleTokens,
            encode=encode,
            multithreading=multithreading,
            **kwargs,
        )

    def is_sha224(self, hash: str) -> Optional[HashingType]:
        return self.is_hash(hash, self.sha224)

    def sha224(
        self,
        token: str,
        possibleTokens: Optional[GeneratorLen] = None,
        encode: Optional[bool] = True,
        multithreading: Optional[int] = None,
        **kwargs: Any,
    ) -> str | tuple[Optional[str], Optional[str], Optional[str]]:
        return self.hash(
            Hashes.sha224,
            token,
            possibleTokens=possibleTokens,
            encode=encode,
            multithreading=multithreading,
            **kwargs,
        )

    def is_sha256(self, hash: str) -> Optional[HashingType]:
        return self.is_hash(hash, self.sha256)

    def sha256(
        self,
        token: str,
        possibleTokens: Optional[GeneratorLen] = None,
        encode: Optional[bool] = True,
        multithreading: Optional[int] = None,
        **kwargs: Any,
    ) -> str | tuple[Optional[str], Optional[str], Optional[str]]:
        return self.hash(
            Hashes.sha256,
            token,
            possibleTokens=possibleTokens,
            encode=encode,
            multithreading=multithreading,
            **kwargs,
        )

    def is_sha384(self, hash: str) -> Optional[HashingType]:
        return self.is_hash(hash, self.sha384)

    def sha384(
        self,
        token: str,
        possibleTokens: Optional[GeneratorLen] = None,
        encode: Optional[bool] = True,
        multithreading: Optional[int] = None,
        **kwargs: Any,
    ) -> str | tuple[Optional[str], Optional[str], Optional[str]]:
        return self.hash(
            Hashes.sha384,
            token,
            possibleTokens=possibleTokens,
            encode=encode,
            multithreading=multithreading,
            **kwargs,
        )

    def is_sha512(self, hash: str) -> Optional[HashingType]:
        return self.is_hash(hash, self.sha512)

    def sha512(
        self,
        token: str,
        possibleTokens: Optional[GeneratorLen] = None,
        encode: Optional[bool] = True,
        multithreading: Optional[int] = None,
        **kwargs: Any,
    ) -> str | tuple[Optional[str], Optional[str], Optional[str]]:
        return self.hash(
            Hashes.sha512,
            token,
            possibleTokens=possibleTokens,
            encode=encode,
            multithreading=multithreading,
            **kwargs,
        )

    def is_sha3_224(self, hash: str) -> Optional[HashingType]:
        return self.is_hash(hash, self.sha3_224)

    def sha3_224(
        self,
        token: str,
        possibleTokens: Optional[GeneratorLen] = None,
        encode: Optional[bool] = True,
        multithreading: Optional[int] = None,
        **kwargs: Any,
    ) -> str | tuple[Optional[str], Optional[str], Optional[str]]:
        return self.hash(
            Hashes.sha3_224,
            token,
            possibleTokens=possibleTokens,
            encode=encode,
            multithreading=multithreading,
            **kwargs,
        )

    def is_sha3_256(self, hash: str) -> Optional[HashingType]:
        return self.is_hash(hash, self.sha3_256)

    def sha3_256(
        self,
        token: str,
        possibleTokens: Optional[GeneratorLen] = None,
        encode: Optional[bool] = True,
        multithreading: Optional[int] = None,
        **kwargs: Any,
    ) -> str | tuple[Optional[str], Optional[str], Optional[str]]:
        return self.hash(
            Hashes.sha3_256,
            token,
            possibleTokens=possibleTokens,
            encode=encode,
            multithreading=multithreading,
            **kwargs,
        )

    def is_sha3_384(self, hash: str) -> Optional[HashingType]:
        return self.is_hash(hash, self.sha3_384)

    def sha3_384(
        self,
        token: str,
        possibleTokens: Optional[GeneratorLen] = None,
        encode: Optional[bool] = True,
        multithreading: Optional[int] = None,
        **kwargs: Any,
    ) -> str | tuple[Optional[str], Optional[str], Optional[str]]:
        return self.hash(
            Hashes.sha3_384,
            token,
            possibleTokens=possibleTokens,
            encode=encode,
            multithreading=multithreading,
            **kwargs,
        )

    def is_sha3_512(self, hash: str) -> Optional[HashingType]:
        return self.is_hash(hash, self.sha3_512)

    def sha3_512(
        self,
        token: str,
        possibleTokens: Optional[GeneratorLen] = None,
        encode: Optional[bool] = True,
        multithreading: Optional[int] = None,
        **kwargs: Any,
    ) -> str | tuple[Optional[str], Optional[str], Optional[str]]:
        return self.hash(
            Hashes.sha3_512,
            token,
            possibleTokens=possibleTokens,
            encode=encode,
            multithreading=multithreading,
            **kwargs,
        )

    def is_blake_256(self, hash: str) -> Optional[HashingType]:
        return self.is_hash(hash, self.blake_256)

    def blake_256(
        self,
        token: str,
        possibleTokens: Optional[GeneratorLen] = None,
        encode: Optional[bool] = True,
        multithreading: Optional[int] = None,
        **kwargs: Any,
    ) -> str | tuple[Optional[str], Optional[str], Optional[str]]:
        return self.hash(
            Hashes.blake_256,
            token,
            possibleTokens=possibleTokens,
            encode=encode,
            multithreading=multithreading,
            **kwargs,
        )

    def is_blake_512(self, hash: str) -> Optional[HashingType]:
        return self.is_hash(hash, self.blake_512)

    def blake_512(
        self,
        token: str,
        possibleTokens: Optional[GeneratorLen] = None,
        encode: Optional[bool] = True,
        multithreading: Optional[int] = None,
        **kwargs: Any,
    ) -> str | tuple[Optional[str], Optional[str], Optional[str]]:
        return self.hash(
            Hashes.blake_512,
            token,
            possibleTokens=possibleTokens,
            encode=encode,
            multithreading=multithreading,
            **kwargs,
        )
