# -*- coding: utf-8 -*-
# Author: Aethlios <contact@aeth.cc>

from typing import Any, Optional
from functools import partial
from decimal import Decimal, getcontext
from math import floor

from resetTolkien.format import Formatter, FormatType, EncodingType, HashingType
from resetTolkien.utils import (
    NotAHash,
    GeneratorLen,
    AlternativeGen,
    TimestampGenerator,
    TimestampHashFormat,
    TimestampFormatType,
    import_from_yaml,
    possible_date_format_of_token,
)
from resetTolkien.constants import (
    DEFAULT_TIMERANGE_FOR_INT_TIMESTAMP,
    DEFAULT_TIMERANGE_FOR_FLOAT_TIMESTAMP,
    MAX_DEPTH_LEVEL,
    DEFAULT_THREAD_NUMBER,
    DEFAULT_CONFIG_FILE,
    DEFAULT_DECIMAL_LENGTH,
    TIMESTAMP_STR_LENGTH,
)


class ResetTolkien:
    """Class to detect whether a value is based on a timestamp
    and generate tokens with the correct formatting."""

    def __init__(
        self,
        token: Optional[str] = None,
        verbosity: int = 0,
        timestamp_hash_formats_config_file: str = DEFAULT_CONFIG_FILE,
        level: int = MAX_DEPTH_LEVEL,
        decimal_length: int = DEFAULT_DECIMAL_LENGTH,
        int_range_limit: int = DEFAULT_TIMERANGE_FOR_INT_TIMESTAMP,
        float_range_limit: int = DEFAULT_TIMERANGE_FOR_FLOAT_TIMESTAMP,
        prefixes: Optional[list[str]] = None,
        suffixes: Optional[list[str]] = None,
        hashes: Optional[list[str]] = None,
        alternative_tokens: Optional[list[str]] = None,
        timezone: int = 0,
        date_format_of_token: Optional[str] = None,
        formats: Optional[list[str]] = None,
        progress_active: bool = False,
    ) -> None:
        """Initialization function of ResetTolkien."""

        self.formatter = Formatter()
        self.token = token
        self.decimal_length = (
            decimal_length if decimal_length else DEFAULT_DECIMAL_LENGTH
        )
        getcontext().prec = TIMESTAMP_STR_LENGTH + self.decimal_length
        self.int_range_limit = (
            int_range_limit * 2
            if int_range_limit
            else DEFAULT_TIMERANGE_FOR_INT_TIMESTAMP * 2
        )
        self.float_range_limit = (
            float_range_limit * 2 * 10**self.decimal_length
            if float_range_limit
            else DEFAULT_TIMERANGE_FOR_FLOAT_TIMESTAMP * 2 * 10**self.decimal_length
        )
        self.prefixes: list[str] = [] if not prefixes else prefixes.copy()
        self.suffixes: list[str] = [] if not suffixes else suffixes.copy()
        self.hashes: list[str] = []
        if hashes:
            for h in hashes:
                if not h in self.formatter.allHashing():
                    raise ValueError(f"Unknown hash : {h}")
            self.hashes = hashes.copy()
        self.alternative_tokens: list[str] = (
            [] if not alternative_tokens else alternative_tokens.copy()
        )
        self.timezone = timezone
        self.date_format_of_token = date_format_of_token
        self.formats = []
        if formats:
            self.formats = self.formatter.import_formats(formats)
        self.verbosity = verbosity
        self.level = level
        self.timestamp_hash_formats_config_file = timestamp_hash_formats_config_file
        self.timestamp_hash_formats = self.getTimestampsHashFormatsByLevel(
            level, timestamp_hash_formats_config_file
        )
        self.progress_active = progress_active
        self.timestamp_format_types = [
            TimestampFormatType(
                int, (lambda t: int(Decimal(str(t)))), self.int_range_limit
            ),
            TimestampFormatType(
                float, (lambda t: Decimal(str(t))), self.float_range_limit
            ),
        ]

    def getTimestampsHashFormatsByLevel(
        self, level: int, timestamp_hash_formats_config_file: str
    ) -> list[TimestampHashFormat]:
        """Class function to get depth level of timestamp hash search."""

        if level > MAX_DEPTH_LEVEL or level < 1:
            raise ValueError

        if self.verbosity >= 1:
            print(f"Selected level : {level}")

        timestamp_hash_formats = import_from_yaml(
            timestamp_hash_formats_config_file,
            level,
            self.formatter.allEncoding(),
        )

        if self.verbosity >= 1:
            print(f"Selected Timestamp hash formats : {timestamp_hash_formats}")

        return timestamp_hash_formats

    def detectOneEncoding(
        self, token: str, format: EncodingType, **kwargs: Any
    ) -> tuple[Optional[str], Optional[EncodingType]]:
        """Determines whether a value has been encoded
        using an encoding function provided as input."""

        try:
            c = format(token, encode=False, **kwargs)
            return c, format
        except Exception as e:
            if self.verbosity >= 2:
                print(f"Exception with {format.__name__} : {e}")
            return None, None

    def detectHash(
        self,
        hashes: dict[str, HashingType],
        formats: list[FormatType],
        timestamp: Decimal | int,
        token: str,
        multithreading: Optional[int] = None,
    ) -> Optional[
        tuple[tuple[str, Optional[str], Optional[str]], list[FormatType], bool]
    ]:
        """Determines which hash function matches the format of an input token."""
        available_hashes = list(hashes.values())
        (new_token, prefix, suffix, hash, timestamp_hash_format) = (
            None,
            None,
            None,
            None,
            None,
        )
        for timestamp_format_type in self.timestamp_format_types:
            if self.verbosity >= 1:
                print(f"Try with {timestamp_format_type.timestamp_type}")
            possibleTokens = GeneratorLen(
                self.generate_possible_token(
                    timestamp_format_type.timestamp_type_func(str(timestamp)),
                    range_limit=timestamp_format_type.range_limit,
                ),
                timestamp_format_type.range_limit,
            )
            timestamp_hash_formats = [
                e
                for e in self.timestamp_hash_formats
                if e.timestamp_type == timestamp_format_type.timestamp_type
            ]
            try:
                if multithreading and multithreading > 1:
                    (new_token, prefix, suffix, hash, timestamp_hash_format) = (
                        self.formatter.multithread_decrypt(
                            token,
                            possibleTokens,
                            timestamp_hash_formats,
                            available_hashes,
                            self.prefixes,
                            self.suffixes,
                            self.timezone,
                            self.date_format_of_token,
                            self.alternative_tokens,
                            nb_threads=multithreading,
                            progress_active=self.progress_active,
                        )
                    )
                else:
                    (new_token, prefix, suffix, hash, timestamp_hash_format) = (
                        self.formatter.native_decrypt(
                            token,
                            possibleTokens,
                            self.timestamp_hash_formats,
                            available_hashes,
                            self.prefixes,
                            self.suffixes,
                            self.timezone,
                            self.date_format_of_token,
                            self.alternative_tokens,
                            progress_active=self.progress_active,
                        )
                    )
            except NotAHash as e:
                if self.verbosity >= 2:
                    print(f"Exception : {e}")
            if new_token and hash:
                new_formats: list[FormatType] = formats.copy()
                new_formats.append(hash)
                if new_token[1] or new_token[2]:
                    new_formats.append(
                        partial(
                            self.formatter.prefix_suffix,
                            prefix=prefix,
                        )
                    )
                    new_formats.append(
                        partial(
                            self.formatter.prefix_suffix,
                            suffix=suffix,
                        )
                    )
                if timestamp_hash_format:
                    new_formats += timestamp_hash_format.formats_output
                return ((new_token, prefix, suffix), new_formats, True)
        return None

    def _detectFormat(
        self,
        token: str,
        multithreading: int,
        formats: Optional[list[FormatType]] = None,
        timestamp: Optional[Decimal | int] = None,
    ) -> list[tuple[tuple[str, Optional[str], Optional[str]], list[FormatType], bool]]:
        """Recursive function - Determines a function
        corresponding to the format of an input token."""

        formats = [] if formats is None else formats

        numbers = self.formatter.getNumbers(token)
        if self.verbosity >= 1 and len(numbers) > 0:
            print(f"Integer value detected : {numbers}")
        possibleTimestamp = self.formatter.searchTimestamps(numbers)
        if len(possibleTimestamp) > 0:
            print(
                f'Possible timestamp detected! {[str(t) for t in possibleTimestamp]} from "{token}"'
            )

        if self.formatter.isLiteralIntegerOrFloat(token):
            new_token, _ = self.detectOneEncoding(token, self.formatter.timestamp)
            if new_token:
                if self.verbosity >= 1:
                    print(
                        f"Format detected and stored : {self.formatter.export_formats(formats)}"
                    )
                self.formats = formats
                return [((token, None, None), formats, True)]

        if self.formatter.isDatetime(token):
            if self.verbosity >= 1:
                print(f"Datetime value detected : {token}")
            new_token, format = self.detectOneEncoding(
                token,
                self.formatter.datetime,
                timezone=self.timezone,
                date_format_of_token=self.date_format_of_token,
            )
            if new_token and format:
                if not self.date_format_of_token:
                    possible_format = possible_date_format_of_token(token)
                    print(
                        f'Please enter a datetime format for this input: "{token}" (possible format : --date-format-of-token="{possible_format}")'
                    )
                    exit()
                formats.append(format)
                if self.verbosity >= 1:
                    print(
                        f"Format detected and stored : {self.formatter.export_formats(formats)}"
                    )
                self.formats = formats
                return [((token, None, None), formats, True)]

        results: list[
            tuple[tuple[str, Optional[str], Optional[str]], list[FormatType], bool]
        ] = []
        encodings = self.formatter.availableEncoding()
        for e in encodings:
            encoding = encodings[e]
            if len(formats) < 3 or formats[-3:] != [encoding, encoding, encoding]:
                if self.verbosity >= 2:
                    print(f"Check encoding with {e}")
                new_token, format = self.detectOneEncoding(
                    token, encoding, init_token=self.token
                )
                if new_token and format:
                    if self.verbosity >= 1:
                        print(f"Possible encoding format found : {format.__name__}")
                    new_formats = formats.copy()
                    new_formats.append(format)
                    results += self._detectFormat(
                        new_token,
                        multithreading,
                        formats=new_formats,
                        timestamp=timestamp,
                    )

        if timestamp:
            hashes = self.formatter.availableHashingDict(token)
            if len(hashes) > 0:
                if self.verbosity >= 1:
                    print(f"Hash format detected : {list(hashes.keys())} : {token}")

                if token.lower() != token:
                    if self.verbosity >= 1:
                        print(
                            f"Hash with uppercase detected : {token} -> {token.lower()}"
                        )
                    token = token.lower()

                r = self.detectHash(
                    hashes,
                    formats,
                    timestamp,
                    token,
                    multithreading=multithreading,
                )
                if r:
                    results.append(r)

        return results

    def detectFormat(
        self,
        timestamp: Optional[Decimal | int] = None,
        nb_threads: int = DEFAULT_THREAD_NUMBER,
    ) -> Optional[
        list[tuple[tuple[str, Optional[str], Optional[str]], list[FormatType], bool]]
    ]:
        """Non-recursive function - Determines a list of functions
        corresponding to the format of an input token."""

        if not self.token:
            return None
        return self._detectFormat(self.token, nb_threads, timestamp=timestamp)

    def encode(
        self,
        value: str,
        token: Optional[str] = None,
        formats: list[FormatType] | None = None,
    ) -> str:
        """Converts a value from an input list of format functions."""

        if formats == None:
            formats = self.formats

        if token == None:
            token = self.token

        return self.formatter.encode(
            value, token, formats, self.timezone, self.date_format_of_token
        )

    def generate_possible_token(
        self,
        init: Decimal | int,
        range_limit: int | None = None,
        formats: list[FormatType] | None = None,
        prefix: str | None = None,
        suffix: str | None = None,
    ) -> TimestampGenerator:
        """Returns a list of tokens generated from timestamps
        according to the value provided as input and
        the token generation format, taking into account
        the type of value provided."""

        if isinstance(init, int):
            if not range_limit:
                range_limit = self.int_range_limit + 1
        else:
            if not range_limit:
                range_limit = self.float_range_limit + 1

        for i in AlternativeGen(range_limit):  # type: ignore
            timestamp = str(init + i)
            if isinstance(init, Decimal):
                timestamp = str(
                    Decimal(init + Decimal(i / 10**self.decimal_length)).normalize()
                )
            if prefix:
                timestamp = f"{prefix}{timestamp}"
            if suffix:
                timestamp = f"{timestamp}{suffix}"
            if formats:
                yield self.encode(timestamp, formats=formats), timestamp
                for alternative_token in self.alternative_tokens:
                    yield self.encode(
                        timestamp, token=alternative_token, formats=formats
                    ), timestamp
            else:
                yield timestamp, timestamp

    def generate_bounded_possible_token(
        self,
        begin: Decimal | int,
        end: Decimal | int,
        formats: list[FormatType] | None = None,
        prefix: str | None = None,
        suffix: str | None = None,
    ) -> TimestampGenerator:
        """Returns a list of tokens generated from timestamps
        contained in a temporal range provided as input and
        the token generation format, taking into account
        the type of value provided.
        """

        if isinstance(begin, int) and isinstance(end, int):
            limit = end - begin + 1
            begin = end - floor((end - begin) / 2)
            return self.generate_possible_token(
                begin, prefix=prefix, suffix=suffix, range_limit=limit, formats=formats
            )
        else:
            limit = int(Decimal(end - begin) * 10**self.decimal_length) + 1
            begin = round(
                (
                    Decimal(
                        end - Decimal(floor((limit - 1) / 2) / 10**self.decimal_length)
                    )
                ),
                self.decimal_length,
            )
            return self.generate_possible_token(
                begin, prefix=prefix, suffix=suffix, range_limit=limit, formats=formats
            )
