# -*- coding: utf-8 -*-
# Author: Aethlios <tom.chambaretaud@protonmail.com>

from typing import Callable, Any, Optional
from functools import partial
from decimal import Decimal
from math import floor

from resetTolkien.format import Formatter, FormatType, EncodingType, HashingType
from resetTolkien.utils import (
    NotAHash,
    GeneratorLen,
    AlternativeGen,
    TimestampGenerator,
    TimestampHashFormat,
    import_from_yaml,
    possible_date_format_of_token,
    CustomFloat,
)
from resetTolkien.constants import (
    DEFAULT_TIMERANGE_FOR_INT_TIMESTAMP,
    DEFAULT_TIMERANGE_FOR_FLOAT_TIMESTAMP,
    MAX_DEPTH_LEVEL,
    DEFAULT_THREAD_NUMBER,
    DEFAULT_CONFIG_FILE,
    DEFAULT_DECIMAL_LENGTH,
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
        timezone: int = 0,
        date_format_of_token: Optional[str] = None,
        formats: Optional[list[str]] = None,
    ) -> None:
        """Initialization function of ResetTolkien."""

        self.formatter = Formatter()
        self.token = token
        self.decimal_length = (
            decimal_length if decimal_length else DEFAULT_DECIMAL_LENGTH
        )
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
            self.int_range_limit,
            self.float_range_limit,
            self.formatter.intHashing(),
            self.formatter.floatHashing(),
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

    def detectOneHash(
        self,
        token: str,
        hash: HashingType,
        possibleTokens: GeneratorLen,
        multithreading: Optional[int] = None,
    ) -> tuple[
        tuple[Optional[str], Optional[str], Optional[str]], Optional[HashingType]
    ]:
        """Determines whether a value has been hashed
        using an hash function provided as input."""

        try:
            c = hash(
                token,
                possibleTokens,
                encode=False,
                multithreading=multithreading,
                prefixes=self.prefixes,
                suffixes=self.suffixes,
            )
            if isinstance(c, tuple):
                return c, hash
            else:
                raise ValueError("The token has not been decoded but encoded")
        except NotAHash as e:
            if self.verbosity >= 2:
                print(f"Exception with {hash.__name__} : {e}")
            return (None, None, None), None

    def detectHash(
        self,
        hashes: dict[str, HashingType],
        hashes_by_type: dict[str, HashingType],
        formats: list[FormatType],
        formats_output: list[FormatType],
        timestamp: float,
        token: str,
        timestamp_type_func: Callable[[str], Any],
        range_limit: int,
        multithreading: Optional[int] = None,
    ) -> Optional[
        tuple[tuple[str, Optional[str], Optional[str]], list[FormatType], bool]
    ]:
        """Determines which hash function matches the format of an input token."""

        for h in hashes:
            if h in hashes_by_type and (len(self.hashes) == 0 or h in self.hashes):
                hash = hashes[h]
                possibleTokens = GeneratorLen(
                    self.generate_possible_token(
                        timestamp_type_func(str(timestamp)),
                        range_limit=range_limit,
                        formats=formats_output,
                    ),
                    range_limit,
                )
                (new_token, prefix, suffix), format = self.detectOneHash(
                    token, hash, possibleTokens, multithreading=multithreading
                )
                if new_token and format:
                    if self.verbosity >= 1:
                        print(f"Hash found! : {h}")
                    new_formats: list[FormatType] = formats.copy()
                    new_formats.append(format)
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
                    new_formats += formats_output
                    return ((new_token, prefix, suffix), new_formats, True)
        return None

    def _detectFormat(
        self,
        token: str,
        multithreading: int,
        formats: Optional[list[FormatType]] = None,
        timestamp: Optional[float] = None,
    ) -> list[tuple[tuple[str, Optional[str], Optional[str]], list[FormatType], bool]]:
        """Recursive function - Determines a function
        corresponding to the format of an input token."""

        formats = [] if formats is None else formats

        numbers = self.formatter.getNumbers(token)
        if self.verbosity >= 1 and len(numbers) > 0:
            print(f"Integer value detected : {numbers}")
        possibleTimestamp = self.formatter.searchTimestamps(numbers)
        if len(possibleTimestamp) > 0:
            print(f"Possible timestamp detected! {possibleTimestamp} from \"{token}\"")

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

                for timestampFormat in self.timestamp_hash_formats:
                    if self.verbosity >= 1:
                        print(
                            f"Check hash with {timestampFormat.description} ({timestampFormat.range_limit} tokens)"
                        )

                    r = self.detectHash(
                        hashes,
                        timestampFormat.hashes_by_type,
                        formats,
                        timestampFormat.formats_output,
                        timestamp,
                        token,
                        timestampFormat.timestamp_type_func,
                        timestampFormat.range_limit,
                        multithreading=multithreading,
                    )
                    if r:
                        results.append(r)
                        break

        return results

    def detectFormat(
        self,
        timestamp: Optional[float] = None,
        nb_threads: int = DEFAULT_THREAD_NUMBER,
    ) -> Optional[
        list[tuple[tuple[str, Optional[str], Optional[str]], list[FormatType], bool]]
    ]:
        """Non-recursive function - Determines a list of functions
        corresponding to the format of an input token."""

        if not self.token:
            return None
        return self._detectFormat(self.token, nb_threads, timestamp=timestamp)

    def encode(self, value: str, formats: list[FormatType] | None = None) -> str:
        """Converts a value from an input list of format functions."""

        if formats == None:
            formats = self.formats

        for format in formats[::-1]:
            token = format(
                value,
                encode=True,
                timezone=self.timezone,
                date_format_of_token=self.date_format_of_token,
                init_token=self.token,
            )
            if isinstance(token, str):
                value = token
            else:
                raise ValueError("The token has not been encoded but decoded")

        return value

    def generate_possible_token(
        self,
        init: float,
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
                range_limit = self.int_range_limit
        else:
            if not range_limit:
                range_limit = self.float_range_limit

        for i in AlternativeGen(range_limit):  # type: ignore
            timestamp = str(init + i)
            if not isinstance(init, int):
                t = CustomFloat(init, self.decimal_length)
                t.value = t.value + i
                timestamp = str(t)
            if prefix:
                timestamp = f"{prefix}{timestamp}"
            if suffix:
                timestamp = f"{timestamp}{suffix}"
            encoded_timestamp = self.encode(timestamp, formats=formats)
            yield encoded_timestamp, timestamp

    def generate_bounded_possible_token(
        self,
        begin: float | int,
        end: float | int,
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
            limit = (
                int(
                    round(float(Decimal(end) - Decimal(begin)), self.decimal_length)
                    * 10**self.decimal_length
                )
                + 1
            )
            begin = round(
                (
                    float(
                        Decimal(end)
                        - Decimal(floor((limit - 1) / 2) / 10**self.decimal_length)
                    )
                ),
                self.decimal_length,
            )
            return self.generate_possible_token(
                begin, prefix=prefix, suffix=suffix, range_limit=limit, formats=formats
            )
