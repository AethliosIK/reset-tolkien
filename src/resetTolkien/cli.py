# -*- coding: utf-8 -*-
# Author: Aethlios <contact@aeth.cc>

import argparse
import datetime
from decimal import Decimal

from resetTolkien.resetTolkien import ResetTolkien
from resetTolkien import version
from resetTolkien.format import Formatter
from resetTolkien.utils import SplitArgs, SERVER_DATE_FORMAT, server_date_example
from resetTolkien.constants import (
    OUTPUT_STRINGS,
    PROG_DESCRIPTION,
    DEFAULT_THREAD_NUMBER,
    MIN_DEPTH_LEVEL,
    MAX_DEPTH_LEVEL,
    DEFAULT_VERBOSITY_LEVEL,
    MAX_VERBOSITY_LEVEL,
    DEFAULT_DEPTH_LEVEL,
    DEFAULT_DECIMAL_LENGTH,
    DEFAULT_TIMERANGE_FOR_INT_TIMESTAMP,
    DEFAULT_TIMERANGE_FOR_FLOAT_TIMESTAMP,
    DEFAULT_CONFIG_FILE,
)

# PARENT

parent_parser = argparse.ArgumentParser(add_help=False)
parent_parser.add_argument(
    "-r",
    "--roleplay",
    help="Not recommended if you don't have anything else to do",
    action="store_true",
)
parent_parser.add_argument(
    "-v",
    "--verbosity",
    help=f"Verbosity level (default: {DEFAULT_VERBOSITY_LEVEL})",
    type=int,
    choices=range(DEFAULT_VERBOSITY_LEVEL, MAX_VERBOSITY_LEVEL + 1),
    default=DEFAULT_VERBOSITY_LEVEL,
)
parent_parser.add_argument(
    "-c",
    "--config",
    help=f"Config file to set TimestampHashFormat (default: {DEFAULT_CONFIG_FILE})",
    type=str,
    default=DEFAULT_CONFIG_FILE,
)
parent_parser.add_argument(
    "--threads",
    help=f"Define the number of parallelized tasks for the decryption attack on the hash. (default: {DEFAULT_THREAD_NUMBER})",
    type=int,
    default=DEFAULT_THREAD_NUMBER,
)
parent_parser.add_argument(
    "--date-format-of-token",
    help="Date format for the token - please set it if you have found a date as input.",
)
parent_parser.add_argument(
    "--only-int-timestamp",
    help="Only use integer timestamp. (default: False)",
    action="store_true",
)
parent_parser.add_argument(
    "--decimal-length",
    help=f"Length of the float timestamp (default: {DEFAULT_DECIMAL_LENGTH})",
    type=int,
)
parent_parser.add_argument(
    "--int-timestamp-range",
    help=f"Time range over which the int timestamp will be tested before and after the input value (default: {DEFAULT_TIMERANGE_FOR_INT_TIMESTAMP}s)",
    type=int,
)
parent_parser.add_argument(
    "--float-timestamp-range",
    help=f"Time range over which the float timestamp will be tested before and after the input value (default: {DEFAULT_TIMERANGE_FOR_FLOAT_TIMESTAMP}s)",
    type=int,
)
parent_parser.add_argument(
    "--timezone",
    help=f"Timezone of the application for datetime value (default: 0)",
    type=int,
    default=0,
)
parent_parser.add_argument(
    "--progress",
    help="Show a progress bar. (default: True)",
    action="store_true",
    default=True,
)

# MAIN

main_parser = argparse.ArgumentParser(description=PROG_DESCRIPTION)
action_subparser = main_parser.add_subparsers(title="action", dest="action")

main_parser.add_argument(
    "-v", "--version", help="Print tool version", action="store_true"
)

# DETECT

detect_parser = action_subparser.add_parser(
    "detect", help="Detect the format of reset token", parents=[parent_parser]
)
detect_parser.add_argument("token", help="The token given as input.")
detect_parser.add_argument(
    "-l",
    "--level",
    help=f"Level of search depth (default: {DEFAULT_DEPTH_LEVEL})",
    type=int,
    choices=range(MIN_DEPTH_LEVEL, MAX_DEPTH_LEVEL + 1),
    default=DEFAULT_DEPTH_LEVEL,
)
detect_parser.add_argument(
    "-t", "--timestamp", help="The timestamp of the reset request", type=Decimal
)
detect_parser.add_argument(
    "-d",
    "--datetime",
    help=f"The datetime of the reset request",
    type=str,
)
detect_parser.add_argument(
    "--datetime-format",
    help=f'The input datetime format (default: server date format like "{server_date_example}")',
    default=SERVER_DATE_FORMAT,
)
detect_parser.add_argument(
    "--prefixes",
    action=SplitArgs,
    help="List of possible values for the prefix concatenated with the timestamp. Format: prefix1,prefix2",
    default=[],
)
detect_parser.add_argument(
    "--suffixes",
    action=SplitArgs,
    help="List of possible values for the suffix concatenated with the timestamp. Format: suffix1,suffix2",
    default=[],
)
detect_parser.add_argument(
    "--hashes",
    action=SplitArgs,
    help="List of possible hashes to try to detect the format. Format: hash1,hash2 (default: all identified hash)",
    default=[],
)
detect_parser.add_argument(
    "--alternative-tokens",
    action=SplitArgs,
    help="List of possible tokens to try to detect the format with different static data. Format: token1,token2",
    default=[],
)


# BRUTEFORCE

bruteforce_parser = action_subparser.add_parser(
    "bruteforce", help="Attack the reset token", parents=[parent_parser]
)
bruteforce_parser.add_argument("token", help="The token given as input.")
bruteforce_parser.add_argument(
    "-t",
    "--timestamp",
    help="The timestamp of the reset request with victim email",
    type=Decimal,
)
bruteforce_parser.add_argument(
    "-d",
    "--datetime",
    help=f"The datetime of the reset request with victim email",
    type=str,
)
bruteforce_parser.add_argument(
    "--datetime-format",
    help=f'The input datetime format (default: server date format like "{server_date_example}")',
    default=SERVER_DATE_FORMAT,
)
bruteforce_parser.add_argument(
    "--token-format",
    action=SplitArgs,
    help="The token encoding/hashing format - Format: encoding1,encoding2",
)
bruteforce_parser.add_argument(
    "--prefix",
    help="The prefix value concatenated with the timestamp.",
    type=str,
)
bruteforce_parser.add_argument(
    "--suffix",
    help="The suffix value concatenated with the timestamp.",
    type=str,
)
bruteforce_parser.add_argument(
    "-o",
    "--output",
    help="The filename of the output",
    type=argparse.FileType("w", encoding="utf-8"),
)
bruteforce_parser.add_argument(
    "--with-timestamp",
    help="Write the output with timestamp",
    action="store_true",
)
bruteforce_parser.add_argument(
    "--alternative-tokens",
    action=SplitArgs,
    help="List of possible tokens to try to detect the format with different static data. Format: token1,token2",
    default=[],
)

# SANDWICH

sandwich_parser = action_subparser.add_parser(
    "sandwich",
    help="Attack the reset token with sandwich method",
    parents=[parent_parser],
)
sandwich_parser.add_argument("token", help="The token given as input.")
sandwich_parser.add_argument(
    "-bt",
    "--begin-timestamp",
    help="The begin timestamp of the reset request with victim email",
    type=Decimal,
)
sandwich_parser.add_argument(
    "-et",
    "--end-timestamp",
    help="The end timestamp of the reset request with victim email",
    type=Decimal,
)
sandwich_parser.add_argument(
    "-bd",
    "--begin-datetime",
    help="The begin datetime of the reset request with victim email",
    type=str,
)
sandwich_parser.add_argument(
    "-ed",
    "--end-datetime",
    help="The end datetime of the reset request with victim email",
    type=str,
)
sandwich_parser.add_argument(
    "--datetime-format",
    help=f'The input datetime format (default: server date format like "{server_date_example}")',
    default=SERVER_DATE_FORMAT,
)
sandwich_parser.add_argument(
    "--token-format",
    action=SplitArgs,
    help="The token encoding/hashing format - Format: encoding1,encoding2",
)
sandwich_parser.add_argument(
    "--prefix",
    help="The prefix value concatenated with the timestamp.",
    type=str,
)
sandwich_parser.add_argument(
    "--suffix",
    help="The suffix value concatenated with the timestamp.",
    type=str,
)
sandwich_parser.add_argument(
    "-o",
    "--output",
    help="The filename of the output",
    type=argparse.FileType("w", encoding="utf-8"),
)
sandwich_parser.add_argument(
    "--with-timestamp",
    help="Write the output with timestamp",
    action="store_true",
)
sandwich_parser.add_argument(
    "--alternative-tokens",
    action=SplitArgs,
    help="List of possible tokens to try to detect the format with different static data. Format: token1,token2",
    default=[],
)


def main():
    args = main_parser.parse_args()

    if args.version:
        print(version)
        exit()

    if not args.action:
        main_parser.print_help()
        exit()

    output_version = "NOJOKE"

    if args.roleplay:
        output_version = "ROLEPLAY"

    if args.action == "detect":

        if args.datetime:
            args.timestamp = Decimal.from_float(
                datetime.datetime.strptime(args.datetime, args.datetime_format)
                .replace(tzinfo=datetime.timezone.utc)
                .timestamp()
            )

        if args.only_int_timestamp:
            args.timestamp = int(args.timestamp)

        if args.date_format_of_token and (
            len(args.prefixes) != 0 or len(args.suffixes) != 0
        ):
            print(
                "Unsupported usage of prefix/suffix with date format -> Please define this prefix/suffix in the date format."
            )
            exit()

        tolkien = ResetTolkien(
            token=args.token,
            level=args.level,
            timezone=args.timezone,
            timestamp_hash_formats_config_file=args.config,
            decimal_length=args.decimal_length,
            int_range_limit=args.int_timestamp_range,
            float_range_limit=args.float_timestamp_range,
            prefixes=args.prefixes,
            suffixes=args.suffixes,
            hashes=args.hashes,
            date_format_of_token=args.date_format_of_token,
            verbosity=args.verbosity,
            progress_active=args.progress,
            alternative_tokens=args.alternative_tokens,
        )

        results = tolkien.detectFormat(
            timestamp=args.timestamp, nb_threads=args.threads
        )
        success = False

        if results:
            for values, formats, isBasedOnTimestamp in results:
                if isBasedOnTimestamp:
                    success = True
                    print(
                        OUTPUT_STRINGS[output_version]["TIMESTAMP_FOUND"].format(
                            timestamp=values[0], prefix=values[1], suffix=values[2]
                        )
                    )
                    print(
                        OUTPUT_STRINGS[output_version]["TOKEN_FORMAT"].format(
                            formats=Formatter().export_formats(formats)
                        )
                    )
                    if int(Decimal(values[0])) == Decimal(values[0]):
                        print(OUTPUT_STRINGS[output_version]["INT_TIMESTAMP"])

        if not success:
            print(OUTPUT_STRINGS[output_version]["FAIL"])
            exit()

    if args.action == "bruteforce":

        if args.datetime:
            args.timestamp = Decimal.from_float(
                datetime.datetime.strptime(args.datetime, args.datetime_format)
                .replace(tzinfo=datetime.timezone.utc)
                .timestamp()
            )

        if not args.timestamp:
            print(f"Please provide a timestamp via -t or -d arguments.")
            exit()

        if args.only_int_timestamp:
            args.timestamp = int(args.timestamp)

        tolkien = ResetTolkien(
            token=args.token,
            timezone=args.timezone,
            timestamp_hash_formats_config_file=args.config,
            decimal_length=args.decimal_length,
            int_range_limit=args.int_timestamp_range,
            float_range_limit=args.float_timestamp_range,
            date_format_of_token=args.date_format_of_token,
            verbosity=args.verbosity,
            formats=args.token_format,
            progress_active=args.progress,
            alternative_tokens=args.alternative_tokens,
        )

        for token, value in tolkien.generate_possible_token(
            args.timestamp,
            prefix=args.prefix,
            suffix=args.suffix,
            formats=tolkien.formats,
        ):
            output = f"{token}"
            if args.with_timestamp:
                output = f"{value}:{token}"
            if args.output:
                args.output.write(f"{output}\n")
            else:
                print(f"{output}")

        if args.output:
            print(
                OUTPUT_STRINGS[output_version]["OUTPUT_IN_FILE"].format(
                    output=args.output.name
                )
            )

    if args.action == "sandwich":

        if args.begin_datetime:
            args.begin_timestamp = Decimal.from_float(
                datetime.datetime.strptime(args.begin_datetime, args.datetime_format)
                .replace(tzinfo=datetime.timezone.utc)
                .timestamp()
            )

        if args.end_datetime:
            args.end_timestamp = Decimal.from_float(
                datetime.datetime.strptime(args.end_datetime, args.datetime_format)
                .replace(tzinfo=datetime.timezone.utc)
                .timestamp()
            )

        if not args.begin_timestamp:
            print(
                "Please provide a begin timestamp via --begin-timestamp or --begin-datetime arguments."
            )
            exit()

        if not args.end_timestamp:
            print(
                "Please provide a end timestamp via --end-timestamp or --end-datetime arguments."
            )
            exit()

        if args.only_int_timestamp:
            args.begin_timestamp = int(args.begin_timestamp)
            args.end_timestamp = int(args.end_timestamp)

        if args.end_timestamp < args.begin_timestamp:
            print("Please define a beginning of timestamp before the end of timestamp.")
            exit()

        tolkien = ResetTolkien(
            token=args.token,
            timezone=args.timezone,
            timestamp_hash_formats_config_file=args.config,
            decimal_length=args.decimal_length,
            int_range_limit=args.int_timestamp_range,
            float_range_limit=args.float_timestamp_range,
            date_format_of_token=args.date_format_of_token,
            verbosity=args.verbosity,
            formats=args.token_format,
            progress_active=args.progress,
            alternative_tokens=args.alternative_tokens,
        )

        for token, value in tolkien.generate_bounded_possible_token(
            args.begin_timestamp,
            args.end_timestamp,
            prefix=args.prefix,
            suffix=args.suffix,
            formats=tolkien.formats,
        ):
            output = f"{token}"
            if args.with_timestamp:
                output = f"{value}:{token}"
            if args.output:
                args.output.write(f"{output}\n")
            else:
                print(f"{output}")

        if args.output:
            print(
                OUTPUT_STRINGS[output_version]["OUTPUT_IN_FILE"].format(
                    output=args.output.name
                )
            )


if __name__ == "__main__":
    main()
