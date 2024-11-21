# -*- coding: utf-8 -*-
# Author: Aethlios <contact@aeth.cc>

from os import cpu_count, path

OUTPUT_STRINGS = {
    "ROLEPLAY": {
        "TIMESTAMP_FOUND": "We found my precious! {timestamp} (prefix: {prefix} / suffix: {suffix})",
        "TOKEN_FORMAT": 'The way to get my precious is "{formats}"',
        "OUTPUT_IN_FILE": 'I\'ve hidden my precious ones in this dark corner: "{output}"',
        "INT_TIMESTAMP": "Please set you precious with --only-int-timestamp",
        "FAIL": "Stupid fat hobbit!",
    },
    "NOJOKE": {
        "TIMESTAMP_FOUND": "The token may be based on a timestamp: {timestamp} (prefix: {prefix} / suffix: {suffix})",
        "TOKEN_FORMAT": 'The convertion logic is "{formats}"',
        "OUTPUT_IN_FILE": 'Tokens have been exported in "{output}"',
        "INT_TIMESTAMP": "Please set the optional argument --only-int-timestamp",
        "FAIL": "It's not timestamp-based.",
    },
}

PROG_DESCRIPTION = "Reset Tolkien can be used to find out whether a provided token is based on a timestamp, from a timestamp corresponding to the period in which it was generated."

NB_DAYS_LIMIT = 365 * 1
TIMESTAMP_HEX_LENGTH = 8
TIMESTAMP_STR_LENGTH = 10
UUID_DECIMAL_LENGTH = 7
DEFAULT_DECIMAL_LENGTH = UUID_DECIMAL_LENGTH
DEFAULT_TIMERANGE_FOR_INT_TIMESTAMP = 60
DEFAULT_TIMERANGE_FOR_FLOAT_TIMESTAMP = 2
MIN_LENGTH_OF_FLOATING_TIMESTAMP_HEX = 8
MAX_LENGTH_OF_FLOATING_TIMESTAMP_HEX = 13

cpu = cpu_count()
DEFAULT_THREAD_NUMBER = cpu if cpu else 1
MIN_DEPTH_LEVEL = 1
MAX_DEPTH_LEVEL = 3
DEFAULT_DEPTH_LEVEL = MAX_DEPTH_LEVEL
MAX_VERBOSITY_LEVEL = 2
DEFAULT_VERBOSITY_LEVEL = 0

DEFAULT_CONFIG_FILENAME = "default.yml"
DEFAULT_CONFIG_FILE = path.join(path.dirname(path.realpath(__file__)), "config", DEFAULT_CONFIG_FILENAME)

SERVER_DATE_FORMAT = "%a, %d %b %Y %H:%M:%S %Z"

PARTIAL_FUNC_NAME_REGEX = r"functools\.partial\(<bound method Formatter\.([a-zA-Z_]*) of <.*\.format\.Formatter object at [0-9a-fx]*>>, (.*)\)"

# 12/12/2023 or 5/5/2023 or 12/12/23 or 2023/12/12
DATE_SLASH_REGEX = r"[0-9]{1,4}\/[0-9]{1,2}\/[0-9]{1,4}"
# 12-12-2023 or 5-5-2023 or 12-12-23 or 2023-12-12
DATE_DASH_REGEX = r"[0-9]{1,4}\-[0-9]{1,2}\-[0-9]{1,4}"
# 22:32:47
TIME_REGEX = r"(?:\d{2}):(?:\d{2}):(?:\d{2})"
# January or Jan
MONTH_REGEX = r"(?:J(anuary|u(ne|ly))|February|Ma(rch|y)|A(pril|ugust)|(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)|(September|October|November|December))"
