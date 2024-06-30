# Reset Tolkien

## Unsecure time-based secret exploitation and Sandwich attack implementation 

![image.png](image.png)

This tool is the result of research into "Unsecure time-based secrets" from this article:
- [\[EN\] Unsecure time-based secret and Sandwich Attack - Analysis of my research and release of the "Reset Tolkien" tool](https://www.aeth.cc/public/Article-Reset-Tolkien/secret-time-based-article-en.html)

To better understand how to use this tool, we strongly recommend that you read it first.

> *Yeah, this tool is based on a rather grotesque pun.*

- - -

## Installation

Install from [pip](https://pypi.org/project/reset-tolkien/):

```
▶ pip install reset-tolkien
```

## Installation from Docker

```
▶ git clone https://github.com/AethliosIK/reset-tolkien.git
▶ cd reset-tolkien
▶ docker build -t reset-tolkien:latest . 
▶ docker run --rm -it --net=host -v "$PWD:/reset-tolkien/" reset-tolkien:latest -h
```

## Usage

To detect whether a token is time-based, simply use this command:

```bash
$ reset-tolkien detect 660430516ffcf -d "Wed, 27 Mar 2024 14:42:25 GMT" --prefixes "attacker@example.com" --suffixes "attacker@example.com" --timezone "-7"
The token may be based on a timestamp: 1711550545.458703 (prefix: None / suffix: None)
The convertion logic is "uniqid"
```

To attack this token, use this command to export possible tokens:

```bash
$ reset-tolkien sandwich 660430516ffcf -bt 1711550546.485597 -et 1711550546.505134 -o output.txt --token-format="uniqid"
Tokens have been exported in "output.txt"
```

## Encoding and hash function supported

The tool recursively tests different token formats:
- `base32`
- `base64`
- `urlencode`
- `hexint`
- `hexstr`: ASCII integer encoding
- `uniqid`: the PHP function `uniqid` previously studied
- `uuidv1`: the format of a time-based UUID Version 1
- `shortuuid`: a popular UUID encoding function
- `mongodb_objectid`: the Mongo DB data format studied above
- `datetime`: the encoding of a date from a custom date format
- `datetimeRFC2822`: encoding a date using the format from the RFC2822 standard

The tool also manages the most popular hash functions:
- `md5`
- `sha1`
- `sha224`
- `sha256`
- `sha384`
- `sha512`
- `sha3_224`
- `sha3_256`
- `sha3_384`
- `sha3_512`
- `blake_256`
- `blake_512`

## Help

```bash
usage: reset-tolkien [-h] [-v] {detect,bruteforce,sandwich} ...

Reset Tolkien can be used to find out whether a provided token is based on a
timestamp, from a timestamp corresponding to the period in which it was
generated.

options:
  -h, --help            show this help message and exit
  -v, --version         Print tool version

action:
  {detect,bruteforce,sandwich}
    detect              Detect the format of reset token
    bruteforce          Attack the reset token
    sandwich            Attack the reset token with sandwich method
```

The various features of the tool are as follows:
- `detect`: detects whether a provided token is based on a date, provided or not:

```bash
usage: reset-tolkien detect [-h] [-r] [-v {0,1,2}] [-c CONFIG] [--threads THREADS]
                     [--date-format-of-token DATE_FORMAT_OF_TOKEN]
                     [--only-int-timestamp] [--decimal-length DECIMAL_LENGTH]
                     [--int-timestamp-range INT_TIMESTAMP_RANGE]
                     [--float-timestamp-range FLOAT_TIMESTAMP_RANGE]
                     [--timezone TIMEZONE] [-l {1,2,3}] [-t TIMESTAMP]
                     [-d DATETIME] [--datetime-format DATETIME_FORMAT]
                     [--prefixes PREFIXES] [--suffixes SUFFIXES]
                     [--hashes HASHES]
                     token

positional arguments:
  token                 The token given as input.

options:
  -h, --help            show this help message and exit
  -r, --roleplay        Not recommended if you don't have anything else to do
  -v {0,1,2}, --verbosity {0,1,2}
                        Verbosity level (default: 0)
  -c CONFIG, --config CONFIG
                        Config file to set TimestampHashFormat (default: resetTolkien/config/default.yml)
  --threads THREADS     Define the number of parallelized tasks for the
                        decryption attack on the hash. (default: 8)
  --date-format-of-token DATE_FORMAT_OF_TOKEN
                        Date format for the token - please set it if you have
                        found a date as input.
  --only-int-timestamp  Only use integer timestamp. (default: False)
  --decimal-length DECIMAL_LENGTH
                        Length of the float timestamp (default: 7)
  --int-timestamp-range INT_TIMESTAMP_RANGE
                        Time range over which the int timestamp will be tested
                        before and after the input value (default: 60s)
  --float-timestamp-range FLOAT_TIMESTAMP_RANGE
                        Time range over which the float timestamp will be
                        tested before and after the input value (default: 2s)
  --timezone TIMEZONE   Timezone of the application for datetime value
                        (default: 0)
  -l {1,2,3}, --level {1,2,3}
                        Level of search depth (default: 3)
  -t TIMESTAMP, --timestamp TIMESTAMP
                        The timestamp of the reset request
  -d DATETIME, --datetime DATETIME
                        The datetime of the reset request
  --datetime-format DATETIME_FORMAT
                        The input datetime format (default: server date format
                        like "Sun, 30 Jun 2024 01:38:41 UTC")
  --prefixes PREFIXES   List of possible values for the prefix concatenated
                        with the timestamp. Format: prefix1,prefix2
  --suffixes SUFFIXES   List of possible values for the suffix concatenated
                        with the timestamp. Format: suffix1,suffix2
  --hashes HASHES       List of possible hashes to try to detect the format.
                        Format: suffix1,suffix2 (default: all identified hash)
```

- `bruteforce`:  provides a list of possible tokens from an arbitrarily defined token format and time frame:

```bash
usage: reset-tolkien bruteforce [-h] [-r] [-v {0,1,2}] [-c CONFIG]
                         [--threads THREADS]
                         [--date-format-of-token DATE_FORMAT_OF_TOKEN]
                         [--only-int-timestamp]
                         [--decimal-length DECIMAL_LENGTH]
                         [--int-timestamp-range INT_TIMESTAMP_RANGE]
                         [--float-timestamp-range FLOAT_TIMESTAMP_RANGE]
                         [--timezone TIMEZONE] [-t TIMESTAMP] [-d DATETIME]
                         [--datetime-format DATETIME_FORMAT]
                         [--token-format TOKEN_FORMAT] [--prefix PREFIX]
                         [--suffix SUFFIX] [-o OUTPUT] [--with-timestamp]
                         token

positional arguments:
  token                 The token given as input.

options:
  -h, --help            show this help message and exit
  -r, --roleplay        Not recommended if you don't have anything else to do
  -v {0,1,2}, --verbosity {0,1,2}
                        Verbosity level (default: 0)
  -c CONFIG, --config CONFIG
                        Config file to set TimestampHashFormat (default: resetTolkien/config/default.yml)
  --threads THREADS     Define the number of parallelized tasks for the
                        decryption attack on the hash. (default: 8)
  --date-format-of-token DATE_FORMAT_OF_TOKEN
                        Date format for the token - please set it if you have
                        found a date as input.
  --only-int-timestamp  Only use integer timestamp. (default: False)
  --decimal-length DECIMAL_LENGTH
                        Length of the float timestamp (default: 7)
  --int-timestamp-range INT_TIMESTAMP_RANGE
                        Time range over which the int timestamp will be tested
                        before and after the input value (default: 60s)
  --float-timestamp-range FLOAT_TIMESTAMP_RANGE
                        Time range over which the float timestamp will be
                        tested before and after the input value (default: 2s)
  --timezone TIMEZONE   Timezone of the application for datetime value
                        (default: 0)
  -t TIMESTAMP, --timestamp TIMESTAMP
                        The timestamp of the reset request with victim email
  -d DATETIME, --datetime DATETIME
                        The datetime of the reset request with victim email
  --datetime-format DATETIME_FORMAT
                        The input datetime format (default: server date format
                        like "Sun, 30 Jun 2024 01:40:15 UTC")
  --token-format TOKEN_FORMAT
                        The token encoding/hashing format - Format:
                        encoding1,encoding2
  --prefix PREFIX       The prefix value concatenated with the timestamp.
  --suffix SUFFIX       The suffix value concatenated with the timestamp.
  -o OUTPUT, --output OUTPUT
                        The filename of the output
  --with-timestamp      Write the output with timestamp
```

- `sandwich`: provides a list of possible tokens based on a token format and a time frame bounded by two dates:

```bash
usage: reset-tolkien sandwich [-h] [-r] [-v {0,1,2}] [-c CONFIG] [--threads THREADS]
                       [--date-format-of-token DATE_FORMAT_OF_TOKEN]
                       [--only-int-timestamp]
                       [--decimal-length DECIMAL_LENGTH]
                       [--int-timestamp-range INT_TIMESTAMP_RANGE]
                       [--float-timestamp-range FLOAT_TIMESTAMP_RANGE]
                       [--timezone TIMEZONE] [-bt BEGIN_TIMESTAMP]
                       [-et END_TIMESTAMP] [-bd BEGIN_DATETIME]
                       [-ed END_DATETIME] [--datetime-format DATETIME_FORMAT]
                       [--token-format TOKEN_FORMAT] [--prefix PREFIX]
                       [--suffix SUFFIX] [-o OUTPUT] [--with-timestamp]
                       token

positional arguments:
  token                 The token given as input.

options:
  -h, --help            show this help message and exit
  -r, --roleplay        Not recommended if you don't have anything else to do
  -v {0,1,2}, --verbosity {0,1,2}
                        Verbosity level (default: 0)
  -c CONFIG, --config CONFIG
                        Config file to set TimestampHashFormat (default: resetTolkien/config/default.yml)
  --threads THREADS     Define the number of parallelized tasks for the
                        decryption attack on the hash. (default: 8)
  --date-format-of-token DATE_FORMAT_OF_TOKEN
                        Date format for the token - please set it if you have
                        found a date as input.
  --only-int-timestamp  Only use integer timestamp. (default: False)
  --decimal-length DECIMAL_LENGTH
                        Length of the float timestamp (default: 7)
  --int-timestamp-range INT_TIMESTAMP_RANGE
                        Time range over which the int timestamp will be tested
                        before and after the input value (default: 60s)
  --float-timestamp-range FLOAT_TIMESTAMP_RANGE
                        Time range over which the float timestamp will be
                        tested before and after the input value (default: 2s)
  --timezone TIMEZONE   Timezone of the application for datetime value
                        (default: 0)
  -bt BEGIN_TIMESTAMP, --begin-timestamp BEGIN_TIMESTAMP
                        The begin timestamp of the reset request with victim
                        email
  -et END_TIMESTAMP, --end-timestamp END_TIMESTAMP
                        The end timestamp of the reset request with victim
                        email
  -bd BEGIN_DATETIME, --begin-datetime BEGIN_DATETIME
                        The begin datetime of the reset request with victim
                        email
  -ed END_DATETIME, --end-datetime END_DATETIME
                        The end datetime of the reset request with victim
                        email
  --datetime-format DATETIME_FORMAT
                        The input datetime format (default: server date format
                        like "Sun, 30 Jun 2024 01:40:54 UTC")
  --token-format TOKEN_FORMAT
                        The token encoding/hashing format - Format:
                        encoding1,encoding2
  --prefix PREFIX       The prefix value concatenated with the timestamp.
  --suffix SUFFIX       The suffix value concatenated with the timestamp.
  -o OUTPUT, --output OUTPUT
                        The filename of the output
  --with-timestamp      Write the output with timestamp
```

## VI.4 - Default tests

By default, the tool is configured to detect this type of time-based token generation:

```php
function getToken($level, $email)
{
    switch ($level) {
        case 1:
            return uniqid();
        case 2:
            return hash(time());
        case 3:
            return hash(uniqid());
        case 4:
            return hash(uniqid() . $email);
        case 5:
            return hash(date(DATE_RFC2822));
        case 6:
            return hash($email . uniqid() . $email);
        case 7:
            return uuid1("Test");
    }
}
```

## Customised test configuration

In addition, the tool allows you to define your own token formats before applying a hash function via a `TimestampHashFormat` object. For example, to test whether the token is generated using this token generation function:

```python
# Generate a formatted token
def generate_token():
    import datetime
    import hashlib
    
    t = datetime.datetime.utcnow().timestamp()
    token = hashlib.md5(uniqid(t).encode()).hexdigest()
    return token
```

This can be defined in the YAML configuration file:

```yaml
float-uniqid:
  description: "Uniqid timestamp"
  level: 2
  timestamp_type: float
  formats:
    - uniqid
```

## The "Todo" list

Of course, as with any tool, there is always the possibility of adding new features to complement it.

Among the points that would be very useful:
- **Format management via [Abstract syntax tree](https://docs.python.org/3/library/ast.html)**: the tool currently only manages formats applied in a linear way, so a simple format like `md5(timestamp()+1)` won't be supported. By configuring formats as a tree, this type of format can be supported by the tool.
- **Better application of user-specific information**: when detecting a token format, it is possible to define user-specific information as prefixes or suffixes of the token generation date. Many other configurations could be possible.
- **Management of other dynamic variables**: the tool detects formats and allows attacks based on the only variable supported: time. However, some formats can have several variables that evolve.
- **Addition of new supported formats**: the tool only supports the time-based functions found during my research, but many other formats should still exist and could also be supported by the tool.

## Changelog

You could retrieve changes for each version from [CHANGELOG.md](CHANGELOG.md).

## Licensing

This project is licensed under the [MIT license](LICENSE).

## Credit

- Main illustration: service provided by [@valentin.froute](https://www.instagram.com/valentin.froute/).
