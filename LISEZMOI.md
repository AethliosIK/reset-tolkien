# Reset Tolkien

![image.png](image.png)

Cet outil est le résultat d'une recherche sur les "Secrets non sécurisés basés sur le temps" de cet article:
- [\[FR\] Secret basé sur le temps non sécurisé et attaque par sandwich - Analyse de mes recherches et publication de l’outil “Reset Tolkien”](https://www.aeth.cc/public/Article-Reset-Tolkien/secret-time-based-article-fr.html)

Pour mieux comprendre comment utiliser cet outil, nous vous recommandons vivement de lire d'abord cet article.

> *Ouais, cet outil est basé sur un jeu de mots plutôt grotesque.*

- - -

## Installation

Installer depuis [pip](https://pypi.org/project/reset-tolkien/):

```
▶ pip install reset-tolkien
```

## Usage

Pour savoir si un token est basé sur le temps, il suffit d'utiliser cette commande :

```bash
$ reset-tolkien detect 660430516ffcf -d "Wed, 27 Mar 2024 14:42:25 GMT" --prefixes "attacker@example.com" --suffixes "attacker@example.com" --timezone "-7"
The token may be based on a timestamp: 1711550545.458703 (prefix: None / suffix: None)
The convertion logic is "uniqid"
```

Pour attaquer ce jeton, utilisez cette commande pour exporter les jetons possibles :

```bash
$ reset-tolkien sandwich 660430516ffcf -bt 1711550546.485597 -et 1711550546.505134 -o output.txt --token-format="uniqid"
Tokens have been exported in "output.txt"
```

## Encodage et fonction de hachage pris en charge

L'outil teste différents formats de token de façon récursive:
- `base32`
- `base64`
- `urlencode`
- `hexint`
- `hexstr`: encodage d'un nombre entier en ASCII
- `uniqid`: la fonction PHP `uniqid` précédemment étudié
- `uuidv1`: le format d'un UUID v1 basé sur le temps
- `shortuuid`: une fonction populaire d'encodage d'UUID
- `mongodb_objectid`: le format de donnée de Mongo DB précédemment étudié
- `datetime`: l'encodage d'une date à partir d'un format de date personnalisé
- `datetimeRFC2822`: l'encodage d'une date à partir du format issu de la norme RFC2822

L'outil gère également les fonctions de hachage les plus populaires:
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

Les différentes fonctionnalité de l'outil sont les suivantes:
- `detect`: permet de détecter si un token fournit est basé sur un date, fournit ou non:

```bash
usage: reset-tolkien detect [-h] [-r] [-v {0,1,2}] [-c CONFIG] [--threads THREADS] [--date-format-of-token DATE_FORMAT_OF_TOKEN] [--only-int-timestamp] [--decimal-length DECIMAL_LENGTH]
                     [--int-timestamp-range INT_TIMESTAMP_RANGE] [--float-timestamp-range FLOAT_TIMESTAMP_RANGE] [--timezone TIMEZONE] [-l {1,2,3}] [-t TIMESTAMP] [-d DATETIME]
                     [--datetime-format DATETIME_FORMAT] [--prefixes PREFIXES] [--suffixes SUFFIXES] [--hashes HASHES]
                     token

positional arguments:
  token                 The token given as input.

options:
  -h, --help            show this help message and exit
  -r, --roleplay        Not recommended if you don't have anything else to do
  -v {0,1,2}, --verbosity {0,1,2}
                        Verbosity level (default: 0)
  -c CONFIG, --config CONFIG
                        Config file to set TimestampHashFormat (default: default.yml)
  --threads THREADS     Define the number of parallelized tasks for the decryption attack on the hash. (default: 8)
  --date-format-of-token DATE_FORMAT_OF_TOKEN
                        Date format for the token - please set it if you have found a date as input.
  --only-int-timestamp  Only use integer timestamp. (default: False)
  --decimal-length DECIMAL_LENGTH
                        Length of the float timestamp (default: 7)
  --int-timestamp-range INT_TIMESTAMP_RANGE
                        Time range over which the int timestamp will be tested before and after the input value (default: 60s)
  --float-timestamp-range FLOAT_TIMESTAMP_RANGE
                        Time range over which the float timestamp will be tested before and after the input value (default: 2s)
  --timezone TIMEZONE   Timezone of the application for datetime value (default: 0)
  -l {1,2,3}, --level {1,2,3}
                        Level of search depth (default: 3)
  -t TIMESTAMP, --timestamp TIMESTAMP
                        The timestamp of the reset request
  -d DATETIME, --datetime DATETIME
                        The datetime of the reset request
  --datetime-format DATETIME_FORMAT
                        The input datetime format (default: server date format like "Tue, 12 Mar 2024 16:24:05 UTC")
  --prefixes PREFIXES   List of possible values for the prefix concatenated with the timestamp. Format: prefix1,prefix2
  --suffixes SUFFIXES   List of possible values for the suffix concatenated with the timestamp. Format: suffix1,suffix2
  --hashes HASHES       List of possible hashes to try to detect the format. Format: suffix1,suffix2 (default: all identified hash)
```

- `bruteforce`: permet de fournir une liste de tokens possibles à partir d'un format de token et d'une fenètre temporelle défini arbitrairement:

```bash
usage: reset-tolkien bruteforce [-h] [-r] [-v {0,1,2}] [-c CONFIG] [--threads THREADS] [--date-format-of-token DATE_FORMAT_OF_TOKEN] [--only-int-timestamp] [--decimal-length DECIMAL_LENGTH]
                         [--int-timestamp-range INT_TIMESTAMP_RANGE] [--float-timestamp-range FLOAT_TIMESTAMP_RANGE] [--timezone TIMEZONE] [-t TIMESTAMP] [-d DATETIME]
                         [--datetime-format DATETIME_FORMAT] [--token-format TOKEN_FORMAT] [--prefix PREFIX] [--suffix SUFFIX] [-o OUTPUT] [--with-timestamp]
                         token

positional arguments:
  token                 The token given as input.

options:
  -h, --help            show this help message and exit
  -r, --roleplay        Not recommended if you don't have anything else to do
  -v {0,1,2}, --verbosity {0,1,2}
                        Verbosity level (default: 0)
  -c CONFIG, --config CONFIG
                        Config file to set TimestampHashFormat (default: default.yml)
  --threads THREADS     Define the number of parallelized tasks for the decryption attack on the hash. (default: 8)
  --date-format-of-token DATE_FORMAT_OF_TOKEN
                        Date format for the token - please set it if you have found a date as input.
  --only-int-timestamp  Only use integer timestamp. (default: False)
  --decimal-length DECIMAL_LENGTH
                        Length of the float timestamp (default: 7)
  --int-timestamp-range INT_TIMESTAMP_RANGE
                        Time range over which the int timestamp will be tested before and after the input value (default: 60s)
  --float-timestamp-range FLOAT_TIMESTAMP_RANGE
                        Time range over which the float timestamp will be tested before and after the input value (default: 2s)
  --timezone TIMEZONE   Timezone of the application for datetime value (default: 0)
  -t TIMESTAMP, --timestamp TIMESTAMP
                        The timestamp of the reset request with victim email
  -d DATETIME, --datetime DATETIME
                        The datetime of the reset request with victim email
  --datetime-format DATETIME_FORMAT
                        The input datetime format (default: server date format like "Tue, 12 Mar 2024 16:25:07 UTC")
  --token-format TOKEN_FORMAT
                        The token encoding/hashing format - Format: encoding1,encoding2
  --prefix PREFIX       The prefix value concatenated with the timestamp.
  --suffix SUFFIX       The suffix value concatenated with the timestamp.
  -o OUTPUT, --output OUTPUT
                        The filename of the output
  --with-timestamp      Write the output with timestamp
```

- `sandwich`: permet de fournir une liste de tokens possibles à partir d'un format de token et d'une fenètre temporelle borné par deux dates:

```bash
usage: reset-tolkien sandwich [-h] [-r] [-v {0,1,2}] [-c CONFIG] [--threads THREADS] [--date-format-of-token DATE_FORMAT_OF_TOKEN] [--only-int-timestamp] [--decimal-length DECIMAL_LENGTH]
                       [--int-timestamp-range INT_TIMESTAMP_RANGE] [--float-timestamp-range FLOAT_TIMESTAMP_RANGE] [--timezone TIMEZONE] [-bt BEGIN_TIMESTAMP] [-et END_TIMESTAMP]
                       [-bd BEGIN_DATETIME] [-ed END_DATETIME] [--datetime-format DATETIME_FORMAT] [--token-format TOKEN_FORMAT] [--prefix PREFIX] [--suffix SUFFIX] [-o OUTPUT]
                       [--with-timestamp]
                       token

positional arguments:
  token                 The token given as input.

options:
  -h, --help            show this help message and exit
  -r, --roleplay        Not recommended if you don't have anything else to do
  -v {0,1,2}, --verbosity {0,1,2}
                        Verbosity level (default: 0)
  -c CONFIG, --config CONFIG
                        Config file to set TimestampHashFormat (default: default.yml)
  --threads THREADS     Define the number of parallelized tasks for the decryption attack on the hash. (default: 8)
  --date-format-of-token DATE_FORMAT_OF_TOKEN
                        Date format for the token - please set it if you have found a date as input.
  --only-int-timestamp  Only use integer timestamp. (default: False)
  --decimal-length DECIMAL_LENGTH
                        Length of the float timestamp (default: 7)
  --int-timestamp-range INT_TIMESTAMP_RANGE
                        Time range over which the int timestamp will be tested before and after the input value (default: 60s)
  --float-timestamp-range FLOAT_TIMESTAMP_RANGE
                        Time range over which the float timestamp will be tested before and after the input value (default: 2s)
  --timezone TIMEZONE   Timezone of the application for datetime value (default: 0)
  -bt BEGIN_TIMESTAMP, --begin-timestamp BEGIN_TIMESTAMP
                        The begin timestamp of the reset request with victim email
  -et END_TIMESTAMP, --end-timestamp END_TIMESTAMP
                        The end timestamp of the reset request with victim email
  -bd BEGIN_DATETIME, --begin-datetime BEGIN_DATETIME
                        The begin datetime of the reset request with victim email
  -ed END_DATETIME, --end-datetime END_DATETIME
                        The end datetime of the reset request with victim email
  --datetime-format DATETIME_FORMAT
                        The input datetime format (default: server date format like "Tue, 12 Mar 2024 16:25:55 UTC")
  --token-format TOKEN_FORMAT
                        The token encoding/hashing format - Format: encoding1,encoding2
  --prefix PREFIX       The prefix value concatenated with the timestamp.
  --suffix SUFFIX       The suffix value concatenated with the timestamp.
  -o OUTPUT, --output OUTPUT
                        The filename of the output
  --with-timestamp      Write the output with timestamp
```

## Tests par défaut

Par défaut, l'outil est configuré pour détecter ce type de génération de token basé sur le temps:

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

## Configuration personnalisée des tests

De plus, l'outil permet de définir ses propres formats de token avant l'application d'une fonction de hachage via un object `TimestampHashFormat`. Par exemple, pour tester si le token est généré via cette fonction de génération de token:

```python
# Generate a formatted token
def generate_token():
    import datetime
    import hashlib
    
    t = datetime.datetime.utcnow().timestamp()
    token = hashlib.md5(uniqid(t).encode()).hexdigest()
    return token
```

Il est possible de définir dans le fichier YAML de configuration:

```yaml
float-uniqid:
  description: "Uniqid timestamp"
  level: 2
  timestamp_type: float
  formats:
    - uniqid
```

## La liste des "Todo"

Forcément, comme tout outil, il est toujours possible d'y ajouter de nouvelles fonctionnalités qui viendraient le compléter.

Parmis les points qui seraient bien utiles:
- **Gestion des formats via [Abstract syntax tree](https://docs.python.org/3/library/ast.html)**: l'outil ne gère actuellement que les formats appliqués de façon linéaire, ainsi, un format simple comme `md5(timestamp()+1)` ne pourra pas être pris en charge. Via une configuration des formats en arbre, ce genre de format pourra être pris en charge par l'outil.
- **Meilleure application des informations propres à l'utilisateur**: lors de la détection d'un format de token, il est possible de définir les informations propres à l'utilisateur en tant que préfixes ou suffixes de la date de génération du token. De nombreuses autres configurations pourraient être possibles.
- **Gestion des autres variables dynamiques**: l'outil détecte les formats et permet d'attaquer à partir de la seule variable pris en charge: le temps. Cependant, certains formats peuvent avoir plusieurs variables qui évoluent.
- **Ajout de nouveaux formats pris en charge**: l'outil prend en charge uniquement les fonctions basées sur le temps découvertes lors de mes recherches, mais de nombreuses autres formats doivent encore exister et pourraient être aussi prises en charge par l'outil.


## Licence

Ce projet est placé sous la [licence MIT](LICENSE).

## Credit

- Illustration principale: prestation réalisé par [@valentin.froute](https://www.instagram.com/valentin.froute/).
