# -*- coding: utf-8 -*-
# Author: Aethlios <contact@aeth.cc>

import hashlib


class Hashes:
    """Utility class for hashing all available formats"""

    @staticmethod
    def md5(value: str) -> str:
        return hashlib.md5(value.encode()).hexdigest()

    @staticmethod
    def sha1(value: str) -> str:
        return hashlib.sha1(value.encode()).hexdigest()

    @staticmethod
    def sha224(value: str) -> str:
        return hashlib.sha224(value.encode()).hexdigest()

    @staticmethod
    def sha256(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    @staticmethod
    def sha384(value: str) -> str:
        return hashlib.sha384(value.encode()).hexdigest()

    @staticmethod
    def sha512(value: str) -> str:
        return hashlib.sha512(value.encode()).hexdigest()

    @staticmethod
    def sha3_224(value: str) -> str:
        return hashlib.sha3_224(value.encode()).hexdigest()

    @staticmethod
    def sha3_256(value: str) -> str:
        return hashlib.sha3_256(value.encode()).hexdigest()

    @staticmethod
    def sha3_384(value: str) -> str:
        return hashlib.sha3_384(value.encode()).hexdigest()

    @staticmethod
    def sha3_512(value: str) -> str:
        return hashlib.sha3_512(value.encode()).hexdigest()

    @staticmethod
    def blake_256(value: str) -> str:
        return hashlib.blake2s(value.encode()).hexdigest()

    @staticmethod
    def blake_512(value: str) -> str:
        return hashlib.blake2b(value.encode()).hexdigest()
