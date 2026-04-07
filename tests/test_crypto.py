"""Tests for the Crypto utilities."""

import pytest

from protector_stack.utils.crypto import (
    chain_hash,
    generate_signing_key,
    get_or_create_signing_key,
    load_signing_key,
    record_fingerprint,
    sign_record,
    sha256_hex,
    verify_record,
)


def test_sha256_hex():
    h = sha256_hex(b"hello")
    assert len(h) == 64
    assert h == sha256_hex(b"hello")
    assert h != sha256_hex(b"world")


def test_sign_and_verify(tmp_path):
    key_path = str(tmp_path / "test.pem")
    key = generate_signing_key(key_path)
    record = {"action": "test", "value": 42}
    sig = sign_record(record, key)
    assert verify_record(record, sig, key)
    # Tampered record should fail
    tampered = dict(record)
    tampered["value"] = 99
    assert not verify_record(tampered, sig, key)


def test_chain_hash_changes_on_modification():
    record1 = {"id": "1", "data": "original"}
    record2 = {"id": "1", "data": "modified"}
    prev = "0" * 64
    h1 = chain_hash(prev, record1)
    h2 = chain_hash(prev, record2)
    assert h1 != h2


def test_chain_hash_changes_on_prev_hash():
    record = {"id": "1"}
    h1 = chain_hash("0" * 64, record)
    h2 = chain_hash("a" * 64, record)
    assert h1 != h2


def test_generate_and_load_key(tmp_path):
    key_path = str(tmp_path / "k.pem")
    key = generate_signing_key(key_path)
    loaded = load_signing_key(key_path)
    assert key == loaded


def test_get_or_create_key(tmp_path):
    key_path = str(tmp_path / "new.pem")
    key1 = get_or_create_signing_key(key_path)
    key2 = get_or_create_signing_key(key_path)
    assert key1 == key2


def test_record_fingerprint():
    fp = record_fingerprint({"a": 1})
    assert len(fp) == 8
    assert fp == record_fingerprint({"a": 1})
    assert fp != record_fingerprint({"a": 2})
