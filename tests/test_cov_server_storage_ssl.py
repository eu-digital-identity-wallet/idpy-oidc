"""Coverage tests for idpyoidc.storage.abfile, idpyoidc.storage.listfile and idpyoidc.ssl_context."""

import datetime
import json
import os
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from idpyoidc import ssl_context
from idpyoidc.storage import DictType
from idpyoidc.storage import abfile
from idpyoidc.storage import listfile
from idpyoidc.storage.abfile import AbstractFileSystem
from idpyoidc.storage.listfile import ReadOnlyListFile
from idpyoidc.storage.listfile import ReadOnlyListFileMtime


class _RaisingLock:
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        raise RuntimeError("lock failure")

    def __exit__(self, *args):
        return False


def _bump_mtime(fname, delta=10):
    st = os.stat(fname)
    os.utime(fname, ns=(st.st_atime_ns, st.st_mtime_ns + delta * 1_000_000_000))


# ---------------------------------------------------------------------------
# storage.DictType


def test_dict_type_keeps_kwargs():
    assert DictType(a=1).kwargs == {"a": 1}


# ---------------------------------------------------------------------------
# AbstractFileSystem


class TestAbstractFileSystem:
    def test_creates_directory(self, tmp_path):
        fdir = tmp_path / "db"
        db = AbstractFileSystem(fdir=str(fdir))
        assert fdir.is_dir()
        assert len(db) == 0
        assert db.kwargs == {"fdir": str(fdir), "key_conv": "", "value_conv": ""}

    def test_set_get_and_file_content(self, tmp_path):
        db = AbstractFileSystem(fdir=str(tmp_path))
        db["a b"] = "value"
        # QPKey is the default key converter
        assert (tmp_path / "a+b").read_text() == "value"
        assert db["a b"] == "value"
        assert db.get("a b") == "value"
        assert db.get("missing", "dflt") == "dflt"
        assert db.get("missing") is None
        assert "a b" in db
        assert "missing" not in db
        assert str(db) == "info:{'a+b': 'value'}"

    def test_value_converter(self, tmp_path):
        db = AbstractFileSystem(
            fdir=str(tmp_path), key_conv="idpyoidc.util.QPKey", value_conv="idpyoidc.util.JSON"
        )
        db["k"] = {"x": [1, 2]}
        assert json.loads((tmp_path / "k").read_text()) == {"x": [1, 2]}
        fresh = AbstractFileSystem(fdir=str(tmp_path), value_conv="idpyoidc.util.JSON")
        assert fresh["k"] == {"x": [1, 2]}

    def test_reads_existing_files_at_start(self, tmp_path):
        (tmp_path / "one").write_text("1\n")
        (tmp_path / "one.lock").write_text("")
        (tmp_path / "sub").mkdir()
        db = AbstractFileSystem(fdir=str(tmp_path))
        assert db.storage == {"one": "1"}
        assert list(db.keys()) == ["one"]
        assert len(db) == 1  # lock file and sub directory are skipped

    def test_external_change_is_picked_up(self, tmp_path):
        db = AbstractFileSystem(fdir=str(tmp_path))
        db["k"] = "old"
        fname = tmp_path / "k"
        fname.write_text("new")
        _bump_mtime(fname)
        assert db["k"] == "new"
        # unchanged afterwards: served from cache
        db.storage["k"] = "cached"
        assert db["k"] == "cached"

    def test_unseen_file_is_read(self, tmp_path):
        db = AbstractFileSystem(fdir=str(tmp_path))
        (tmp_path / "late").write_text("arrived")
        assert db["late"] == "arrived"

    def test_missing_key(self, tmp_path):
        db = AbstractFileSystem(fdir=str(tmp_path))
        with pytest.raises(KeyError):
            db["nope"]

    def test_synch_updates_changed_and_new(self, tmp_path):
        db = AbstractFileSystem(fdir=str(tmp_path))
        db["a"] = "1"
        (tmp_path / "a").write_text("2")
        _bump_mtime(tmp_path / "a")
        (tmp_path / "b").write_text("3")
        assert dict(db.items()) == {"a": "2", "b": "3"}
        assert dict(iter(db)) == {"a": "2", "b": "3"}
        assert sorted(db()) == ["a", "b"]
        assert db.dump() == {"a": "2", "b": "3"}

    def test_synch_recreates_directory(self, tmp_path):
        fdir = tmp_path / "db"
        db = AbstractFileSystem(fdir=str(fdir))
        os.rmdir(fdir)
        assert len(db) == 0
        db.synch()
        assert fdir.is_dir()

    def test_synch_bad_content_is_skipped(self, tmp_path, caplog):
        (tmp_path / "bad").write_text("{not json")
        (tmp_path / "good").write_text('"ok"')
        db = AbstractFileSystem(fdir=str(tmp_path), value_conv="idpyoidc.util.JSON")
        assert db.storage == {"good": "ok"}
        assert "bad" not in db.fmtime
        assert "Bad content" in caplog.text

    def test_setitem_recreates_directory(self, tmp_path):
        fdir = tmp_path / "db"
        db = AbstractFileSystem(fdir=str(fdir))
        os.rmdir(fdir)
        db["x"] = "y"
        assert (fdir / "x").read_text() == "y"
        assert db.fmtime["x"] == os.stat(fdir / "x").st_mtime_ns

    def test_setitem_key_conv_keyerror(self, tmp_path):
        db = AbstractFileSystem(fdir=str(tmp_path))

        class _Conv:
            def serialize(self, key):
                raise KeyError(key)

            def deserialize(self, key):
                return key

        db.key_conv = _Conv()
        db["raw"] = "v"
        assert (tmp_path / "raw").read_text() == "v"

    def test_delitem(self, tmp_path):
        db = AbstractFileSystem(fdir=str(tmp_path))
        db["k"] = "v"
        # make sure a lock file exists next to the data file
        (tmp_path / "k.lock").touch()
        del db["k"]
        assert not (tmp_path / "k").exists()
        assert not (tmp_path / "k.lock").exists()
        assert "k" not in db
        # deleting something unknown is a no-op
        del db["unknown"]

    def test_delitem_lock_file(self, tmp_path):
        db = AbstractFileSystem(fdir=str(tmp_path))
        (tmp_path / "x.lock").touch()
        del db["x.lock"]
        assert not (tmp_path / "x.lock").exists()
        del db["x.lock"]  # already gone

    @pytest.mark.xfail(
        strict=True,
        reason="BUG: storage/abfile.py:129 __delitem__ doesn't apply key_conv, so a key "
        "that needs quoting ('a b' -> 'a+b') is never removed from disk or cache",
    )
    def test_delitem_quoted_key(self, tmp_path):
        db = AbstractFileSystem(fdir=str(tmp_path))
        db["a b"] = "v"
        del db["a b"]
        assert "a b" not in db
        assert len(db) == 0

    def test_clear(self, tmp_path):
        db = AbstractFileSystem(fdir=str(tmp_path))
        db.update({"a": "1", "b": "2"})
        assert len(db) == 2
        db.clear()
        assert len(db) == 0
        assert db.storage == {}
        assert os.listdir(tmp_path) == []

    def test_clear_missing_directory(self, tmp_path):
        fdir = tmp_path / "db"
        db = AbstractFileSystem(fdir=str(fdir))
        os.rmdir(fdir)
        db.clear()
        assert fdir.is_dir()

    def test_len_missing_directory(self, tmp_path):
        fdir = tmp_path / "db"
        db = AbstractFileSystem(fdir=str(fdir))
        os.rmdir(fdir)
        assert len(db) == 0

    def test_load(self, tmp_path):
        db = AbstractFileSystem(fdir=str(tmp_path))
        db.load({"x": "1", "y": "2"})
        assert db.dump() == {"x": "1", "y": "2"}

    def test_read_info(self, tmp_path, monkeypatch):
        db = AbstractFileSystem(fdir=str(tmp_path))
        assert db._read_info(str(tmp_path / "nope")) is None
        (tmp_path / "f").write_text(" padded \n")
        assert db._read_info(str(tmp_path / "f")) == "padded"
        monkeypatch.setattr(abfile, "FileLock", _RaisingLock)
        with pytest.raises(RuntimeError):
            db._read_info(str(tmp_path / "f"))

    def test_get_mtime_retries(self, tmp_path, monkeypatch):
        fname = tmp_path / "f"
        fname.write_text("x")
        real_stat = os.stat
        calls = {"stat": 0, "sleep": []}

        def _stat(path, *args, **kwargs):
            calls["stat"] += 1
            if calls["stat"] == 1:
                raise OSError("busy")
            return real_stat(path, *args, **kwargs)

        monkeypatch.setattr(abfile.os, "stat", _stat)
        monkeypatch.setattr(abfile.time, "sleep", lambda s: calls["sleep"].append(s))
        assert AbstractFileSystem.get_mtime(str(fname)) == real_stat(fname).st_mtime_ns
        assert calls["sleep"] == [1]


# ---------------------------------------------------------------------------
# ReadOnlyListFile


class TestReadOnlyListFile:
    def test_creates_missing_file(self, tmp_path):
        fname = tmp_path / "list.txt"
        lst = ReadOnlyListFile(str(fname))
        assert fname.exists()
        assert len(lst) == 0
        assert lst[0] is None
        assert lst() is None

    def test_reads_lines(self, tmp_path):
        fname = tmp_path / "list.txt"
        fname.write_text("one\n two \nthree\n")
        lst = ReadOnlyListFile(str(fname))
        assert len(lst) == 3
        assert lst[1] == "two"
        assert lst() == ["one", "two", "three"]
        fname.write_text("four\n")
        assert len(lst) == 1
        assert lst[0] == "four"

    def test_file_removed(self, tmp_path):
        fname = tmp_path / "list.txt"
        lst = ReadOnlyListFile(str(fname))
        os.unlink(fname)
        assert lst() is None
        assert len(lst) == 0

    def test_read_error(self, tmp_path, monkeypatch):
        fname = tmp_path / "list.txt"
        fname.write_text("x\n")
        lst = ReadOnlyListFile(str(fname))
        monkeypatch.setattr(listfile, "FileLock", _RaisingLock)
        with pytest.raises(RuntimeError):
            lst()


class TestReadOnlyListFileMtime:
    def test_creates_missing_file(self, tmp_path):
        fname = tmp_path / "list.txt"
        lst = ReadOnlyListFileMtime(str(fname))
        assert fname.exists()
        assert lst.fmtime == 0
        assert len(lst) == 0

    def test_first_read(self, tmp_path):
        fname = tmp_path / "list.txt"
        fname.write_text("a\nb\n")
        lst = ReadOnlyListFileMtime(str(fname))
        assert lst[1] == "b"
        assert lst.fmtime == os.path.getmtime(fname)

    def test_first_len(self, tmp_path):
        fname = tmp_path / "list.txt"
        fname.write_text("a\nb\n")
        assert len(ReadOnlyListFileMtime(str(fname))) == 2

    def test_empty_file_getitem(self, tmp_path):
        fname = tmp_path / "list.txt"
        fname.write_text("")
        assert ReadOnlyListFileMtime(str(fname))[0] is None

    def test_reread_after_change(self, tmp_path):
        fname = tmp_path / "list.txt"
        fname.write_text("a\n")
        lst = ReadOnlyListFileMtime(str(fname))
        assert lst[0] == "a"
        fname.write_text("b\nc\n")
        st = os.stat(fname)
        os.utime(fname, (st.st_atime, st.st_mtime + 10))
        assert len(lst) == 2

    def test_is_changed(self, tmp_path):
        fname = tmp_path / "list.txt"
        fname.write_text("a\n")
        lst = ReadOnlyListFileMtime(str(fname))
        assert lst.is_changed(str(fname)) is True
        assert lst.is_changed(str(fname)) is False
        st = os.stat(fname)
        os.utime(fname, (st.st_atime, st.st_mtime + 10))
        assert lst.is_changed(str(fname)) is True
        with pytest.raises(FileNotFoundError):
            lst.is_changed(str(tmp_path / "gone"))

    def test_read_info(self, tmp_path, monkeypatch):
        fname = tmp_path / "list.txt"
        fname.write_text("a\n")
        lst = ReadOnlyListFileMtime(str(fname))
        assert lst._read_info(str(fname)) == ["a"]
        assert lst._read_info(str(tmp_path / "gone")) is None
        monkeypatch.setattr(listfile, "FileLock", _RaisingLock)
        with pytest.raises(RuntimeError):
            lst._read_info(str(fname))

    def test_get_mtime_retries(self, tmp_path, monkeypatch):
        fname = tmp_path / "list.txt"
        fname.write_text("a\n")
        real = os.path.getmtime
        calls = {"n": 0, "sleep": []}

        def _getmtime(path):
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("busy")
            return real(path)

        monkeypatch.setattr(listfile.os.path, "getmtime", _getmtime)
        monkeypatch.setattr(listfile.time, "sleep", lambda s: calls["sleep"].append(s))
        assert ReadOnlyListFileMtime.get_mtime(str(fname)) == real(fname)
        assert calls["sleep"] == [1]

    @pytest.mark.xfail(
        strict=True,
        raises=UnboundLocalError,
        reason="BUG: storage/listfile.py:15-33 the list is kept in a local '_lst' and never "
        "stored on the instance; reading an unchanged file a second time raises "
        "UnboundLocalError",
    )
    def test_second_read_without_change(self, tmp_path):
        fname = tmp_path / "list.txt"
        fname.write_text("a\nb\n")
        lst = ReadOnlyListFileMtime(str(fname))
        assert lst[0] == "a"
        assert lst[1] == "b"

    @pytest.mark.xfail(
        strict=True,
        raises=UnboundLocalError,
        reason="BUG: storage/listfile.py:33-37 __len__ on an unchanged file raises "
        "UnboundLocalError ('_lst' is a local only set when the file changed)",
    )
    def test_len_twice(self, tmp_path):
        fname = tmp_path / "list.txt"
        fname.write_text("a\nb\n")
        lst = ReadOnlyListFileMtime(str(fname))
        assert len(lst) == 2
        assert len(lst) == 2


# ---------------------------------------------------------------------------
# ssl_context


@pytest.fixture(scope="module")
def cert_and_key(tmp_path_factory):
    d = tmp_path_factory.mktemp("tls")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    cert_file = d / "cert.pem"
    key_file = d / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(d), str(cert_file), str(key_file)


class TestSslContext:
    def test_lower_or_upper(self):
        assert ssl_context.lower_or_upper({"server_cert": "a"}, "SERVER_CERT") == "a"
        assert ssl_context.lower_or_upper({"SERVER_CERT": "b"}, "server_cert") == "b"
        assert ssl_context.lower_or_upper({}, "server_cert", "d") == "d"
        assert ssl_context.lower_or_upper({}, "server_cert") is None

    def test_no_cert(self, cert_and_key):
        d, _, key = cert_and_key
        assert ssl_context.create_context(d, {"server_key": key}) is None

    def test_no_key(self, cert_and_key):
        d, cert, _ = cert_and_key
        assert ssl_context.create_context(d, {"server_cert": cert}) is None

    def test_absolute_paths(self, cert_and_key):
        d, cert, key = cert_and_key
        ctx = ssl_context.create_context(
            "/nonexistent", {"server_cert": cert, "server_key": key}, protocol=ssl.PROTOCOL_TLS_SERVER
        )
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.verify_mode == ssl.CERT_NONE

    def test_relative_paths_upper_case(self, cert_and_key):
        d, _, _ = cert_and_key
        ctx = ssl_context.create_context(
            d, {"SERVER_CERT": "cert.pem", "SERVER_KEY": "key.pem"}, protocol=ssl.PROTOCOL_TLS_SERVER
        )
        assert isinstance(ctx, ssl.SSLContext)

    @pytest.mark.parametrize(
        "verify_user,mode", [("optional", ssl.CERT_OPTIONAL), ("required", ssl.CERT_REQUIRED)]
    )
    def test_verify_user(self, cert_and_key, verify_user, mode):
        d, cert, key = cert_and_key
        ctx = ssl_context.create_context(
            d,
            {
                "server_cert": cert,
                "server_key": key,
                "verify_user": verify_user,
                "ca_bundle": cert,
            },
            protocol=ssl.PROTOCOL_TLS_SERVER,
        )
        assert ctx.verify_mode == mode
        assert ctx.cert_store_stats()["x509"] == 1

    def test_verify_user_without_ca_bundle(self, cert_and_key):
        d, cert, key = cert_and_key
        ctx = ssl_context.create_context(
            d,
            {"server_cert": cert, "server_key": key, "verify_user": "required"},
            protocol=ssl.PROTOCOL_TLS_SERVER,
        )
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.cert_store_stats()["x509"] == 0

    def test_unknown_verify_user(self, cert_and_key):
        d, cert, key = cert_and_key
        with pytest.raises(SystemExit, match="Unknown verify_user"):
            ssl_context.create_context(
                d,
                {"server_cert": cert, "server_key": key, "verify_user": "maybe"},
                protocol=ssl.PROTOCOL_TLS_SERVER,
            )

    def test_missing_cert_file(self, cert_and_key, capsys):
        d, _, key = cert_and_key
        with pytest.raises(SystemExit, match="Missing cert or key"):
            ssl_context.create_context(
                d, {"server_cert": "nope.pem", "server_key": key}, protocol=ssl.PROTOCOL_TLS_SERVER
            )
        out = capsys.readouterr().out
        assert "cert_file:" + os.path.join(d, "nope.pem") in out
        assert "key_file:" + key in out
