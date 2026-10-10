#!/usr/bin/env python3
import ctypes
import ctypes.util
import errno
import hashlib
import os
import stat
import sys

IS_LINUX = sys.platform.startswith("linux")

if not IS_LINUX:
    _LIBC = ctypes.CDLL(ctypes.util.find_library("c") or "libSystem.dylib", use_errno=True)
    _LIBC.getxattr.restype = ctypes.c_ssize_t


def named_xattr_state(path, name=b"security.capability"):
    # Return one of: ("absent", None), ("present", raw), or raise OSError on an
    # API error so the caller can classify a probe failure rather than an
    # absence. On Linux the stdlib os.* are the authoritative syscall wrappers;
    # elsewhere a libc getxattr call is used (same classification; the host is
    # only exercised for fault/error taxonomy tests).
    if IS_LINUX:
        raw = os.getxattr(path, name)
        return ("present", raw)
    lbuf = ctypes.create_string_buffer(name)
    pbuf = ctypes.c_char_p(os.fsencode(path))
    size = _LIBC.getxattr(pbuf, lbuf, None, 0, 0, 0)
    if size < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    if size == 0:
        return ("absent", None)
    buf = ctypes.create_string_buffer(size)
    got = _LIBC.getxattr(pbuf, lbuf, buf, size, 0, 0)
    if got < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ("present", buf.raw[:got])


def classify_error(kind, detail, code):
    sys.stderr.write("metadata-probe %s: %s\n" % (kind, detail))
    return code


_MISSING_XATTR_ERRNOS = [errno.ENODATA]
if hasattr(errno, "ENOATTR"):
    _MISSING_XATTR_ERRNOS.append(errno.ENOATTR)


def _missing_xattr(err):
    return err in _MISSING_XATTR_ERRNOS


def main():
    if len(sys.argv) not in (2, 3):
        return classify_error("usage", "expected path [expected_sha256]", 2)
    path = sys.argv[1]
    expected = sys.argv[2] if len(sys.argv) == 3 else None
    try:
        st = os.stat(path)
    except OSError as exc:
        return classify_error("stat-error", "%s: %s" % (path, exc), 2)
    if not stat.S_ISREG(st.st_mode):
        return classify_error("nonregular", "not a regular file: %s" % path, 2)
    # The ordinary-nonsetid applicability proof is void for a setid executable,
    # so a setuid/setgid mode bit is rejected here (unr B4), never merely
    # reported alongside a passed probe.
    if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
        return classify_error(
            "setid", "setid mode rejected (not ordinary non-setid): %s mode=%s" % (path, oct(stat.S_IMODE(st.st_mode))), 5
        )
    present = False
    has_xattr_api = False
    try:
        present = named_xattr_state(path)[0] == "present"
        has_xattr_api = True
    except OSError as exc:
        if not _missing_xattr(exc.errno):
            return classify_error("xattr-api-error", "%s: %s" % (path, exc), 3)
        has_xattr_api = True
        present = False
    mode = oct(stat.S_IMODE(st.st_mode))
    with open(path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    if expected is not None and digest != expected:
        return classify_error("digest-mismatch", "%s: %s != expected %s" % (path, digest, expected), 4)
    state = "present" if present else "absent"
    sys.stdout.write(
        "metadata: path=%s mode=%s security.capability=%s xattr_api=%s sha256=%s\n"
        % (path, mode, state, "ok" if has_xattr_api else "unavailable", digest)
    )
    return 0 if not present else 1


if __name__ == "__main__":
    sys.exit(main())
