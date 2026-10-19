"""Minimal libpam binding (ctypes) for password checks and account management.

Blocking: call through asyncio.to_thread().
"""

from __future__ import annotations

import ctypes
import ctypes.util
from ctypes import CFUNCTYPE, POINTER, Structure, byref, c_char_p, c_int, c_void_p

PAM_SUCCESS = 0
PAM_PROMPT_ECHO_OFF = 1
PAM_PROMPT_ECHO_ON = 2
PAM_ERROR_MSG = 3
PAM_TEXT_INFO = 4
PAM_SILENT = 0x8000
PAM_DISALLOW_NULL_AUTHTOK = 0x0001
PAM_RHOST = 4


class PamMessage(Structure):
    _fields_ = [("msg_style", c_int), ("msg", c_char_p)]


class PamResponse(Structure):
    _fields_ = [("resp", c_void_p), ("resp_retcode", c_int)]


CONV_FUNC = CFUNCTYPE(
    c_int, c_int, POINTER(POINTER(PamMessage)), POINTER(POINTER(PamResponse)), c_void_p
)


class PamConv(Structure):
    _fields_ = [("conv", CONV_FUNC), ("appdata_ptr", c_void_p)]


_libc = ctypes.CDLL(ctypes.util.find_library("c"))
_libc.calloc.restype = c_void_p
_libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
_libc.strdup.restype = c_void_p
_libc.strdup.argtypes = [c_char_p]

_libpam = None


def _pam():
    global _libpam
    if _libpam is None:
        name = ctypes.util.find_library("pam") or "libpam.so.0"
        lib = ctypes.CDLL(name)
        lib.pam_start.restype = c_int
        lib.pam_start.argtypes = [c_char_p, c_char_p, POINTER(PamConv), POINTER(c_void_p)]
        lib.pam_end.argtypes = [c_void_p, c_int]
        lib.pam_authenticate.argtypes = [c_void_p, c_int]
        lib.pam_acct_mgmt.argtypes = [c_void_p, c_int]
        lib.pam_set_item.argtypes = [c_void_p, c_int, c_void_p]
        lib.pam_strerror.restype = c_char_p
        lib.pam_strerror.argtypes = [c_void_p, c_int]
        _libpam = lib
    return _libpam


class PamError(Exception):
    def __init__(self, step: str, code: int, text: str):
        super().__init__(f"{step}: {text} ({code})")
        self.code = code


def _run(service: str, user: str, password: str | None, rhost: str | None, authenticate: bool):
    lib = _pam()
    secret = (password or "").encode()

    @CONV_FUNC
    def conv(n_messages, messages, p_response, _appdata):
        addr = _libc.calloc(n_messages, ctypes.sizeof(PamResponse))
        if not addr:
            return 5  # PAM_BUF_ERR
        responses = ctypes.cast(addr, POINTER(PamResponse))
        for i in range(n_messages):
            style = messages[i].contents.msg_style
            if style == PAM_PROMPT_ECHO_OFF:
                responses[i].resp = _libc.strdup(secret)
            elif style == PAM_PROMPT_ECHO_ON:
                responses[i].resp = _libc.strdup(user.encode())
        p_response[0] = responses
        return PAM_SUCCESS

    handle = c_void_p()
    conv_struct = PamConv(conv, None)
    rc = lib.pam_start(service.encode(), user.encode(), byref(conv_struct), byref(handle))
    if rc != PAM_SUCCESS:
        raise PamError("pam_start", rc, "cannot start PAM transaction")
    try:
        if rhost:
            lib.pam_set_item(handle, PAM_RHOST, ctypes.cast(c_char_p(rhost.encode()), c_void_p))
        if authenticate:
            rc = lib.pam_authenticate(handle, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK)
            if rc != PAM_SUCCESS:
                raise PamError("authenticate", rc, lib.pam_strerror(handle, rc).decode())
        rc = lib.pam_acct_mgmt(handle, PAM_SILENT)
        if rc != PAM_SUCCESS:
            raise PamError("account", rc, lib.pam_strerror(handle, rc).decode())
    finally:
        lib.pam_end(handle, rc)


def authenticate(service: str, user: str, password: str, rhost: str | None = None) -> None:
    """Password check plus account check. Raises PamError on failure."""
    _run(service, user, password, rhost, authenticate=True)


def account_ok(service: str, user: str, rhost: str | None = None) -> None:
    """Account check only (expiry, lock, access rules). Raises PamError on failure."""
    _run(service, user, None, rhost, authenticate=False)
