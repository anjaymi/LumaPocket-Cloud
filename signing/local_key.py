"""Protect the local state key with Windows DPAPI for the current user."""
import ctypes
import os
import secrets
from pathlib import Path
from common import SigningError


def dpapi(data, decrypt=False):
    from ctypes import wintypes
    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    source = Blob(len(data), buffer)
    output = Blob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if decrypt:
        method = crypt32.CryptUnprotectData
        method.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                           ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        ok = method(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(output))
    else:
        method = crypt32.CryptProtectData
        method.argtypes = [ctypes.POINTER(Blob), ctypes.c_wchar_p, ctypes.c_void_p,
                           ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        ok = method(ctypes.byref(source), "LumaPocket personal signing", None, None, None, 1, ctypes.byref(output))
    if not ok:
        raise SigningError("local_key_protection_failed")
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree(output.pbData)


def state_key(home, create=False):
    path = Path(home) / ("key.dpapi" if os.name == "nt" else "key")
    if path.is_file():
        data = path.read_bytes()
        return (dpapi(data, decrypt=True) if os.name == "nt" else data).decode()
    if not create:
        raise SigningError("local_authorization_key_missing")
    value = secrets.token_urlsafe(48)
    path.write_bytes(dpapi(value.encode()) if os.name == "nt" else value.encode())
    if os.name != "nt":
        path.chmod(0o600)
    return value
