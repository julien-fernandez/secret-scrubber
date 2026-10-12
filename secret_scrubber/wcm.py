"""Lecture du Windows Credential Manager (générique) via ctypes — sans dépendance.

Permet au job planifié de charger un secret littéral connu (ex. la clé Ollama
stockée sous `MCP_OLLAMA_API_KEY`) pour le scrubber où qu'il apparaisse, quel que
soit son format. No-op hors Windows (retourne None).
"""
from __future__ import annotations

import sys

CRED_TYPE_GENERIC = 1


def read_credential(target: str) -> str | None:
    """Retourne le secret WCM générique nommé `target`, ou None s'il est absent.

    Le blob est décodé en UTF-16LE : c'est l'encodage utilisé pour écrire ces
    credentials (cf. profil PowerShell `Load-MCPSecrets`).
    """
    if sys.platform != "win32":
        return None

    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    cred_read = advapi32.CredReadW
    cred_read.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.POINTER(CREDENTIAL)),
    ]
    cred_read.restype = wintypes.BOOL
    cred_free = advapi32.CredFree
    cred_free.argtypes = [ctypes.c_void_p]

    ptr = ctypes.POINTER(CREDENTIAL)()
    if not cred_read(target, CRED_TYPE_GENERIC, 0, ctypes.byref(ptr)):
        return None
    try:
        cred = ptr.contents
        size = cred.CredentialBlobSize
        if size <= 0 or not cred.CredentialBlob:
            return None
        raw = ctypes.string_at(cred.CredentialBlob, size)
        return raw.decode("utf-16-le", errors="ignore")
    finally:
        cred_free(ptr)
