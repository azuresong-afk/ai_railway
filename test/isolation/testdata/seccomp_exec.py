"""Запуск программы под профилем seccomp Docker через libseccomp (задача 5.47).

Тест изоляции aisec-media (test/isolation) проверяет профиль
deploy/compose/pilot/seccomp/aisec-media.json на живом процессе вне
контейнера: в облаке нет Docker и runc. Скрипт читает профиль, собирает
фильтр той же библиотекой libseccomp, что и runc, проверяет на себе, что
сетевой сокет запрещён, и заменяет себя программой (execve разрешён
профилем). Флаг no_new_privs libseccomp ставит сам.

Запуск: python3 -I seccomp_exec.py <профиль.json> <программа> [аргументы...]
Вывод в stderr: «seccomp: AF_INET errno=N» — итог проверки сокета.
"""

import ctypes
import ctypes.util
import errno
import json
import os
import socket
import sys

SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_KILL_PROCESS = 0x80000000


def scmp_act_errno(code):
    return 0x00050000 | (code & 0x0000FFFF)


# enum scmp_compare из seccomp.h.
COMPARE = {
    "SCMP_CMP_NE": 1,
    "SCMP_CMP_LT": 2,
    "SCMP_CMP_LE": 3,
    "SCMP_CMP_EQ": 4,
    "SCMP_CMP_GE": 5,
    "SCMP_CMP_GT": 6,
    "SCMP_CMP_MASKED_EQ": 7,
}


class ArgCmp(ctypes.Structure):
    # struct scmp_arg_cmp
    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_int),
        ("datum_a", ctypes.c_uint64),
        ("datum_b", ctypes.c_uint64),
    ]


def action(name, errno_ret, default_errno):
    if name == "SCMP_ACT_ALLOW":
        return SCMP_ACT_ALLOW
    if name == "SCMP_ACT_ERRNO":
        return scmp_act_errno(errno_ret if errno_ret is not None else default_errno)
    if name in ("SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS"):
        return SCMP_ACT_KILL_PROCESS
    raise SystemExit("seccomp: неизвестное действие " + name)


def main():
    if len(sys.argv) < 3:
        raise SystemExit("seccomp: нужны профиль и программа")
    with open(sys.argv[1], encoding="utf-8") as f:
        prof = json.load(f)
    path = ctypes.util.find_library("seccomp") or "libseccomp.so.2"
    lib = ctypes.CDLL(path, use_errno=True)
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint, ctypes.POINTER(ArgCmp)]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]

    default_errno = prof.get("defaultErrnoRet", errno.EPERM)
    ctx = lib.seccomp_init(action(prof["defaultAction"], None, default_errno))
    if not ctx:
        raise SystemExit("seccomp: seccomp_init")
    for rule in prof["syscalls"]:
        act = action(rule["action"], rule.get("errnoRet"), default_errno)
        args = rule.get("args") or []
        cmps = (ArgCmp * max(len(args), 1))()
        for i, a in enumerate(args):
            cmps[i] = ArgCmp(a["index"], COMPARE[a["op"]], a["value"], a.get("valueTwo", 0))
        for name in rule["names"]:
            nr = lib.seccomp_syscall_resolve_name(name.encode())
            if nr < 0:
                raise SystemExit("seccomp: неизвестный вызов " + name)
            rc = lib.seccomp_rule_add_array(ctx, act, nr, len(args), cmps)
            if rc != 0:
                raise SystemExit("seccomp: правило %s: %d" % (name, rc))
    rc = lib.seccomp_load(ctx)
    if rc != 0:
        raise SystemExit("seccomp: seccomp_load: %d" % rc)
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()
        print("seccomp: AF_INET errno=0", file=sys.stderr, flush=True)
    except OSError as e:
        print("seccomp: AF_INET errno=%d" % e.errno, file=sys.stderr, flush=True)
    os.execv(sys.argv[2], sys.argv[2:])


main()
