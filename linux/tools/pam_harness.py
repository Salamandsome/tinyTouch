#!/usr/bin/env python3
"""Run one PAM authentication, as an application would, and exit with its result.

    pam_harness.py SERVICE [--user NAME] [--confdir DIR] [--tty PATH]

With --confdir, libpam reads SERVICE's stack from DIR instead of /etc/pam.d
(pam_start_confdir), so a copy of a PAM file can be tried without changing /etc. Messages
(PAM_TEXT_INFO, PAM_ERROR_MSG) are printed; password prompts are answered from the terminal.
Exit status: the PAM result, 0 for success. Standard library only (pamtester is AUR-only).
"""

import argparse
import ctypes
import getpass
import os
import pwd
import sys

PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON, PAM_ERROR_MSG, PAM_TEXT_INFO = 1, 2, 3, 4
PAM_SUCCESS, PAM_CONV_ERR, PAM_BUF_ERR = 0, 19, 5
PAM_TTY = 3  # pam_set_item: what pam_exec exports as PAM_TTY


class Message(ctypes.Structure):
    _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]


class Response(ctypes.Structure):
    _fields_ = [("resp", ctypes.c_void_p), ("resp_retcode", ctypes.c_int)]


CONV_FUNC = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(Message)),
                             ctypes.POINTER(ctypes.POINTER(Response)), ctypes.c_void_p)


class Conversation(ctypes.Structure):
    _fields_ = [("conv", CONV_FUNC), ("appdata_ptr", ctypes.c_void_p)]


def load():
    """libpam and libc with the prototypes used here."""
    pam = ctypes.CDLL("libpam.so.0")
    libc = ctypes.CDLL("libc.so.6")
    libc.calloc.restype = ctypes.c_void_p
    libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    libc.strdup.restype = ctypes.c_void_p
    libc.strdup.argtypes = [ctypes.c_char_p]
    libc.free.restype = None
    libc.free.argtypes = [ctypes.c_void_p]
    handle = ctypes.c_void_p
    pam.pam_start_confdir.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                      ctypes.POINTER(Conversation), ctypes.c_char_p,
                                      ctypes.POINTER(handle)]
    pam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(Conversation),
                              ctypes.POINTER(handle)]
    pam.pam_set_item.argtypes = [handle, ctypes.c_int, ctypes.c_void_p]
    pam.pam_authenticate.argtypes = [handle, ctypes.c_int]
    pam.pam_end.argtypes = [handle, ctypes.c_int]
    pam.pam_strerror.argtypes = [handle, ctypes.c_int]
    pam.pam_strerror.restype = ctypes.c_char_p
    return pam, libc


def converse(libc, out=sys.stdout):
    """The conversation callback. libpam frees the responses, so they are malloc'd. An error
    in the callback must not escape into ctypes (it would return garbage to libpam): it is
    printed, what was allocated is freed, and libpam gets PAM_CONV_ERR."""
    def conv(count, messages, responses, appdata):
        replies = None
        try:
            replies = libc.calloc(count, ctypes.sizeof(Response))
            if not replies:
                return PAM_BUF_ERR
            array = ctypes.cast(replies, ctypes.POINTER(Response))
            for i in range(count):
                message = messages[i].contents  # Linux-PAM passes an array of pointers
                text = (message.msg or b"").decode("utf-8", "replace")
                if message.msg_style == PAM_PROMPT_ECHO_OFF:
                    answer = getpass.getpass(text)
                elif message.msg_style == PAM_PROMPT_ECHO_ON:
                    answer = input(text)
                else:
                    print(("error: " if message.msg_style == PAM_ERROR_MSG else "") + text,
                          file=out, flush=True)
                    continue
                array[i].resp = libc.strdup(answer.encode())
            responses[0] = array
            return PAM_SUCCESS
        except (Exception, KeyboardInterrupt) as exc:
            try:
                print(f"error: conversation failed ({type(exc).__name__})", file=sys.stderr,
                      flush=True)
            except Exception:
                pass
            if replies:
                array = ctypes.cast(replies, ctypes.POINTER(Response))
                for i in range(count):
                    if array[i].resp:
                        libc.free(array[i].resp)
                libc.free(replies)
            return PAM_CONV_ERR
    return CONV_FUNC(conv)


def authenticate(service: str, user: str, confdir: str | None, tty: str | None) -> int:
    pam, libc = load()
    callback = converse(libc)
    conversation = Conversation(callback, None)
    handle = ctypes.c_void_p()
    if confdir:
        result = pam.pam_start_confdir(service.encode(), user.encode(),
                                       ctypes.byref(conversation), confdir.encode(),
                                       ctypes.byref(handle))
    else:
        result = pam.pam_start(service.encode(), user.encode(), ctypes.byref(conversation),
                               ctypes.byref(handle))
    if result != PAM_SUCCESS:
        print(f"pam_start: {pam.pam_strerror(None, result).decode()} ({result})", flush=True)
        return result
    try:
        if tty:
            tty_name = ctypes.create_string_buffer(tty.encode())
            result = pam.pam_set_item(handle, PAM_TTY, ctypes.cast(tty_name, ctypes.c_void_p))
        if result == PAM_SUCCESS:
            result = pam.pam_authenticate(handle, 0)
        print(f"pam_authenticate: {pam.pam_strerror(handle, result).decode()} ({result})",
              flush=True)
        return result
    finally:
        pam.pam_end(handle, result)


def main(argv: list[str] | None = None) -> int:
    top = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    top.add_argument("service", help="PAM service name (a file in /etc/pam.d or --confdir)")
    top.add_argument("--user", default=pwd.getpwuid(os.getuid()).pw_name,
                     help="user to authenticate (default: you)")
    top.add_argument("--confdir", help="read the service from this directory, not /etc/pam.d")
    try:
        default_tty = os.ttyname(0)
    except OSError:
        default_tty = None
    top.add_argument("--tty", default=default_tty,
                     help="PAM_TTY to set (default: standard input's terminal, if any)")
    args = top.parse_args(argv)
    if args.confdir and not os.path.isfile(os.path.join(args.confdir, args.service)):
        top.error(f"{args.confdir} has no file {args.service}")
    return authenticate(args.service, args.user, args.confdir, args.tty)


if __name__ == "__main__":
    sys.exit(main())
