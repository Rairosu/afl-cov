import os
from typing import List, Optional, Tuple
from tempfile import NamedTemporaryFile
import argparse
import subprocess
from util import WANT_OUTPUT, LOG_ERRORS, logr


def run_in_background() -> None:
    # could use the python 'daemon' module, but it isn't always
    # installed, and we just need a basic backgrounding
    # capability anyway
    pid = os.fork()
    if pid < 0:
        print("[*] fork() error, exiting.")
        os._exit(1)
    elif pid > 0:
        os._exit(0)
    else:
        os.setsid()


def run_cmd(
    cmd: str,
    log_file: Optional[str],
    cargs: argparse.Namespace,
    collect: int,
    aflrun: bool,
    fn: str,
    timeout: Optional[int] = None,
) -> Tuple[int, List[bytes]]:
    out = []

    if cargs.disable_cmd_redirection or collect == WANT_OUTPUT or collect == LOG_ERRORS:
        fh = NamedTemporaryFile(delete=False)
    else:
        fh = open(os.devnull, "wb")

    if timeout:
        cmd = "timeout -s KILL %s %s" % (timeout, cmd)

    if aflrun is True and len(fn) > 0:
        cmd = "cat " + fn + " | " + cmd

    if cargs.verbose:
        if log_file:
            logr(b"    CMD: %s" % cmd.encode(errors="namereplace"), log_file, cargs)
        else:
            print("    CMD: %s" % cmd)

    exit_code = subprocess.call(
        cmd, stdin=None, stdout=fh, stderr=subprocess.STDOUT, shell=True
    )

    fh.close()

    if cargs.disable_cmd_redirection or collect == WANT_OUTPUT or collect == LOG_ERRORS:
        with open(fh.name, "rb") as f:
            for line in f:
                out.append(line.rstrip(b"\n"))
        os.unlink(fh.name)

    if (exit_code != 0) and (
        collect == LOG_ERRORS or (collect == WANT_OUTPUT and cargs.verbose)
    ):
        if log_file:
            logr(
                b"    Non-zero exit status '%d' for CMD: %s"
                % (exit_code, cmd.encode()),
                log_file,
                cargs,
            )
            for line in out:
                logr(b"    " + line, log_file, cargs)
        else:
            print("    Non-zero exit status '%d' for CMD: %s" % (exit_code, cmd))

    return exit_code, out
