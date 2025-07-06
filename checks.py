import os
from argparse import Namespace
from util import WANT_OUTPUT, which, is_exe, is_dir, get_running_pid
from run import run_cmd
import time


def is_bin_gcov_enabled(binary: str, cargs: Namespace) -> bool:
    rv = False

    # run readelf against the binary to see if it contains gcov support
    for line in run_cmd(
        "%s -a %s" % (cargs.readelf_path, binary), None, cargs, WANT_OUTPUT, False, ""
    )[1]:
        if b" __gcov" in line:
            if cargs.validate_args or cargs.gcov_check or cargs.gcov_check_bin:
                print(
                    "[+] Binary '%s' is compiled with code coverage support via gcc."
                    % binary
                )
            rv = True
            break

        if b"__llvm_gcov" in line:
            if cargs.validate_args or cargs.gcov_check or cargs.gcov_check_bin:
                print(
                    "[+] Binary '%s' is compiled with code coverage support via llvm."
                    % binary
                )
            rv = True
            break

    if not rv and cargs.gcov_check_bin:
        print("[*] Binary '%s' is not compiled with code coverage support." % binary)

    return rv


def is_gcov_enabled(cargs: Namespace) -> bool:
    if not is_exe(cargs.readelf_path):
        print("[*] Need a valid path to readelf, use --readelf-path")
        return False

    if cargs.coverage_cmd:
        # make sure at least one component of the command is an
        # executable and is compiled with code coverage support

        found_exec = False
        found_code_cov_binary = False

        for part in cargs.coverage_cmd.split(" "):
            if not part or part[0] == " " or part[0] == "-":
                continue
            if which(part):
                found_exec = True
                if not cargs.disable_gcov_check and is_bin_gcov_enabled(part, cargs):
                    found_code_cov_binary = True
                    break

        if not found_exec:
            print(
                "[*] Could not find an executable binary "
                "--coverage-cmd '%s'" % cargs.coverage_cmd
            )
            return False

        if not cargs.disable_gcov_check and not found_code_cov_binary:
            print(
                "[*] Could not find an executable binary with code "
                "coverage support ('-fprofile-arcs -ftest-coverage') "
                "in --coverage-cmd '%s'" % cargs.coverage_cmd
            )
            return False

    elif cargs.gcov_check_bin:
        if not is_bin_gcov_enabled(cargs.gcov_check_bin, cargs):
            return False
    elif cargs.gcov_check:
        print(
            "[*] Either --coverage-cmd or --gcov-check-bin required in --gcov-check mode"
        )
        return False

    return True


def is_afl_fuzz_running(cargs):
    pid = None
    stats_file = cargs.afl_fuzzing_dir + "/fuzzer_stats"

    if os.path.exists(stats_file):
        pid = get_running_pid(stats_file, rb"fuzzer_pid\s+\:\s+(\d+)")
    else:
        for p in os.listdir(cargs.afl_fuzzing_dir):
            # stats_file = "%s/%s/fuzzer_stats" % (
            #    cargs.afl_fuzzing_dir.encode(),
            #    p.encode(),
            # )
            stats_file = "%s/%s/fuzzer_stats" % (cargs.afl_fuzzing_dir, p)
            if os.path.exists(stats_file):
                # allow a single running AFL instance in parallel mode
                # to mean that AFL is running (and may be generating
                # new code coverage)
                pid = get_running_pid(stats_file, rb"fuzzer_pid\s+\:\s+(\d+)")
                if pid:
                    break

    return pid


def do_gcno_files_exist(cargs: Namespace) -> bool:
    # make sure the code has been compiled with code coverage support,
    # so *.gcno files should exist
    found_code_coverage_support = False
    for root, dirs, files in os.walk(cargs.code_dir):
        for filename in files:
            if filename[-5:] == ".gcno":
                found_code_coverage_support = True
    if not found_code_coverage_support:
        print(
            "[*] Could not find any *.gcno files in --code-dir "
            "'%s', is code coverage ('-fprofile-arcs -ftest-coverage') "
            "compiled in?" % cargs.code_dir
        )
        return False
    return True
