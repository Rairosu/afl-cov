from typing import Dict, Union, Optional
from shutil import rmtree
from argparse import Namespace
import sys
import os
import re
import errno

NO_OUTPUT = 0
WANT_OUTPUT = 1
LOG_ERRORS = 2

# id_min id_max are int, dirs is Dict, the rest is str or dict.
CovPathsDictType = Dict[str, Union[Dict[str, str], str, int]]
CovDictType = Dict[bytes, Dict[bytes, Dict[bytes, Dict[bytes, bytes]]]]


class CovPaths:
    def __init__(self, afl_fuzzing_dir):
        self.lcov_info_final = None
        self.id_file = None
        self.dirs = {}

        self.top_dir = "%s/cov" % afl_fuzzing_dir
        self.web_dir = "%s/web" % self.top_dir
        self.lcov_dir = "%s/lcov" % self.top_dir
        self.diff_dir = "%s/diff" % self.top_dir
        self.log_file = "%s/afl-cov.log" % self.top_dir

        # global coverage results
        self.id_delta_cov = "%s/id-delta-cov" % self.top_dir
        self.zero_cov = "%s/zero-cov" % self.top_dir
        self.pos_cov = "%s/pos-cov" % self.top_dir
        self.diff = ""
        self.id_file = ""
        self.id_min = -1  # used in --cover-corpus mode
        self.id_max = -1  # used in --cover-corpus mode

        # raw lcov files
        self.lcov_base = "%s/trace.lcov_base" % self.lcov_dir
        self.lcov_info = "%s/trace.lcov_info" % self.lcov_dir
        self.lcov_info_final = "%s/trace.lcov_info_final" % self.lcov_dir

        # if cargs.overwrite:
        #     mkdirs(self, cargs)
        # else:
        #     if is_dir(self.top_dir):
        #         if not cargs.func_search and not cargs.line_search:
        #             print(
        #                 "[*] Existing coverage dir %s found, use --overwrite to "
        #                 "re-calculate coverage" % (self.top_dir)
        #             )
        #             return False
        #     else:
        #         mkdirs(self, cargs)

    def setup(self, overwrite: bool):
        create_cov_dirs = False
        if is_dir(self.top_dir):
            if overwrite:
                rmtree(self.top_dir)
                create_cov_dirs = True
        else:
            create_cov_dirs = True

        if create_cov_dirs:
            for dir in [self.top_dir, self.web_dir, self.lcov_dir, self.diff_dir]:
                if not is_dir(dir):
                    os.mkdir(dir)

            # write coverage results in the following format
            cfile = open(self.id_delta_cov, "wb")
            if cargs.cover_corpus or cargs.coverage_at_exit:
                cfile.write(
                    b"# id:[range]..., cycle, src_file, coverage_type, fcn/line\n"
                )
            else:
                cfile.write(
                    b"# id:NNNNNN*_file, cycle, src_file, coverage_type, fcn/line\n"
                )
            cfile.close()

    def add_dir(self, fdir: str) -> None:
        self.dirs[fdir] = {}


class Cov:
    def __init__(self):
        pass


# credit:
# http://stackoverflow.com/questions/377017/test-if-executable-exists-in-python
def is_exe(fpath: str) -> bool:
    return os.path.isfile(fpath) and os.access(fpath, os.X_OK)


def is_dir(dpath: str) -> bool:
    return os.path.exists(dpath) and os.path.isdir(dpath)


def which(prog: str) -> Optional[str]:
    fpath, fname = os.path.split(prog)
    if fpath:
        if is_exe(prog):
            return prog
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, prog)
            if is_exe(exe_file):
                return exe_file
    return None


def append_file(pstr: bytes, path: str) -> None:
    f = open(path, "ab")
    f.write(b"%s\n" % pstr)
    f.close()


def logr(pstr: bytes, log_file: str, cargs: Namespace) -> None:
    if not cargs.background and not cargs.quiet:
        sys.stdout.buffer.write(b"    %s\n" % pstr)
    append_file(pstr, log_file)


def get_running_pid(stats_file: str, pid_re: bytes) -> Optional[int]:
    if not os.path.exists(stats_file):
        return None

    pid = None
    with open(stats_file, "rb") as f:
        for line in f:
            line = line.strip()
            m = re.search(pid_re, line)
            if m and m.group(1):
                is_running = int(m.group(1))
                try:
                    os.kill(is_running, 0)
                except OSError as e:
                    if e.errno == errno.EPERM:
                        pid = is_running
                else:
                    pid = is_running
                break
    return pid
