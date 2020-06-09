#!/usr/bin/env python3
"""
Command-line program that hashes a directory or directory tree, file or files, or
a compressed archive file such as a tar or zip file.
Requires Python 3 with the pathlib package installed.
Python 3.4 and higher contains the pathlib module.

"""

import hashlib
import os
from datetime import datetime
import argparse
import sys
import re
import platform
from collections import Counter, deque
import glob
from pathlib import Path
import zipfile
import tarfile
from copy import deepcopy
import stat

__license__ = """
Copyright 2019 Christopher Corpora (pyhasher@gmail.com)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

__version__ = "2.7.4"

__author__ = "Chris Corpora"

KB = 2 ** 10
MB = KB * KB
GB = MB * KB
TB = GB * KB

# For command line arguments
NOT_SPECIFIED = "?"

# start of errors in output/logging
ERROR_START = "ERROR: "

ALL_FILES = "*"

ALGORITHMS = {'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'}

if os.name == 'nt':
    HIDDEN = stat.FILE_ATTRIBUTE_HIDDEN
    SYSTEM = stat.FILE_ATTRIBUTE_SYSTEM
elif os.name == 'posix':
    HIDDEN = stat.UF_HIDDEN
    SYSTEM = None

def get_file_attributes(fpath):
    """Get file attributes for directories or files"""
    return fpath.stat().st_file_attributes

def win_hidden_file(fpath):
    """Return True if directory of file path is hidden"""
    attrs = get_file_attributes(fpath)
    return (attrs & HIDDEN) == HIDDEN

def win_system_file(fpath):
    """Return True if directory of file path is a system file"""
    attrs = get_file_attributes(fpath)
    return (attrs & SYSTEM) == SYSTEM

def mac_hidden_file(fpath):
    """Simple checker for Mac, may not catch all hidden file"""
    return fpath.name.startswith('.')

def mac_system_file(fpath):
    """No 'system' files on macOS"""
    return False

if os.name == 'nt':
    hidden_file = win_hidden_file
    system_file = win_system_file
elif os.name == 'posix':
    hidden_file = mac_hidden_file
    system_file = mac_system_file

class Hasher:
    """
    Object to hash files and directories of files
    """

    algorithm = 'md5'

    # if file size is <= MAX_READ_SZ bytes, if will be read at once,
    # otherwise the file will be read with multiple read calls
    MAX_READ_SZ = 100 * MB
    READ_SZ = 32 * KB

    def __init__(self, algorithm=None, show_status=True):
        if algorithm and algorithm:
            if algorithm in ALGORITHMS:
                self.algorithm = algorithm
            elif algorithm is NOT_SPECIFIED:
                pass
            else:
                raise ValueError("{} hash is unknown".format(algorithm))
        self.hex_len = len(hashlib.new(self.algorithm).hexdigest())
        self.hashed = 0
        self.errors = 0
        self.total_files = 0
        self.total_bytes = 0
        self.current_file = None
        self.current_file_size = 0
        if show_status:
            self._hash_large = self._hash_large_status
        else:
            self._hash_large = self._hash_large_no_status

    def get_hash(self):
        """Return hash of a file"""
        with self.current_file.open('rb') as fin:
            if self.current_file_size >= self.MAX_READ_SZ:
                h = self._hash_large(fin)
            else:
                h = hashlib.new(self.algorithm, fin.read()).hexdigest()
        self.total_bytes += self.current_file_size
        return h

    def _hash_large_no_status(self, fin):
        """Return hash of files with sizes larger than max read size"""
        h = hashlib.new(self.algorithm)
        b = fin.read(self.READ_SZ)
        while b:
            h.update(b)
            b = fin.read(self.READ_SZ)
        return h.hexdigest()

    def _hash_large_status(self, fin):
        """Return hash of files with sizes larger than max read size"""
        h = hashlib.new(self.algorithm)
        status = StatusBar(fin.name, self.current_file_size)
        bytes_read = 0
        b = fin.read(self.READ_SZ)
        while b:
            bytes_read += self.READ_SZ
            h.update(b)
            #status.update(bytes_read)
            b = fin.read(self.READ_SZ)
        status.cleanup()
        return h.hexdigest()

    @staticmethod
    def match_fpath(fpath, fname_patterns):
        """Matches filename of fpath against list of filename patterns"""
        for p in fname_patterns:
            if fpath.match(p):
                return True
        return False

    def hash_file(self, fpath):
        """Hashes a file and returns the hash or an error message"""  
        self.total_files += 1
        try:
            # moved next two lines under try after getting FileNotFoundErrors on some files with long paths
            self.current_file = fpath
            self.current_file_size = fpath.stat().st_size
            h = self.get_hash()
            self.hashed += 1
        except (IOError, OSError, FileNotFoundError) as exc:
            self.errors += 1
            # format the error message to be the same length of the hash
            h = format("{}{}".format(ERROR_START, exc.strerror),
                       "<{}".format(self.hex_len))
            if len(h) > self.hex_len:
                h = h[:self.hex_len - 3] + "..."
        return h

    def hash_files(self, root, recurs, fname_patterns=None, ignore_directory=None, ignore_system=False, ignore_hidden=False):
        """Generator that returns a Path object and its hash or an error"""
        for startdir, dirs, fnames in os.walk(str(root)):
            dirpath = Path(startdir)
            if ((ignore_directory and dirpath.match(ignore_directory)) 
                or (ignore_system and system_file(dirpath)) 
                or (ignore_hidden and hidden_file(dirpath))):
                pass
            else:
                for fn in fnames:
                    fpath = dirpath / fn
                    if (ignore_system and system_file(fpath)) or (ignore_hidden and hidden_file(fpath)):
                        continue
                    elif (not fname_patterns) or self.match_fpath(fpath, fname_patterns):
                        yield self.hash_file(fpath), fpath
                if not recurs:
                    return


class TarHasher(Hasher):
    """Hashes individual members of a tarfile"""
    def __init__(self, algorithm=None):
        super().__init__(algorithm)
        self.archive = None

    def get_hash(self):
        """Return hash of a member of the archive"""
        f = self.archive.extractfile(self.current_file)
        if self.current_file_size >= self.MAX_READ_SZ:
            h = self._hash_large(f)
        else:
            h = hashlib.new(self.algorithm, f.read()).hexdigest()
        self.total_bytes += self.current_file_size
        return h

    def hash_file(self, member):
        """Hashes a member of the archive and returns the hash or an error message"""
        self.current_file = member
        try:
            self.current_file_size = member.size
        except AttributeError:
            self.current_file_size = member.file_size
        self.total_files += 1
        try:
            h = self.get_hash()
            self.hashed += 1
        except (IOError, OSError) as exc:
            self.errors += 1
            # format the error message to be the same length of the hash
            h = format("{}{}".format(ERROR_START, exc.strerror),
                       "<{}".format(self.hex_len))
            if len(h) > self.hex_len:
                h = h[:self.hex_len - 3] + "..."
        return h

    def hash_files(self, root, recurs=True, fname_patterns=None, **kwargs):
        """Generator that returns a Path object and its hash or an error"""
        self.archive = tarfile.open(root)
        for m in self.archive.getmembers():
            if m.isfile():
                p = Path(m.name)
                if fname_patterns:
                    if self.match_fpath(p, fname_patterns):
                        yield self.hash_file(m), p
                else:
                    yield self.hash_file(m), p


class ZipHasher(TarHasher):
    """Hashes individual members of a zip file"""
    def __init__(self, algorithm=None):
        super().__init__(algorithm)

    def get_hash(self):
        """Return hash of a member of a zip archive"""
        f = self.archive.open(self.current_file.filename)
        if self.current_file_size >= self.MAX_READ_SZ:
            h = self._hash_large(f)
        else:
            h = hashlib.new(self.algorithm, f.read()).hexdigest()
        self.total_bytes += self.current_file_size
        return h

    def hash_files(self, root, recurs=True, fname_patterns=None, **kwargs):
        """Generator that returns a Path object and its hash or an error"""
        self.archive = zipfile.ZipFile(str(root))
        for m in self.archive.infolist():
            fname = m.filename
            # will be a directory
            if fname.endswith("/") and m.file_size == 0:
                continue
            p = Path(fname)
            if (not fname_patterns) or self.match_fpath(p, fname_patterns):
                yield self.hash_file(m), p

ALG_HEX_LENGTHS = {'md5': 32, 'sha1': 40, 'sha224': 56, 'sha256': 64, 'sha384': 96, 'sha512': 128}

class Verifier(Hasher):
    """Verifies hashes from previously produced hashes"""

    # results of verifications
    HASH_MATCH = 1
    HASH_NO_MATCH = 0
    HASH_FILE_NOT_FOUND = -1
    HASH_READ_ERROR = -2

    def __init__(self, algorithm):
        super().__init__(algorithm)
        self.matching = 0
        self.non_matching = 0
        self.not_found = 0

    def verify_hash(self, old_hash, fpath):
        """Returns results of verification"""
        try:
            self.current_file = fpath.resolve()
            self.current_file_size = fpath.stat().st_size
            new_hash = self.get_hash()
        except FileNotFoundError:
            # count separately from other OSError exceptions
            self.not_found += 1
            res = self.HASH_FILE_NOT_FOUND
        # all other errors when reading
        except (IOError, OSError):
            self.total_files += 1
            self.errors += 1
            res = self.HASH_READ_ERROR
        else:
            self.total_files += 1
            self.hashed += 1
            # in case old hash is uppercase
            if new_hash == old_hash.lower():
                res = self.HASH_MATCH
                self.matching += 1
            else:
                res = self.HASH_NO_MATCH
                self.non_matching += 1
        return res

class StatusBar:
    """A status bar for hashing"""

    def __init__(self, fname, total_bytes, max_line_len=None, output=sys.stderr):
        # max length in characters of the progress bar line
        # min size in characters of the progress bar itself
        if not max_line_len:
            try:
                # (columns, lines)[0] = column length - 1 for \r at end
                self.max_line_len = os.get_terminal_size()[0] - 1
            except OSError:
                self.max_line_len = 50
        else:
            self.max_line_len = max_line_len
        self.output = output
        total_mb = total_bytes//2**20
        self.line = "Hashing {} ({:,} MB)".format(fname, total_mb)
        print(self.line, end='\r', file=self.output, flush=True)

    def cleanup(self):
        """Cleans up the line"""
        print(" "*(len(self.line)), end="\r", file=self.output)


BLANK_FIELD = ("", "")


class Header:
    def __init__(self, fields=None, start="", end=""):
        """Object to store header and format printing"""
        self.start = start
        if not fields:
            self.fields = deque()
        else:
            self.fields = fields
        self.end = end

    @property
    def _max_len(self):
        """Helps determine padding to align statements on each line"""
        return max([len(f[0]) for f in self.fields])

    @staticmethod
    def make_line(field, padding):
        """Format a line for printing"""
        return format(field[0], "<{}".format(padding)) + str(field[1])

    def __str__(self):
        to_pad = self._max_len
        res = [self.start, ""]
        for f in self.fields:
            res.append(self.make_line(f, to_pad))
        res.append("")
        if self.end:
            res.append(self.end)
            res.append("")
        return "\n".join(res)


class EndStats(Header):
    def __init__(self, fields=None, start="", end=""):
        """Object to store header and format printing"""
        super().__init__(fields, start, end)

    def __str__(self):
        to_pad = self._max_len
        res = ["", self.start, ""]
        for f in self.fields:
            res.append(self.make_line(f, to_pad))
        if self.end:
            res.append("")
            res.append(self.end)
        return "\n".join(res)


class Runner:
    """Generic program runner. Used as base class for HashRunner and VerifyRunner"""

    # use default local time and date display
    DATETIME_FORMAT = "%X %x"
    # characters to separate header and footer from hash values or results in
    # the output
    LOG_FILE_SEP = "=" * 60
    # formatting for automatic logfile
    LOGFILE_DT_FMT = "%Y-%m-%d_%H%M%S"
    MSG = "Running"
    DID_NOT_COMPLETE = "STOPPED, Did not complete"
    COMPLETED = "COMPLETED"
    LOGGING = "Logging Output: "

    def __init__(self, args):
        self.started = datetime.now()
        self.args = args
        self.completed = None
        self.total_secs = 0.0
        fname = "{{:{dt_fmt}}}.log".format(dt_fmt=self.LOGFILE_DT_FMT)
        self.output_default_filename = fname
        self.output_path = None
        self.output = None
        self.log = None
        self.header = Header(start=self.python_statement, end=self.LOG_FILE_SEP)
        self.end_stats = EndStats(start=self.LOG_FILE_SEP)

    @property
    def python_statement(self):
        ps = 'Python {} on {{}}'.format(platform.python_version())
        system = platform.system()
        if system == 'Darwin':
            res = ps.format('Mac OSX (version {})'.format(platform.mac_ver()[0]))
        else:
            elems = [system]
            if platform.release():
                elems.append(platform.release())
            elems.append('(version {})'.format(platform.version()))
            res = ps.format(' '.join(elems))
        return res

    def make_filename(self, fpath):
        """Create an output file name and return the full path"""
        if fpath.exists() and fpath.is_dir():
            fpath /= self.output_default_filename
        elif fpath.exists() and not self.args.overwrite:
            count = 1
            fn = fpath.stem
            ext = fpath.suffix
            while fpath.exists():
                fpath = fpath.parent / (fn + "({})".format(count) + ext)
                count += 1
        if not fpath.exists():
            fpath.touch()
        fpath = fpath.resolve()
        return fpath

    def create_output(self):
        """Resolve output to a file or standard out"""
        if not self.args.output:
            self.output = sys.stdout
            self.output_path = None
        else:
            if self.args.output is NOT_SPECIFIED:
                # if not specified, make it cwd
                fpath = Path(self.args.dirpath)
            else:
                fpath = Path(self.args.output)
            self.output_path = self.make_filename(fpath)
            self.output = self.output_path.open('w', encoding='utf-8')

    def make_logger(self):
        """Creates output logger"""

        def to_stdout(*to_print):
            try:
                print(*to_print, sep='')
            except UnicodeEncodeError:
                b = "".join(to_print).encode(sys.stdout.encoding, errors='replace')
                printable = b.decode(sys.stdout.encoding)
                print(printable)

        def to_logfile(*to_print, to_std=True):
            print(*to_print, sep='', file=self.output)
            if to_std:
                to_stdout(*to_print)

        if self.output == sys.stdout:
            return to_stdout
        else:
            return to_logfile

    def make_header(self):
        pass

    def print_header(self):
        self.make_header()
        print(self.header, file=sys.stderr)
        if self.args.log_header:
            self.log(self.header, to_std=False)

    def make_time_stats(self):
        if not self.completed:
            self.completed = datetime.now()
        self.total_secs = (self.completed - self.started).total_seconds()
        self.end_stats.fields.append(("Started:", self.started.strftime(self.DATETIME_FORMAT)))
        self.end_stats.fields.append(("Completed:", self.completed.strftime(self.DATETIME_FORMAT)))
        statement = "Time to Complete: "
        hours, secs = divmod(self.total_secs, 3600)
        mins, secs = divmod(secs, 60)
        hours = int(hours)
        mins = int(mins)
        total_time = "{:02}:{:02}:{:06.3f}".format(hours, mins, secs)
        self.end_stats.fields.append((statement, total_time))

    def make_end_stats(self):
        self.make_time_stats()

    def print_end_stats(self):
        self.make_end_stats()
        if self.output != sys.stdout:
            self.end_stats.end += 'Log File at "{}"'.format(self.output_path)
        if self.args.log_stats:
            self.log(self.end_stats, to_std=False)
        print(self.end_stats, file=sys.stderr)

    def setup(self):
        pass

    def main(self):
        """main logic of running the program"""
        pass

    def cleanup(self):
        if self.output != sys.stdout and not self.output.closed:
            self.output.flush()
            self.output.close()

    def run(self):
        """run setup main and cleanup, log headers and end stats"""
        self.setup()
        self.create_output()
        # create log function based on output selected
        self.log = self.make_logger()
        self.print_header()
        completed = False
        try:
            self.main()
            completed = True
        except Exception:
            raise
        finally:
            self.completed = datetime.now()
            if not completed:
                end_msg = self.DID_NOT_COMPLETE
            else:
                end_msg = self.COMPLETED
            self.end_stats.fields.append(("End Status: ", end_msg))
            self.end_stats.fields.append((BLANK_FIELD))
            self.print_end_stats()
            self.cleanup()

    def __call__(self):
        self.run()


class HashRunner(Runner):
    """Hash program runner"""

    # headings for output and to aid in verification from log files
    HASH_TYPE_START = "Hash Algorithm: "
    STARTING_DIRPATH = "Root Directory: "
    RECURSE_SUBDIR = "Include Subdirectories: "
    PATTERNS_TO_HASH = "Files Being Hashed: "

    # heading for directory paths in output
    DIRPATH_START = "DIRECTORY: "

    # characters to separate the hash value from the filename in the output
    SEP = "\x20" * 2
    # character to outline directory headings in output
    DIR_HEADING_SEP = "-"
    MSG = "Hashing"
    OUTPUT_EXT = ".pyh"

    def __init__(self, args):
        super().__init__(args)
        if self.args.algorithm is NOT_SPECIFIED:
            self.hasher = Hasher()
        else:
            self.hasher = Hasher(self.args.algorithm)
        self.first_startdir = self.args.dirpath
        # will use startdir to keep track of changes to the directory being hashed
        self.curdirpath = Path(self.first_startdir)
        self.output_default_filename = "{:{dt_fmt}}_{}{}".format(
            self.started,
            self.hasher.algorithm,
            self.OUTPUT_EXT,
            dt_fmt=self.LOGFILE_DT_FMT)
        if self.args.sep:
            self.sep = self.args.sep
        else:
            self.sep = self.SEP
        # for logging individual hashes and filenames or paths,
        # uses {{}} to specify literal {} for formatting later
        self.line_template = '{{:{padding}}}{sep}{{}}'.format(
            padding=self.hasher.hex_len,
            sep=self.sep)
        self.changed_curdirpath = False
        self.total_subdirs = 0
        if self.args.ignore_all:
            self.args.ignore_system = True
            self.args.ignore_hidden = True

    @property
    def python_statement(self):
        return "pyhasher {} - {}".format(__version__, super().python_statement)

    def log_curdirpath(self):
        """Creates heading containing starting directory for files listed below"""
        # get the relative path directory and convert backslashes to slashes
        # for compatibility on Posix systems
        elems = self.DIRPATH_START
        elems += self.curdirpath.relative_to(self.first_startdir).as_posix()
        sep = self.DIR_HEADING_SEP * len(elems)
        self.log()
        self.log(sep)
        self.log(elems)
        self.log(sep)

    def log_hash(self, h, fpath):
        if not self.args.headings:
            fn = fpath.relative_to(self.first_startdir).as_posix()
        else:
            fn = fpath.name
            if self.changed_curdirpath:
                self.log_curdirpath()
                self.changed_curdirpath = False
        self.log(self.line_template.format(h, fn))

    def make_header(self):
        self.header.fields.append((self.HASH_TYPE_START, self.hasher.algorithm))
        self.header.fields.append((self.STARTING_DIRPATH, self.args.dirpath))
        check = []
        if self.args.ignore_all:
            check.append("Ignore System (Windows) and Hidden Files")
        else:
            if self.args.ignore_hidden:
                check.append("Ignore Hidden Files")
            if self.args.ignore_system:
                check.append("Ignore System Files (Windows)")
        if self.args.patterns:
            s = "Only filenames matching: "
            _ = []
            for i in self.args.patterns:
                _.append("{!r}".format(i))
            check.append(s + ','.join(_))
        if not check:
            ans = "All Files Including Hidden and System Files/Directories"
        else:
            ans = ', '.join(check)
        self.header.fields.append((self.PATTERNS_TO_HASH, ans))
        if self.args.recursive:
            ans = 'Yes'
        else:
            ans = 'No'
        self.header.fields.append((self.RECURSE_SUBDIR, ans))
        if self.args.no_errors:
            ans = "Hashes Only, No Errors"
        else:
            ans = "Hashes and Errors"
        self.header.fields.append((self.LOGGING, ans))

    def make_hash_stats(self):
        self.end_stats.fields.append(("Total Files: ", "{:,}".format(self.hasher.total_files)))
        self.end_stats.fields.append(("Total Subdirectories: ", "{:,}".format(self.total_subdirs)))
        self.end_stats.fields.append(BLANK_FIELD)
        self.end_stats.fields.append(("Files Hashed: ", "{:,}".format(self.hasher.hashed)))
        self.end_stats.fields.append(("Read Errors: ", "{:,}".format(self.hasher.errors)))

    def make_time_stats(self):
        self.end_stats.fields.append(BLANK_FIELD)
        super().make_time_stats()
        try:
            statement = "{:,.2f}".format((self.hasher.total_bytes / 2 ** 20) / self.total_secs)
        except ZeroDivisionError:
            statement = "N/A"
        self.end_stats.fields.append(BLANK_FIELD)
        tb = self.hasher.total_bytes
        self.end_stats.fields.append(("Bytes Read: ", "{:,} ({:,.1f} GB)".format(tb, tb / GB)))
        self.end_stats.fields.append(("Avg. MB/Sec: ", statement))

    def make_end_stats(self):
        self.make_hash_stats()
        self.make_time_stats()

    def main(self):
        for h, fpath in self.hasher.hash_files(self.args.dirpath,
                                               recurs=self.args.recursive,
                                               fname_patterns=self.args.patterns,
                                               ignore_directory=self.args.ignore_directory,
                                               ignore_system=self.args.ignore_system,
                                               ignore_hidden=self.args.ignore_hidden):
            if fpath == self.output_path:
                self.hasher.total_files -= 1
                self.hasher.hashed -= 1
                self.hasher.total_bytes -= fpath.stat().st_size
            else:
                if fpath.parent != self.curdirpath:
                    self.total_subdirs += 1
                    self.curdirpath = fpath.parent
                    self.changed_curdirpath = True
                if self.args.no_errors and h.startswith(ERROR_START):
                    pass
                else:
                    self.log_hash(h, fpath)

class CompressedHashRunner(HashRunner):

    def __init__(self, cli_args):
        super().__init__(cli_args)
        self.curdirpath = None
        self.archpath = str(self.args.archive)
        if zipfile.is_zipfile(self.archpath):
            self.hasher = ZipHasher(self.hasher.algorithm)
        elif tarfile.is_tarfile(self.archpath):
            self.hasher = TarHasher(self.hasher.algorithm)
        else:
            raise ValueError("Not a ZIP or TAR file at {}".format(self.archpath))

    def log_curdirpath(self):
        """Creates heading containing starting directory for files listed below"""
        elems = self.DIRPATH_START
        elems += self.curdirpath.as_posix()
        sep = self.DIR_HEADING_SEP * len(elems)
        self.log()
        self.log(sep)
        self.log(elems)
        self.log(sep)

    def log_hash(self, h, fpath):
        if self.args.headings:
            fn = fpath.name
            if self.changed_curdirpath:
                self.log_curdirpath()
                self.changed_curdirpath = False
        else:
            fn = fpath
        self.log(self.line_template.format(h, fn))

    def make_header(self):
        self.header.fields.append((self.HASH_TYPE_START, self.hasher.algorithm.upper()))
        self.header.fields.append((self.STARTING_DIRPATH, self.args.dirpath))
        if not self.args.patterns:
            statement = "(ALL FILES)"
        else:
            statement = ", ".join(self.args.patterns)
        self.header.fields.append((self.PATTERNS_TO_HASH, statement))
        self.header.fields.append(("Archive File: ", self.args.archive))

    def main(self):
        try:
            for h, fpath in self.hasher.hash_files(self.archpath,
                                                   fname_patterns=self.args.patterns,
                                                   ignore_directory=self.args.ignore_directory):
                if fpath.parent != self.curdirpath:
                    self.total_subdirs += 1
                    self.curdirpath = fpath.parent
                    self.changed_curdirpath = True
                if self.args.no_errors and h.startswith(ERROR_START):
                    pass
                else:
                    self.log_hash(h, fpath)
            if self.hasher.total_files == 0:
                print(ERROR_START +
                      "No Files Found in Archive", file=sys.stderr)
        except (tarfile.ReadError, zipfile.BadZipfile):
            print(ERROR_START + "Error while reading archive file {}".format(self.archpath),
                  file=sys.stderr)

def infer_format(fpath, enc='utf-8'):
    """Tries to get formatting for hash file and return hash algorithm"""
    hex_lens = [i for i in ALG_HEX_LENGTHS.values()]
    min_len = min(hex_lens)
    max_len = max(hex_lens)
    hash_lengths = "{{{min_alg},{max_alg}}}".format(min_alg=min_len, max_alg=max_len)
    p = re.compile('([a-f0-9]{})(.*)$'.format(hash_lengths), re.IGNORECASE)
    with fpath.open('r', encoding=enc) as inputfile:
        max_read = 1000
        lines_read = 0
        len_found = []
        for line in inputfile:
            lines_read += 1
            m = p.match(line)
            if p.match(line):
                h, other = m.groups()
                len_found.append(len(h))
            if lines_read > max_read:
                break
    if len_found:
        h = None
        c = Counter(len_found).most_common()[0][0]
        for algname, alglen in ALG_HEX_LENGTHS.items():
            if alglen == c:
                return algname
    else:
        return None

class FailFastError(Exception):
    pass

class VerifyRunner(HashRunner):
    """Verification program runner"""

    # results of verifications and what is printed during verification
    HASH_MATCH_PRINT = "| MATCH |"
    HASH_NO_MATCH_PRINT = "! NO MATCH !"
    HASH_FILE_NOT_FOUND_PRINT = "<FILE NOT FOUND>"
    HASH_READ_ERROR_PRINT = "!!READ ERROR!!"

    RESULTS = {Verifier.HASH_MATCH: HASH_MATCH_PRINT,
               Verifier.HASH_NO_MATCH: HASH_NO_MATCH_PRINT,
               Verifier.HASH_FILE_NOT_FOUND: HASH_FILE_NOT_FOUND_PRINT,
               Verifier.HASH_READ_ERROR: HASH_READ_ERROR_PRINT}
    MSG = "Verifying"
    OUTPUT_EXT = ".txt"

    # default values for stipping off the file path after the hash value
    STRIP_SEP = HashRunner.SEP + "*"

    def __init__(self, args):
        super().__init__(args)
        # have already established that self.args.verifyfile exists
        # and is either a file or a directory
        # var for opened self.verifyfile
        self.inputfile = None
        if self.args.verifyfile.is_file():
            self.verifyfile = self.args.verifyfile.resolve()
        else:
            self.verifyfile = self.find_hashlog(self.args.verifyfile)
        # if it can't be found, stopped running the program, it will have to
        # specified
        if not self.verifyfile:
            raise FileNotFoundError(ERROR_START + "file for verification not found")
        if self.args.algorithm is NOT_SPECIFIED:
            try:
                algorithm = infer_format(self.verifyfile)
            except UnicodeDecodeError:
                algorithm = None
            if not algorithm:
                algorithm = self.get_algorithm()
            if algorithm:
                self.args.algorithm = algorithm
            else:
                raise ValueError("Cannot determine algorithm, please specify")
        self.sep = self.args.sep
        self.verifier = Verifier(self.args.algorithm)
        # need a self.hasher for inheritance
        self.hasher = self.verifier
        self.match_pattern = self.make_match_pattern()
        # self.curdirpath will change as the subdirectory being checked changes
        self.curdirpath = Path(self.args.dirpath).resolve()
        self.first_startdir = Path(self.args.dirpath)
        # for padding results of output to read easier, get the longest text
        # result to pad to
        self.result_padding = max([len(val) for val in self.RESULTS.values()]) + 2
        # build default filename
        fname = "{}_verify_".format(self.verifyfile.stem)
        fname += "{:{dt_fmt}}{}".format(self.started,
                                        self.OUTPUT_EXT,
                                        dt_fmt=self.LOGFILE_DT_FMT)
        self.output_default_filename = fname
        self.line_template = "{{:^{padding}}} {{}}".format(padding=self.result_padding)
        self.changed_curdirpath = False
        self.missing_subdirs = []

    def make_match_pattern(self):
        """Returns a regex pattern for hash values based on length of hex of the hash"""
        # use {{}} to create literal {}, separator must be escaped to work properly
        hex_len = len(hashlib.new(self.args.algorithm).hexdigest())
        hash_pat = "([a-f0-9]{{{pattern_len}}})(.*)$".format(pattern_len=hex_len)
        return re.compile(hash_pat, re.IGNORECASE)

    def make_header(self):
        self.header.fields.append((self.HASH_TYPE_START, self.hasher.algorithm.upper()))
        self.header.fields.append(("Verification Hashlog: ", self.verifyfile))
        self.header.fields.append((self.STARTING_DIRPATH, self.args.dirpath))
        if self.args.quiet:
            ans = "Non-matching and Errors Only"
        else:
            ans = "All (Matching, Non-matching, and Errors)"
        self.header.fields.append((self.LOGGING, ans))

    def make_hash_stats(self):
        """Returns hashing stats for end of output"""
        self.end_stats.fields.append(("Matched Hashes: ",
                                      "{:,}".format(self.verifier.matching)))
        self.end_stats.fields.append(("Non-Matching Hashes: ",
                                      "{:,}".format(self.verifier.non_matching)))
        self.end_stats.fields.append(("Files Not Found: ",
                                      "{:,}".format(self.verifier.not_found)))
        self.end_stats.fields.append(BLANK_FIELD)
        super().make_hash_stats()
        tmp = []
        for i in self.end_stats.fields:
            if i[0].startswith("Total Subdirectories: "):
                tmp.append(i)
                tmp.append(("Missing Subdirectories: ", "{:,}".format(len(self.missing_subdirs))))
            else:
                tmp.append(i)
        self.end_stats.fields = tmp

    def get_algorithm(self):
        """Returns None or algorithm based on algorithm in file name or file ext"""
        # make list of algorithm names with longest first to check
        long_algnames = sorted(ALGORITHMS)
        long_algnames.reverse()
        for algname in long_algnames:
            if self.verifyfile.suffix == HashRunner.OUTPUT_EXT and algname in self.verifyfile.stem:
                return algname
            elif algname in self.verifyfile.suffix:
                return algname
        return

    def find_hashlog(self, dirpath):
        """Find hashlogs in starting directory, return the most current"""
        hashlogs = []
        for fpath in dirpath.iterdir():
            f = None
            # if the hash algorithm is not specified look for all hash names
            if fpath.suffix == HashRunner.OUTPUT_EXT:
                f = fpath
            elif self.args.algorithm is NOT_SPECIFIED:
                for algname in ALGORITHMS:
                    # if one of the available algorithms is in the name
                    if algname in fpath.name.lower() and ('_verify_' not in fpath.name.lower()):
                        f = fpath
            elif not self.args.algorithm is NOT_SPECIFIED:
                if self.args.algorithm in fpath.suffix:
                    f = fpath
            else:
                pass
            if f:
                hashlogs.append(f)
        return get_most_recent(hashlogs)

    def parse_lines(self):
        """Returns the old hash and fpath or name from verification file, updates self.curdirpath"""
        path_pattern = re.compile(r'(\\)|/')
        hashes_found = 0
        for line in self.inputfile:
            m = self.match_pattern.match(line)
            if m:
                hashes_found += 1
                h, fn = m.groups()
                if not self.sep:
                    fn = fn.lstrip(self.STRIP_SEP)
                else:
                    fn = fn.split(self.sep)[-1]
                # check if it is filename or a relative path to a file
                if path_pattern.search(fn):
                    # fpath is a relative path and change it accordingly
                    fpath = (self.first_startdir / fn)
                    fn = fpath.name
                    # check if the current directory has changed since
                    # there are no directory headings to check
                    if fpath.parent != self.curdirpath:
                        self.curdirpath = fpath.parent
                        self.changed_curdirpath = True
                        self.total_subdirs += 1
                    else:
                        self.changed_curdirpath = False
                    yield h, self.curdirpath / fn
                else:
                    yield h, self.first_startdir / fn
            elif line.startswith(self.DIRPATH_START):
                rel_dirpath = line.split(self.DIRPATH_START)[1].rstrip()
                self.curdirpath = self.first_startdir / rel_dirpath
                self.changed_curdirpath = True
                self.total_subdirs += 1
            else:
                pass
        if hashes_found == 0:
            error_msg = "No '{}' hash values found in '{}'".format(self.args.algorithm,
                                                                   self.inputfile.name)
            print(ERROR_START + error_msg, file=sys.stderr)

    def verify_hashes(self):
        """Generator that yields result and file path from verification file"""
        for old_hash, fpath in self.parse_lines():
            verified = self.verifier.verify_hash(old_hash, fpath)
            if verified == Verifier.HASH_MATCH:
                if not self.args.quiet:
                    yield verified, fpath
            else:
                yield verified, fpath
                if self.args.fail_fast and verified == Verifier.HASH_NO_MATCH:
                    raise FailFastError("{}".format(fpath))

    def main(self):
        """Runs verification based on arguments passed at runtime"""
        if self.args.md5summer:
            enc = 'cp1252'
        else:
            enc = 'utf-8'
        with self.verifyfile.open('r', encoding=enc) as self.inputfile:
            for res, fpath in self.verify_hashes():
                if res == Verifier.HASH_FILE_NOT_FOUND:
                    if (not fpath.parent.exists()) and (not fpath.parent in self.missing_subdirs):
                        self.total_subdirs -= 1
                        self.missing_subdirs.append(fpath.parent)
                self.log_hash(self.RESULTS[res], fpath)


def get_most_recent(matching_filenames):
    """Returns most recently modified file as a Path object"""
    res = []
    for fpath in matching_filenames:
        p = Path(fpath).resolve()
        if p.is_file():
            file_mtime = p.lstat().st_mtime
            res.append((file_mtime, p))
    if res:
        return max(res)[1]
    else:
        return None

class ProgramRunnerCreator:

    def __init__(self, cli_args):
        self.cli_args = cli_args
        self.args = deepcopy(cli_args)
        self.program_runner = None

    def setup_logging(self):
        if self.cli_args.log_all:
            self.args.log_stats = True
            self.args.log_header = True

    def setup_dirpath(self):
        if self.cli_args.dirpath:
            dirpath = Path(self.cli_args.dirpath).resolve()
            error_msg = "Starting directory: {}, ".format(self.cli_args.dirpath)
            if dirpath.is_file():
                error_msg += "is a file and not a directory"
                raise ValueError(error_msg)
            elif not dirpath.exists():
                error_msg += "does not exist"
                raise FileNotFoundError("Starting directory: {} does not exist".format(error_msg))
            self.args.dirpath = dirpath
        else:
            self.args.dirpath = Path.cwd()

    def make_hash_runner(self):
        if not self.cli_args.patterns or (ALL_FILES in self.cli_args.patterns):
            self.args.patterns = None
        else:
            self.args.patterns = tuple(self.cli_args.patterns)
        if self.cli_args.archive:
            self.args.archive = Path(self.cli_args.archive).resolve()
            self.program_runner = CompressedHashRunner(self.args)
        else:
            self.program_runner = HashRunner(self.args)

    def setup_verifyfile(self):
        # setup self.args.verifyfile as Path object
        if self.cli_args.verifyfile is NOT_SPECIFIED:
            # set as a directory and will find later
            self.args.verifyfile = Path(self.args.dirpath)
        # else a verify file was specified, check filename using glob
        else:
            # try and resolve to an existing directory or file, then try it as a glob pattern
            try:
                self.args.verifyfile = Path(self.cli_args.verifyfile).resolve()
            except OSError:
                matches = glob.glob(self.cli_args.verifyfile)
                if not matches:
                    raise FileNotFoundError("{}".format(self.cli_args.verifyfile))
                else:
                    self.args.verifyfile = get_most_recent(matches)

    def make_verify_runner(self):
        self.setup_verifyfile()
        if self.cli_args.md5summer:
            self.args.sep = " *"
            self.args.algorithm = 'md5'
        self.program_runner = VerifyRunner(self.args)

    def make_runner(self):
        """Create a program runner based on args"""
        # if all files are specified as a pattern assign it None since don't need
        # to check pattern
        self.setup_dirpath()
        self.setup_logging()
        # Hashing
        if not self.cli_args.verifyfile:
            self.make_hash_runner()
        # Verification
        else:
            self.make_verify_runner()

def get_runner(cli_args):
    rc = ProgramRunnerCreator(cli_args)
    rc.make_runner()
    return rc.program_runner

# for CLI Help
HELP_PATTERNS = """
(Hashing Only) Filename pattern or patterns to hash. 
The default is all files in current directory. The patterns are 
not case-sensitive. Be sure to use double or single quotes as necessary
to avoid any unwanted expansion by the shell. For example, specifying 
*.jpg *.png without any quotes will be expanded by a Bash shell to all 
files in the current working directory that have those two extensions; 
if the program is running recursively, only those 
file names will match and all files will not be hashed. 
To hash all instances of jpg and png files in all 
subdirectories, specify the arguments as "*.jpg" "*.png" .
"""

HELP_CD = """
Change directory before running. Changes the current working directory path 
to DIR before running. This is done by Python while running this program and does not 
affect any other processes run after it.
"""

HELP_LOG_OUTPUT = """
Log output directly to FILE. This will avoid any encoding issues between 
the encoding that the shell is using and the output. This seems to only be a concern 
in Windows with Unicode file names. 
You can specify either FILE or a directory path (DIR). 
If no arguments are specified, a file will be created in the current 
working directory using a default filename. If only DIR is specified, 
a file will be created in that directory using a default filename. 
If FILE already exists, a number will be 
appended to the name to avoid ovewriting unless the --overwrite option is used.
"""

HELP_ARCHIVE = """
(Hashing Only) Hash the files contained within FILE which is a tarfile, 
compressed tarfile, or zip file archive. The archive is 
opened based on its extension. This option 
cannot be combined with --dirpath since the archive is 
the starting directory. This is not tested at this time.
"""

HELP_ALGORITHM = """
Hash algorithm to be used. You can only specify 
one. The default is "{}" for hashing.
On verification, if an algorithm is not specified, the program 
will attempt to infer the algorithm based on patterns
found at the start of each line.""".format(Hasher.algorithm)

HELP_RECURSIVE = """
(Hashing Only) Hash all files in all subdirectories. By default the 
program ignores subdirectories and files within.
"""

HELP_VERIFY = """
Will verify from FILE instead of hashing. The program 
will read hashes from FILE or it will look in 
DIR for a file extension that ends with the current 
hash algorithm name (for example "md5" or "pymd5"). If multiple 
files are found, the most recently modified file will be used.
"""

HELP_SEP = """
Use text SEP to separate the logged hash value and 
the filename or filepath. The default is two spaces on 
hashing. During verification, if 
SEP is not specified, the program will just automatically strip off
spaces or asterisks from the end of the hash. [This means file names with
spaces or asterisks at the start will not be resolved properly if they for
some reason exist at all]. If the separator does not contain spaces or 
asterisks then it will need to specified otherwise
the correct paths will not be located for the files.
Use quotes as necessary to avoid expansion or white space removal by 
the shell.
"""

HELP_MD5SUMMER = """
(Verifying Only) If the verification file was created by 
the program MD5summer, use this option to 
avoid text encoding and decoding errors on non-ASCII filenames.
"""

HELP_DIRPATH = """
Directory path to start hashing or verification, defaults to the 
current working directory. Does not change to as with -c/--change-dir 
option.
"""

HELP_LOG_HEADER = """
Includes the header in the output file. By default the header is 
only written to standard error.
"""

HELP_LOG_STATS = """
Includes the end stats in the output file. By default the end stats 
are only written to standard error.
"""

HELP_LOG_ALL = """
The same as specifying '--log-stats' with '--log-header'.
"""

HELP_NO_ERRORS = """
(Hashing Only) Output errors will not be logged 
inline with hashes. Errors are still counted, just 
not logged.
"""

HELP_HEADINGS = """
The relative path will not be logged for each file. 
The relative path to the directory containing the file will be logged once with 
the file names logged underneath.
"""

HELP_OVERWRITE = """
Overwrites any existing LOGFILE with the same name.
"""

HELP_QUIET = """
(Verification Only) Does not display matches on output. 
Only errors, files not found, and mismatches will be output.
"""

HELP_FAIL_FAST = """
(Verification Only) Stop running on first non-matching hash found.
"""

HELP_VERSION = """
Prints version to standard out and exits
"""

HELP_HASH_FILE = """
Hashes a specific file or files and prints the hash to standard output. No header or stats
are calculated, no log files are created. All other arguments except -a/--algorithm
are ignored. The hash is printed followed by the default separator and the file path or name
as it is supplied as an argument. If the full path was supplied, that will be printed.
"""

HELP_IGNORE_DIR = """
(Hashing Only) Does not hash any files in directory named, can be a full or relative path or just a directory 
name. If it is just a name then all directories encountered with that name will be ignored. You can also use wildcard
characters such as * and ? to match patterns. The argument "Videos*" with directories names "Videos_1" and "Videos_2" in 
any directory it is found (if recursive).
"""

HELP_IGNORE_HIDDEN = """
(Hashing Only) Does not hash any files that are considered hidden by the OS being used
"""

HELP_IGNORE_SYSTEM = """
(Hashing Only) Does not hash any files that are considered system files by the OS being used
"""

HELP_IGNORE_ALL = """
(Hashing Only) Sets both --ignore-hidden and --ignore-system options
"""

def make_args(arg_list=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--patterns', nargs='+', metavar='PATTERN',
                        help=HELP_PATTERNS)
    parser.add_argument('-V', '--verify', dest='verifyfile', nargs='?', const=NOT_SPECIFIED,
                        metavar='DIR|FILE', help=HELP_VERIFY)
    parser.add_argument('-c', '--change-dir', metavar='DIR',
                        help=HELP_CD)
    parser.add_argument('-o', '--output', nargs='?',
                        const=NOT_SPECIFIED, metavar='FILE|DIR',
                        help=HELP_LOG_OUTPUT)
    parser.add_argument('-a', '--algorithm',
                        metavar='|'.join(ALGORITHMS),
                        choices=ALGORITHMS, default=NOT_SPECIFIED,
                        help=HELP_ALGORITHM)
    parser.add_argument('-r', '--recursive', action='store_true',
                        help=HELP_RECURSIVE)
    parser.add_argument('--md5summer', action='store_true',
                        help=HELP_MD5SUMMER)
    parser.add_argument('--sep', metavar='SEP',
                        help=HELP_SEP)
    parser.add_argument('--log-header', action='store_true',
                        help=HELP_LOG_HEADER)
    parser.add_argument('--log-stats', action='store_true',
                        help=HELP_LOG_STATS)
    parser.add_argument('-L', '--log-all', action='store_true',
                        help=HELP_LOG_ALL)
    parser.add_argument('--no-errors', dest='no_errors', action='store_true',
                        help=HELP_NO_ERRORS)
    parser.add_argument('--headings', action='store_true',
                        help=HELP_HEADINGS)
    parser.add_argument('--overwrite', action='store_true',
                        help=HELP_OVERWRITE)
    parser.add_argument('--version', action='store_true',
                        help=HELP_VERSION)
    parser.add_argument('-q', '--quiet', action='store_true',
                        help=HELP_QUIET)
    parser.add_argument('--fail-fast', action='store_true',
                        help=HELP_FAIL_FAST)
    parser.add_argument('--ignore-directory',
                        help=HELP_IGNORE_DIR, metavar='DIR')
    parser.add_argument('--ignore-hidden', action='store_true',
                        help=HELP_IGNORE_HIDDEN)
    parser.add_argument('--ignore-system', action='store_true',
                        help=HELP_IGNORE_SYSTEM)
    parser.add_argument('--ignore-all', action='store_true',
                        help=HELP_IGNORE_ALL)
    files_dir_archive = parser.add_mutually_exclusive_group()
    files_dir_archive.add_argument('-d', '--dirpath', metavar='DIR',
                                   help=HELP_DIRPATH)
    files_dir_archive.add_argument('-A', '--archive', metavar='FILE',
                                   help=HELP_ARCHIVE)
    files_dir_archive.add_argument('-f', '--hash-file', metavar='FILE', nargs='+',
                                   help=HELP_HASH_FILE)
    if arg_list:
        args = parser.parse_args(arg_list)
    else:
        args = parser.parse_args()
    return args

def main(cli_args):
    if cli_args.version:
        print("pyhasher {}".format(__version__))
        sys.exit()
    elif cli_args.hash_file:
        for fn in cli_args.hash_file:
            fpath = Path(fn)
            if not fpath.exists():
                print("{}: Does not exist".format(fpath), file=sys.stderr)
            elif not fpath.is_file():
                if fpath.is_dir():
                    print("{}: Is a directory".format(fpath), file=sys.stderr)
                else:
                    print("{}: Is not a file".format(fpath), file=sys.stderr)
            else:
                h = Hasher(cli_args.algorithm)
                msg = "Hashing File: {}, size: {:,} bytes".format(fpath, fpath.stat().st_size)
                print(msg, end='\r', file=sys.stderr)
                f_hash = h.hash_file(fpath)
                print("{}".format(" "*len(msg)), end='\r', file=sys.stderr)
                print("{}{}{}".format(f_hash, HashRunner.SEP, fpath))
    else:
        try:
            if cli_args.change_dir:
                os.chdir(cli_args.change_dir)
            runner = get_runner(cli_args)
            runner()
        except (FailFastError, KeyboardInterrupt):
            pass
        except (ValueError,
                FileNotFoundError,
                IOError,
                OSError) as e:
            s = str(e.__class__).split()[1][1:-2]
            msg = "{}: {}".format(s, e)
            sys.exit(msg)

if __name__ == '__main__':
    CLI_ARGS = make_args()
    main(CLI_ARGS)
