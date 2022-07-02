import unittest
import tempfile
import os
import sys
import shutil
import random
import hashlib
from pathlib import Path
import stat
import pyhasher
from pyhasher import Hasher, Verifier, HashRunner, VerifyRunner, TarHasher, ZipHasher

# tests data can be downloaded as a tgz archive
# from downloads section of pyhasher project on bitbucket
DATA_DIRPATH = Path("tests").resolve()
TEMP_DIRPATH = Path(tempfile.mkdtemp()).resolve()

def sendToDevNull(func, *args, **kwargs):
    stdout = sys.stdout
    stderr = sys.stderr
    with open(os.devnull, 'w') as nullout:
        sys.stdout = nullout
        sys.stderr = nullout
        try:
            res = func(*args, **kwargs)
        except Exception:
            raise
        finally:
            sys.stdout = stdout
            sys.stderr = stderr
    return res

class TestHashingKnown(unittest.TestCase):
    """
    Testing known values from https://www.nsrl.nist.gov/testdata/
    """
    data = b'abc'
    fpath = TEMP_DIRPATH / 'smalldatafile'
    
    def _testAlgorithm(self, algorithm, knownHash):
        h = hashlib.new(algorithm, self.data).hexdigest()
        self.assertEqual(h, knownHash)
        
    def _testAlgorithmFile(self, algorithm, knownHash):
        if self.fpath.exists():
            pass
        else:
            with self.fpath.open('wb') as fout:
                fout.write(self.data)
        hasher = Hasher(algorithm)
        h = hasher.hash_file(self.fpath)
        self.assertEqual(h, knownHash)
    
    def testSHA1(self):
        self._testAlgorithm('sha1', 'a9993e364706816aba3e25717850c26c9cd0d89d')
        
    def testMD5(self):
        self._testAlgorithm('md5', '900150983cd24fb0d6963f7d28e17f72')
        
    def testSHA256(self):
        self._testAlgorithm('sha256', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        
    def testSHA1File(self):
        self._testAlgorithmFile('sha1', 'a9993e364706816aba3e25717850c26c9cd0d89d')
        
    def testMD5File(self):
        self._testAlgorithmFile('md5', '900150983cd24fb0d6963f7d28e17f72')
        
    def testSHA256File(self):
        self._testAlgorithmFile('sha256', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        
        
class TestHashingKnownLarger(TestHashingKnown):
    """
    Testing known values from https://www.nsrl.nist.gov/testdata/
    """
    data = b'a'*(10**6)
    fpath = TEMP_DIRPATH / 'largerdatafile'
    
    def testSHA1(self):
        self._testAlgorithm('sha1', '34aa973cd4c4daa4f61eeb2bdbad27316534016f')
        
    def testMD5(self):
        self._testAlgorithm('md5', '7707d6ae4e027c70eea2a935c2296f21')
        
    def testSHA256(self):
        self._testAlgorithm('sha256', 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0')
        
    def testSHA1File(self):
        self._testAlgorithmFile('sha1', '34aa973cd4c4daa4f61eeb2bdbad27316534016f')
        
    def testMD5File(self):
        self._testAlgorithmFile('md5', '7707d6ae4e027c70eea2a935c2296f21')
        
    def testSHA256File(self):
        self._testAlgorithmFile('sha256', 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0')
        
def makeFile(fpath, data, algorithm='md5'):
    """Create file for testing at specified file path of specified size and returns hash as hexdigest"""
    with fpath.open('wb') as fout:
        fout.write(data)
    return hashlib.new(algorithm, data).hexdigest()

def makeTestFiles(dirpath, fname_template=None, count=None, sizes=None, algorithm='md5'):
    """Create files for testing and returns a list containing hashes and filenames"""
    if not fname_template:
        fname_template = "testfile_{0:02}"
    hashlist = []
    if not count and sizes:
        count = len(sizes)
    elif not count and not sizes:
        count = random.randint(1, 20)
    if not sizes:
        sizes = [random.randrange(25, 2000, 100) for i in range(count)]
    # only create random tests once at max size and write out slices of tests for each size
    max_sz = max(sizes)
    data = memoryview(os.urandom(max_sz))
    for i in range(count):
        # use in case len(sizes) > 
        sz = sizes[i % len(sizes)]
        fname = fname_template.format(i)
        fpath = dirpath / fname
        hashlist.append((fname, makeFile(fpath, data[:sz], algorithm)))
    return hashlist

class TestHasher(unittest.TestCase):
    def setUp(self):
        self.hasher = Hasher('md5')

    def testHashingRandom(self):
        """Test that files are being read and hashed correctly"""
        dirpath = TEMP_DIRPATH / 'Random Test'
        dirpath.mkdir()
        testsizes = [0,
                     1,
                     Hasher.READ_SZ - 1,
                     Hasher.READ_SZ,
                     Hasher.READ_SZ + 1,
                     Hasher.MAX_READ_SZ - 1,
                     Hasher.MAX_READ_SZ,
                     Hasher.MAX_READ_SZ + 1,
                     Hasher.MAX_READ_SZ - (Hasher.READ_SZ + 1),
                     Hasher.MAX_READ_SZ - Hasher.READ_SZ,
                     Hasher.MAX_READ_SZ + (Hasher.READ_SZ - 1),
                     Hasher.MAX_READ_SZ + 1,
                     Hasher.MAX_READ_SZ + pyhasher.MB + 29]        
        random_hashlist = makeTestFiles(dirpath, sizes=testsizes)
        hashlist = []
        for item in random_hashlist:
            fname = item[0]
            self.hasher.current_file = dirpath / fname
            self.hasher.current_file_size = self.hasher.current_file.stat().st_size
            h = self.hasher.get_hash()
            hashlist.append((fname, h))
        for i in hashlist:
            self.assertTrue(i in random_hashlist)
        shutil.rmtree(str(dirpath))

    def makeDirs(self, root):
        dirs = ['Dir_1', 'Dir_2', 'Dir_3']
        subdirs1 = ['SubDir_1', 'SubDir_2', 'SubDir_3']
        subdirs2 = ['SubSubDir_1', 'SubSubDir_2']
        dirpaths = []
        for d in dirs:
            dirpath = root / d
            dirpaths.append(dirpath)
            dirpath.mkdir()
            for subd1 in subdirs1:
                subdirpath1 = dirpath / subd1
                dirpaths.append(subdirpath1)
                subdirpath1.mkdir()
                for subd2 in subdirs2:
                    subdirpath2 = subdirpath1 / subd2
                    dirpaths.append(subdirpath2)
                    subdirpath2.mkdir()
        return dirpaths

    def makeFilesBinAndDat(self, dirpaths, min_files=1, max_files=5):
        dat_count = 0
        bin_count = 0
        all_fpaths = []
        b = b'\xFF\x00\xFF\x01\xFF\x02'
        h = hashlib.new(self.hasher.algorithm, b).hexdigest()
        for d in dirpaths:
            for i in range(random.randint(min_files, max_files)):
                if i % 2 == 0:
                    fpath = d / "{:010}.dat".format(i)
                    dat_count += 1
                else:
                    fpath = d / "{:010}.bin".format(i)
                    bin_count += 1
                with fpath.open('wb') as fout:
                    fout.write(b)
                all_fpaths.append((h, fpath))
        return dat_count, bin_count, all_fpaths

    def testHashFilesRecursivelyNoPattern(self):
        """Hash all files recursively (no filename pattern specified)"""
        root = TEMP_DIRPATH / "Recursive Test"
        root.mkdir()
        dir_list = self.makeDirs(root)
        item  = self.makeFilesBinAndDat(dir_list)
        all_fpaths = item[2]
        retrieved_fpaths = []
        for h, fpath in self.hasher.hash_files(root, recurs=True):
            retrieved_fpaths.append((h, fpath))
        for res in all_fpaths:
            self.assertTrue(res in retrieved_fpaths)
        shutil.rmtree(str(root))

    def testHashFilesRecursivelyWithPattern(self):
        """Hash files recursively with a filename pattern specified"""
        root = TEMP_DIRPATH / "Recursive Pattern Test"
        root.mkdir()
        dir_list = self.makeDirs(root)
        item  = self.makeFilesBinAndDat(dir_list)
        bin_count = item[1]
        all_fpaths = item[2]
        retrieved_fpaths = []
        fname_patterns = ["*.bin"]
        for h, fpath in self.hasher.hash_files(root, recurs=True, fname_patterns=fname_patterns):
            retrieved_fpaths.append((h, fpath))
        self.assertEqual(len(retrieved_fpaths), bin_count)
        for res in all_fpaths:
            fname = res[1].name
            if fname.endswith(".dat"):
                pass
            else:
                self.assertTrue(res in retrieved_fpaths)
        shutil.rmtree(str(root))

    def testHashFileNonRecursively(self):
        """Hash files in root directory only"""
        root = TEMP_DIRPATH / "Non Recursive Test"
        root.mkdir()
        item = self.makeFilesBinAndDat([root], min_files=10, max_files=50)
        all_filepaths = item[2]
        retrieved_fpaths = []
        self.hasher.recursive = False
        for h, fpath in self.hasher.hash_files(root, recurs=False, fname_patterns=None):
            retrieved_fpaths.append((h, fpath))
        for res in all_filepaths:
            self.assertTrue(res in retrieved_fpaths)

    def testHashFileNoDir(self):
        """Hashes Files from Directory that doesn't exist"""
        root = Path("/Users/UserThatDoesNotExist")
        if root.exists():
            raise AssertionError("'{}' Directory Exists, Could not run test".format(root))
        else:
            retrieved_fpaths = []
            for h, fpath in self.hasher.hash_files(root, recurs=True, fname_patterns=None):
                retrieved_fpaths.append((h, fpath))
            self.assertEqual([], retrieved_fpaths)
            
    def testDotFiles(self):
        """Test that files that start with '.' and being found and hashed"""
        root = TEMP_DIRPATH / "Dot Files"
        root.mkdir()
        known_hashlist = makeTestFiles(root, fname_template=".testfile{:02}", count=10)
        hashed = [item for item in self.hasher.hash_files(root, True)]
        self.assertEqual(len(hashed), len(known_hashlist))
        for fname,hash_ in known_hashlist:
            item = (hash_, root / fname)
            self.assertTrue(item in hashed) 
            
class TestTarHasher(unittest.TestCase):
    def setUp(self):
        self.hash_alg = 'md5'
        self.hasher = TarHasher(self.hash_alg)
        self.root = DATA_DIRPATH / 'Archives/tar_data.tgz'
        
    def testHashing(self):
        results = set()
        knowns = ["6e2d34590930731623d4c98e384bd4ca",
                  "8c01b9eac85f153dffd05cd35f535a39",
                  "e76de7333d139e7df894b1d946f0c15d",
                  "6e2d34590930731623d4c98e384bd4ca"]
        for item in self.hasher.hash_files(str(self.root)):
            results.add(item[0])
        for h in knowns:
            self.assertTrue(h in results)
        
class TestZipHasher(unittest.TestCase):
    def setUp(self):
        self.hash_alg = 'md5'
        self.hasher = ZipHasher(self.hash_alg)
        self.root = DATA_DIRPATH / 'Archives/zipped_data.zip'
        
    def testHashing(self):
        results = set()
        knowns = ["6e2d34590930731623d4c98e384bd4ca",
                  "8c01b9eac85f153dffd05cd35f535a39",
                  "e76de7333d139e7df894b1d946f0c15d",
                  "6e2d34590930731623d4c98e384bd4ca"]
        for item in self.hasher.hash_files(str(self.root)):
            results.add(item[0])
        for h in knowns:
            self.assertTrue(h in results)

class TestVerifier(unittest.TestCase):
    def setUp(self):
        self.hash_alg = 'md5'
        self.verifier = Verifier(self.hash_alg)

    def testResultNoMatch(self):
        old_hash = 'ff2d34590930731623d4c98e384bd4ca'
        dirpath = DATA_DIRPATH / 'Contains 3 Files'
        fname = 'Random Data.dat'
        fpath = dirpath / fname
        res = self.verifier.verify_hash(old_hash, fpath)
        self.assertEqual(Verifier.HASH_NO_MATCH, res)

    def testResultMatch(self):
        dirpath = DATA_DIRPATH / 'Contains 3 Files'
        md5_hash, fname = '6e2d34590930731623d4c98e384bd4ca', 'Random Data.dat'
        fpath = dirpath / fname
        res = self.verifier.verify_hash(md5_hash, fpath)
        self.assertEqual(Verifier.HASH_MATCH, res)

    def testResultFileNotFound(self):
        dirpath = DATA_DIRPATH / 'Contains 3 Files'
        fname = 'Random Data Not In Directory.dat'
        fpath = dirpath / fname
        res = self.verifier.verify_hash('6e2d34590930731623d4c98e384bd4ca', fpath)
        self.assertEqual(Verifier.HASH_FILE_NOT_FOUND, res)


class CLIArgs:
    """Default arguments for command line"""

    def __init__(self):
        self.patterns = None
        self.dirpath = None
        self.output = None
        self.no_log_file = False
        self.algorithm = pyhasher.NOT_SPECIFIED
        self.recursive = False
        self.verifyfile = None
        self.md5summer = False
        self.sep = None
        self.log_stats = False
        self.log_header = False
        self.no_errors = False
        self.headings = False
        self.log_all = None
        self.use_verify_dir = False
        self.overwrite = False
        self.change_dir = None
        self.quiet = False
        self.archive = None
        self.fail_fast = False
        self.hash_file = None
        self.version = None
        self.ignore_directory = None
        self.ignore_hidden = False
        self.ignore_system = False
        self.ignore_all = False

    def __str__(self):
        s = []
        for k in self.__dict__:
            s.append("{}: {}".format(k, self.__dict__[k]))
        return "\n".join(s)


class TestMakeRunner(unittest.TestCase):
    def setUp(self):
        self.args = CLIArgs()

    def testHRInstance(self):
        runner = pyhasher.get_runner(self.args)
        self.assertTrue(isinstance(runner, HashRunner))

    def testHRCWD(self):
        hrunner = pyhasher.get_runner(self.args)
        self.assertEqual(hrunner.args.dirpath, Path.cwd())

    def testHRValueError(self):
        p = TEMP_DIRPATH / 'testfile'
        p.touch()
        self.args.dirpath = str(p)
        self.assertRaises(ValueError, pyhasher.get_runner, self.args)

    def testHRFileNotFoundError(self):
        p = TEMP_DIRPATH / 'No Directory By This Name'
        if p.exists():
            raise AssertionError("{} directory exists, cannot run test".format(p))
        self.args.dirpath = str(p)
        self.assertRaises(FileNotFoundError, pyhasher.get_runner, self.args)

    def testVRCreateError(self):
        startdir = Path(TEMP_DIRPATH / 'No Files')
        startdir.mkdir()
        self.args.dirpath = str(startdir)
        self.args.verifyfile = pyhasher.NOT_SPECIFIED
        self.assertRaises(FileNotFoundError, pyhasher.get_runner, self.args)

    def testVRCreate(self):
        # will throw an error if no verification file present when instantiated
        root = TEMP_DIRPATH / 'One Hash Log'
        root.mkdir()
        hlog_path = root / 'hashes.md5'
        hlog_path.touch()
        self.args.verifyfile = str(root)
        runner = pyhasher.get_runner(self.args)
        self.assertTrue(isinstance(runner, VerifyRunner))


class TestHashRunner(unittest.TestCase):
    def setUp(self):
        self.args = CLIArgs()

    def testHROutputFile(self):
        self.args.dirpath = str(DATA_DIRPATH / 'Contains 3 Files')
        output_dir = TEMP_DIRPATH / "Output Test 1"
        output_dir.mkdir()
        fpath = output_dir / 'hashes.md5'
        self.args.output = str(fpath)
        runner = pyhasher.get_runner(self.args)
        sendToDevNull(runner)
        self.assertTrue(fpath.stat().st_size > 1)

    def testHRDefaultFilename(self):
        self.args.dirpath = str(DATA_DIRPATH / 'Contains 3 Files')
        output_dir = TEMP_DIRPATH / "Output Test 2"
        output_dir.mkdir()
        self.args.output = str(output_dir)
        runner = pyhasher.get_runner(self.args)
        sendToDevNull(runner)
        fpath = list(output_dir.iterdir())[0]
        default = runner.output_default_filename
        self.assertTrue(fpath.match(default))
        

class TestIgnoreDirectory(unittest.TestCase):
    
    def setUp(self):
        self.args = CLIArgs()
        self.args.recursive = True
        
    def testIgnoreDirname(self):
        self.args.ignore_directory = "System Volume Information"
        self.args.dirpath = TEMP_DIRPATH / "IgnoreDirTest"
        self.args.dirpath.mkdir()
        ignore_directory = self.args.dirpath / self.args.ignore_directory
        ignore_directory.mkdir()
        for i in range(100):
            fpath = ignore_directory / "ignore_file__{}".format(i)
            fpath.touch()
        for i in range(2):
            fpath = self.args.dirpath / "file__{}".format(i)
            fpath.touch()        
        self.args.output = str(self.args.dirpath)
        runner = pyhasher.get_runner(self.args)
        sendToDevNull(runner)
        self.assertEqual(runner.hasher.hashed, 2)
        
    def testIgnoreDirnameNoDir(self):
        self.args.ignore_directory = "Videos_1"
        self.args.dirpath = TEMP_DIRPATH / "IgnoreDirTestNoDir"
        self.args.dirpath.mkdir()
        subdir = self.args.dirpath / "Videos"
        subdir.mkdir()
        for i in range(100):
            fpath = subdir / "subdir_file__{}".format(i)
            fpath.touch()
        for i in range(2):
            fpath = self.args.dirpath / "file__{}".format(i)
            fpath.touch()        
        self.args.output = str(self.args.dirpath)
        runner = pyhasher.get_runner(self.args)
        sendToDevNull(runner)
        self.assertEqual(runner.hasher.hashed, 102)
        
    def testIgnoreDirnamePattern(self):
        self.args.ignore_directory = "Videos_*"
        self.args.dirpath = TEMP_DIRPATH / "IgnoreDirnamePattern"
        self.args.dirpath.mkdir()
        subdir1 = self.args.dirpath / "Videos_1"
        subdir1.mkdir()
        subdir2 = self.args.dirpath / "Videos_2"
        subdir2.mkdir()        
        for i in range(100):
            fpath = subdir1 / "subdir1_file__{}".format(i)
            fpath.touch()
            fpath = subdir2 / "subdir2_file__{}".format(i)
            fpath.touch()
        for i in range(2):
            fpath = self.args.dirpath / "file__{}".format(i)
            fpath.touch()        
        self.args.output = str(self.args.dirpath)
        runner = pyhasher.get_runner(self.args)
        sendToDevNull(runner)
        self.assertEqual(runner.hasher.hashed, 2)

class TestVerifyRunner(unittest.TestCase):
    def setUp(self):
        self.args = CLIArgs()

    def remove_data_hash_logs(self, keep):
        for i in DATA_DIRPATH.iterdir():
            try:
                if i.is_file() and not i.match(keep) and not i.match('*.py'):
                    i.unlink()
            except OSError:
                pass

    def testVRCWD(self):
        root = TEMP_DIRPATH / "Test VRCWD"
        cwd = str(Path.cwd())
        root.mkdir()
        os.chdir(str(root))
        self.args.dirpath = None
        self.args.output = pyhasher.NOT_SPECIFIED
        hrunner = pyhasher.get_runner(self.args)
        sendToDevNull(hrunner)
        self.args.algorithm = pyhasher.NOT_SPECIFIED
        self.args.verifyfile = pyhasher.NOT_SPECIFIED
        vrunner = pyhasher.get_runner(self.args)
        sendToDevNull(vrunner)
        os.chdir(cwd)
        self.assertEqual(str(vrunner.curdirpath), str(root))

    def testVRStartDir(self):
        root = TEMP_DIRPATH / "Test VRStartDir"
        root.mkdir()
        self.args.output = pyhasher.NOT_SPECIFIED
        self.args.dirpath = str(root)
        hrunner = pyhasher.get_runner(self.args)
        sendToDevNull(hrunner)
        self.args.verifyfile = pyhasher.NOT_SPECIFIED
        vrunner = pyhasher.get_runner(self.args)
        sendToDevNull(vrunner)
        self.assertEqual(str(vrunner.curdirpath), str(self.args.dirpath))

    def testVRSpecifiedVerifyFile(self):
        self.remove_data_hash_logs(keep='Manually Created Directories*md5')
        self.args.verifyfile = str(DATA_DIRPATH / 'Manually Created Directories.md5')
        self.args.md5summer = True
        vrunner = pyhasher.get_runner(self.args)
        self.assertEqual(vrunner.verifyfile, DATA_DIRPATH / 'Manually Created Directories.md5')
        self.assertEqual(vrunner.first_startdir, Path.cwd())

    def testVRSpecifiedVerifyDir(self):
        self.remove_data_hash_logs(keep='Manually Created Directories*md5')
        self.args.verifyfile = str(DATA_DIRPATH)
        vrunner = pyhasher.get_runner(self.args)
        self.assertTrue(vrunner.verifyfile.match('Manually Created Directories*md5'))
        self.assertEqual(vrunner.first_startdir, Path.cwd())

    def testVRSpecifiedVerifyDirAndStartDir(self):
        self.remove_data_hash_logs(keep='Manually Created Directories*md5')
        self.args.verifyfile = str(DATA_DIRPATH)
        self.args.dirpath = str(TEMP_DIRPATH)
        vrunner = pyhasher.get_runner(self.args)
        self.assertTrue(vrunner.verifyfile.match('Manually Created Directories*md5'))
        self.assertEqual(vrunner.first_startdir, TEMP_DIRPATH)

    def testVRFileNotFound(self):
        root = TEMP_DIRPATH / "File Not Found Test"
        root.mkdir()
        self.args.dirpath = str(root)
        self.args.output = pyhasher.NOT_SPECIFIED
        for i in range(10):
            fpath = root / str(i)
            fpath.touch()
        hrunner = pyhasher.get_runner(self.args)
        sendToDevNull(hrunner)
        (root / "2").unlink()
        (root / "5").unlink()
        (root / "8").unlink()
        self.args.verifyfile = pyhasher.NOT_SPECIFIED
        vrunner = pyhasher.get_runner(self.args)
        sendToDevNull(vrunner)
        self.assertEqual(vrunner.verifier.total_files, 7)
        self.assertEqual(vrunner.verifier.not_found, 3)

    def testVRHashNoMatch(self):
        self.args.output = pyhasher.NOT_SPECIFIED
        root = TEMP_DIRPATH / "No Match Test"
        root.mkdir()
        self.args.dirpath = str(root)
        for i in range(10):
            fpath = root / str(i)
            with fpath.open('wb') as fout:
                fout.write(b'This is just data for testing.\n')
        hrunner = pyhasher.get_runner(self.args)
        sendToDevNull(hrunner)
        fpath = root / "5"
        with fpath.open('ab') as fout:
            fout.write(b"The file should not match now")
        fpath = root / "1"
        with fpath.open('ab') as fout:
            fout.write(b"This file should not match now too")
        self.args.verifyfile = pyhasher.NOT_SPECIFIED
        vrunner = pyhasher.get_runner(self.args)
        sendToDevNull(vrunner)
        self.assertEqual(vrunner.verifier.total_files, 10)
        self.assertEqual(vrunner.verifier.non_matching, 2)

    def testVRInferFormat1(self):
        output = "hashes.txt"
        alg = 'sha512'
        sep = " *"
        self.args.algorithm = alg
        self.args.sep = sep
        self.args.recursive = True
        root = TEMP_DIRPATH / "Infer Format Test 1"
        root.mkdir()
        self.args.dirpath = str(root)
        self.args.output = str(root / output)
        for i in range(10):
            fpath = root / "file-{}".format(i)
            fpath.touch()
        for j in range(2):
            d = "dir{}".format(j)
            dpath = root / d
            dpath.mkdir()
            for k in range(10):
                fpath = dpath / "file-{}".format(k)
                fpath.touch()
        hrunner = pyhasher.get_runner(self.args)
        sendToDevNull(hrunner)
        self.args.verifyfile = self.args.output
        self.args.algorithm = pyhasher.NOT_SPECIFIED
        self.args.sep = None
        self.args.output = None
        vrunner = pyhasher.get_runner(self.args)
        sendToDevNull(vrunner)
        self.assertEqual(vrunner.hasher.algorithm, alg)

    def testVRInferFormat2(self):
        output = "hashes.sha1"
        alg = 'sha1'
        sep = "  "
        self.args.algorithm = alg
        self.args.sep = sep
        root = TEMP_DIRPATH / "Infer Format Test 2"
        root.mkdir()
        self.args.dirpath = str(root)
        self.args.output = str(root / output)
        for i in range(10):
            fpath = root / "{}".format(hashlib.sha1(bytes(i)).hexdigest())
            fpath.touch()
        hrunner = pyhasher.get_runner(self.args)
        sendToDevNull(hrunner)
        self.args.verifyfile = self.args.output
        self.args.algorithm = pyhasher.NOT_SPECIFIED
        self.args.sep = None
        self.args.output = None
        vrunner = pyhasher.get_runner(self.args)
        sendToDevNull(vrunner)
        self.assertEqual(vrunner.hasher.algorithm, alg)

    def testVRInferFormat3(self):
        output = "hashes_md5.txt"
        alg = 'md5'
        sep = "<<<<<<<<<<>>>>>>>>>>"
        self.args.algorithm = alg
        self.args.sep = sep
        root = TEMP_DIRPATH / "Infer Format Test 3"
        root.mkdir()
        self.args.dirpath = str(root)
        self.args.output = str(root / output)
        for i in range(10):
            fpath = root / "{}".format(hashlib.sha1(bytes(i)).hexdigest())
            fpath.touch()
        hrunner = pyhasher.get_runner(self.args)
        sendToDevNull(hrunner)
        self.args.verifyfile = self.args.output
        self.args.algorithm = pyhasher.NOT_SPECIFIED
        self.args.sep = None
        self.args.output = None
        vrunner = pyhasher.get_runner(self.args)
        sendToDevNull(vrunner)
        self.assertEqual(vrunner.hasher.algorithm, alg)

class TestFileHashing(unittest.TestCase):

    def setUp(self):
        self.args = CLIArgs()

    def testFileHash(self):
        dirpath = TEMP_DIRPATH / 'Single File Hash'
        dirpath.mkdir()
        fpath = dirpath / 'data'
        fpath.touch()
        self.args.hash_file = [fpath.as_posix()]
        sendToDevNull(pyhasher.main, self.args)

    def testMultiFileHash(self):
        dirpath = TEMP_DIRPATH / 'Multi File Hash'
        dirpath.mkdir()
        tmp = []
        for i in range(20):
            fpath = dirpath / "{:02}".format(i)
            fpath.touch()
            tmp.append(fpath.as_posix())
        self.args.hash_file = tmp
        sendToDevNull(pyhasher.main, self.args)

class TestVerificationFNF(unittest.TestCase):
    """
    Test for Error that occurs when a file is not found during verification because it is
    in the root of the starting directory but was manually appended to the end of the verification
    file.
    """
    
    def setUp(self):
        self.dirpath = TEMP_DIRPATH / 'FNF Error'
        self.dirpath.mkdir()
        os.chdir(str(self.dirpath))
        self.args = CLIArgs()
        self.args.recursive = True
        
    def testFileNotFound(self):
        subdirpath = self.dirpath / 'FNF Subdir'
        subdirpath.mkdir()
        for i in range(10):
            fpath = subdirpath / '{:02}'.format(i)
            fpath.touch()
        self.args.output = 'hashes.md5'
        hr = pyhasher.get_runner(self.args)
        sendToDevNull(hr)
        # file that won't be found
        fpath = self.dirpath / 'potential_fnf'
        fpath.touch()
        with open(self.args.output, 'a') as fin:
            fin.write("{}  {}".format(hashlib.md5().hexdigest(), fpath.name))
        self.args.verifyfile = self.args.output
        self.args.output = None
        vr = pyhasher.get_runner(self.args)
        sendToDevNull(vr)
        self.assertEqual(0, vr.verifier.not_found)
        self.assertEqual(11, vr.verifier.hashed)

if __name__ == "__main__":
    unittest.main()
