# pyhasher
pyhasher
========

Version 2.7.4
    

*pyhasher* is a cross-platform, command-line Python program for hashing files 
in a directory or directory tree.

Suports MD5, SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512

### Dependencies ###

*pyhasher* requires the pathlib library. It is tested and working on Pyton 3.4 and later which contain the module as
part of the standard library.

You may try to run using Python 3.0 to 3.3 versions by installing the pathlib library separately.

### Usage ###

```
usage: pyhasher.py [-h] [-p PATTERN [PATTERN ...]] [-V [DIR|FILE]] [-c DIR]
                   [-o [FILE|DIR]] [-a md5|sha256|sha384|sha512|sha1|sha224]
                   [-r] [--md5summer] [--sep SEP] [--log-header] [--log-stats]
                   [-L] [--no-errors] [--headings] [--overwrite] [--version]
                   [-q] [--fail-fast] [--ignore-directory DIR]
                   [--ignore-hidden] [--ignore-system] [--ignore-all]
                   [-d DIR | -A FILE | -f FILE [FILE ...]]

optional arguments:
  -h, --help            show this help message and exit
  -p PATTERN [PATTERN ...], --patterns PATTERN [PATTERN ...]
                        (Hashing Only) Filename pattern or patterns to hash.
                        The default is all files in current directory. The
                        patterns are not case-sensitive. Be sure to use double
                        or single quotes as necessary to avoid any unwanted
                        expansion by the shell. For example, specifying *.jpg
                        *.png without any quotes will be expanded by a Bash
                        shell to all files in the current working directory
                        that have those two extensions; if the program is
                        running recursively, only those file names will match
                        and all files will not be hashed. To hash all
                        instances of jpg and png files in all subdirectories,
                        specify the arguments as "*.jpg" "*.png" .
  -V [DIR|FILE], --verify [DIR|FILE]
                        Will verify from FILE instead of hashing. The program
                        will read hashes from FILE or it will look in DIR for
                        a file extension that ends with the current hash
                        algorithm name (for example "md5" or "pymd5"). If
                        multiple files are found, the most recently modified
                        file will be used.
  -c DIR, --change-dir DIR
                        Change directory before running. Changes the current
                        working directory path to DIR before running. This is
                        done by Python while running this program and does not
                        affect any other processes run after it.
  -o [FILE|DIR], --output [FILE|DIR]
                        Log output directly to FILE. This will avoid any
                        encoding issues between the encoding that the shell is
                        using and the output. This seems to only be a concern
                        in Windows with Unicode file names. You can specify
                        either FILE or a directory path (DIR). If no arguments
                        are specified, a file will be created in the current
                        working directory using a default filename. If only
                        DIR is specified, a file will be created in that
                        directory using a default filename. If FILE already
                        exists, a number will be appended to the name to avoid
                        ovewriting unless the --overwrite option is used.
  -a md5|sha256|sha384|sha512|sha1|sha224, --algorithm md5|sha256|sha384|sha512|sha1|sha224
                        Hash algorithm to be used. You can only specify one.
                        The default is "md5" for hashing. On verification, if
                        an algorithm is not specified, the program will
                        attempt to infer the algorithm based on patterns found
                        at the start of each line.
  -r, --recursive       (Hashing Only) Hash all files in all subdirectories.
                        By default the program ignores subdirectories and
                        files within.
  --md5summer           (Verifying Only) If the verification file was created
                        by the program MD5summer, use this option to avoid
                        text encoding and decoding errors on non-ASCII
                        filenames.
  --sep SEP             Use text SEP to separate the logged hash value and the
                        filename or filepath. The default is two spaces on
                        hashing. During verification, if SEP is not specified,
                        the program will just automatically strip off spaces
                        or asterisks from the end of the hash. [This means
                        file names with spaces or asterisks at the start will
                        not be resolved properly if they for some reason exist
                        at all]. If the separator does not contain spaces or
                        asterisks then it will need to specified otherwise the
                        correct paths will not be located for the files. Use
                        quotes as necessary to avoid expansion or white space
                        removal by the shell.
  --log-header          Includes the header in the output file. By default the
                        header is only written to standard error.
  --log-stats           Includes the end stats in the output file. By default
                        the end stats are only written to standard error.
  -L, --log-all         The same as specifying '--log-stats' with '--log-
                        header'.
  --no-errors           (Hashing Only) Output errors will not be logged inline
                        with hashes. Errors are still counted, just not
                        logged.
  --headings            The relative path will not be logged for each file.
                        The relative path to the directory containing the file
                        will be logged once with the file names logged
                        underneath.
  --overwrite           Overwrites any existing LOGFILE with the same name.
  --version             Prints version to standard out and exits
  -q, --quiet           (Verification Only) Does not display matches on
                        output. Only errors, files not found, and mismatches
                        will be output.
  --fail-fast           (Verification Only) Stop running on first non-matching
                        hash found.
  --ignore-directory DIR
                        (Hashing Only) Does not hash any files in directory
                        named, can be a full or relative path or just a
                        directory name. If it is just a name then all
                        directories encountered with that name will be
                        ignored. You can also use wildcard characters such as
                        * and ? to match patterns. The argument "Videos*" with
                        directories names "Videos_1" and "Videos_2" in any
                        directory it is found (if recursive).
  --ignore-hidden       (Hashing Only) Does not hash any files that are
                        considered hidden by the OS being used
  --ignore-system       (Hashing Only) Does not hash any files that are
                        considered system files by the OS being used
  --ignore-all          (Hashing Only) Sets both --ignore-hidden and --ignore-
                        system options
  -d DIR, --dirpath DIR
                        Directory path to start hashing or verification,
                        defaults to the current working directory. Does not
                        change to as with -c/--change-dir option.
  -A FILE, --archive FILE
                        (Hashing Only) Hash the files contained within FILE
                        which is a tarfile, compressed tarfile, or zip file
                        archive. The archive is opened based on its extension.
                        This option cannot be combined with --dirpath since
                        the archive is the starting directory. This is not
                        tested at this time.
  -f FILE [FILE ...], --hash-file FILE [FILE ...]
                        Hashes a specific file or files and prints the hash to
                        standard output. No header or stats are calculated, no
                        log files are created. All other arguments except
                        -a/--algorithm are ignored. The hash is printed
                        followed by the default separator and the file path or
                        name as it is supplied as an argument. If the full
                        path was supplied, that will be printed.

```

#### Hashing ####

Hashing is the default behavior.

Assumes `pyhasher` is `python pyhasher.py` where python is Python 3.4 or greater

**Examples**

```
pyhasher
```  
  

* Hash all files in the current working directory using the `md5` algorithm and 
print the results to standard out.

```
pyhasher -f file.txt
```  
  

* Hash only file.txt and print to standard out. All other options are 
ignored except for -a or --algorithm can be changed from the default.


```
pyhasher -r -p *.png *.jpg
```  
  

* Hash files that end with `.PNG`, `.png`, `.JPG`, or `.jpg` in the current 
working directory and all sub-directories and print results to standard out.


```
pyhasher -d ../data -o -r
```

* Hash all files in the `../data` directory and sub-directories and print 
the results to a log file (or hashlog) in the current working directory.
(NOTE: The hashlog's name will be automatically generated based on the starting 
time and date. All relative paths are based on the current working dir)

```
pyhasher -d ../data -o -r --headings --sep "****"
```

* Do as the previous example except only log the relative path for each directory once. The
file names and hash values will be logged underneath. A text separator of `****` will be written between the hash value and file name. 
(NOTE: The default behavior is to only log the relative path of each file after the hash value.)


```
pyhasher -c "C:\Users\me\Important Files" -o "Important Files.md5" --overwrite
```

* Change to `C:\Users\me\Important Files`, hash all the files, and create a hashlog 
named `Important Files.md5`, overwriting any existing files with the same name as the hashlog.

```
pyhasher -c "C:\Users\me\Important Files" -a sha256 -p file.txt
```

* Change to `C:\Users\me\Important Files` and hash all files matching the pattern
`file.txt` using the `sha256` algorithm. (NOTE: The pattern is not case-sensitive and
 will match to `file.txt`, `File.txt`, `file.TXT`, etc.)

```
pyhasher -A "C:\Users\me\Important Files\compressed_files.tar.gz"
```

* Hash all files contained in the compressed archive `C:\Users\me\Important Files\compressed_files.tar.gz`
(NOTE: This feature has not been thoroughly tested at this time.)

```
pyhasher --ignore-directory "Videos*" --recursive
```

* Hash all files in all subdirectories but ignore all files in subdirectories that start with "Videos".
Does not work when hashing compressed archives individually.

```
pyhasher --ignore-all --recursive
```

* Hash all files in all subdirectories but ignore all files with either the Hidden or System file attribute.
Does not work when hashing compressed archives individually.


#### Verification ####

Verification is performed by specifying the `-V` or `--verify` with an optional 
file path that will match using glob.glob(). If a file name is not specified, `pyhasher`
 will search file names in the current working directory for an extension that contains the 
 name of one of the supported hash algorithms, e.g. `hashes.md5`. If multiple files match 
 the pattern, `pyhasher` will use the most recently modified file.

**Examples**

```
pyhasher -V
```

* Verify hashes in the hashlog in the current working directory.

```
pyhasher -V C:\Users\me\hashes.txt -a sha1 --sep "****"
```

* Verify the hashes in the current working directory from the hash values logged 
in the file at `C:\Users\me\hashes.txt` using the `sha1` algorithm and a text
 separator `****`. (NOTE: If the hash name and the text separator are not specified, 
 the program will attempt to infer the algorithm based on the patterns found in the file.)

```
pyhasher -c /Users/me/Documents -V my_hashes.pyh -o
```

* Verify the hashes logged in the `my_hashes.pyh` file contained `/Users/me/Documents`. 
(NOTE: The hashes will be written to a file in the working directory; the file name will 
be based on the file name of the verification file and the current time and date.)

```
pyhasher -V "verify_file.md5" --fail-fast
```

* Verify all files in the current directory using the verification file "verify_file.md5". If a file does not match, then
the verification will stop.

### License ###

Copyright 2017 Chris Corpora

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


### Contact ###

Chris Corpora <pyhasher@gmail.com>