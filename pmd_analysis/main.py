#!../dependencies/python/Python32/python3
import os
import sys
import shutil
from argparse import ArgumentParser
from analyze_juliet import AnalyzeJuliet

def main():
    """
    Analyze all juliet test cases with pmd.
    :return: None
    """
    # define, parse, and validate arguments
    parser = ArgumentParser('main.py')
    parser.add_argument('--juliet_dir', help='path/to/juliet/test/cases', type=str, default='..\juliet_test_cases')
    parser.add_argument('--cwe_mappings_file', help='path/to/cwe/mapping/file', type=str, default='cwe_mappings.txt')
    parser.add_argument('--ruleset_template_file', help='path/to/ruleset/template/file', type=str,
                        default='ruleset_template.xml')
    parser.add_argument('--pmd_exec', help='path/to/pmd/exec', type=str,
                        default='..\..\pmd\pmd-dist\\target\pmd-bin-6.13.0-SNAPSHOT\\bin\pmd.bat')
    parser.add_argument('--outdir', help='path/to/outdir', type=str, default='outdir')
    parser.add_argument('--mp', help='max number of pmd processes to spawn at one time', type=int, default=25)
    parser.add_argument('--keep_copied_source', help='keep copied source files', action='store_true')
    parser.add_argument('--use_multifile_tests', help='include tests with multiple files', action='store_true')
    parser.add_argument('-q', '--quiet', help='supress terminal output', action='store_true')
    args = validate_args(parser.parse_args())

    # analyze
    AnalyzeJuliet(
        args.juliet_dir,
        parse_cwe_mappings_file(args.cwe_mappings_file),
        args.ruleset_template_file,
        args.pmd_exec,
        args.outdir,
        args.mp,
        not args.keep_copied_source,
        not args.use_multifile_tests,
        args.quiet)


def validate_args(args):
    """
    Validate command line arguments. Calls sys.exit if error is found.

    :param args: ArgumentParser arguments
    :return: None
    """
    check_exists(args.juliet_dir, 'juliet_dir', False, args.quiet)
    if not os.path.isdir(os.path.join(args.juliet_dir, 'src', 'testcases')):
        sys.exit('invalid argument "juliet_dir", make sure it is a path to the juliet test cases')

    check_exists(args.cwe_mappings_file, 'cwe_mappings_file', True, args.quiet)

    check_exists(args.ruleset_template_file, 'ruleset_template_file', True, args.quiet)

    check_exists(args.pmd_exec, 'pmd_exec', True, args.quiet)

    if os.path.isdir(args.outdir):
        shutil.rmtree(args.outdir)
    os.makedirs(args.outdir)  # TODO verify we can make ruleset outdir

    return args


def check_exists(path, desc, check_file=True, quiet=False):
    """
    Check if a path exists as a dir or file. Calls sys.exit if error is found.

    :param path: desired/path
    :param desc: description for printing
    :param check_file: True to check for file, False to check for dir
    :param quiet: supress output
    :return: None
    """
    tmp_str = '"%s" -> "%s"' % (desc, path)
    if os.path.exists(path):
        type_ = 'dir'
        if check_file:
            type_ = 'file'
        if (check_file and os.path.isfile(path)) or (not check_file and os.path.isdir(path)):
            if quiet:
                print('found argument: %s.' % tmp_str)
            return

        sys.exit('invalid argument: %s, should be a %s.' % (tmp_str, type_))
    else:
        sys.exit('invalid argument: %s, doesnt exist.' % tmp_str)


def parse_cwe_mappings_file(cwe_mappings_file):
    """
    Parse the cwe mappings file. Call sys exit if file is invalid

    :param cwe_mappings_file: path/to/cwe/mappings/file
    :return: cwe_mappings list
    """
    cwe_mappings = []
    with open(cwe_mappings_file, 'r') as fin:
        for idx, line in enumerate(fin.readlines()):
            error = False
            line = line.replace(" ", "")
            if len(line) > 0:
                if line[:1] == "#":
                    continue
            line = line.split(',')
            cwe = 0
            priority = 0
            pmd_rule = ''
            if len(line) == 2:
                try:
                    cwe = int(line[0])
                except:
                    error = True
                pmd_rule = line[1]
                if len(pmd_rule) == 0:
                    error = True
            else:
                error = True
            if error:
                sys.exit('error in cwe_mappings file: "%s", line: "%d", must be in the following format:'
                         '"cwe_number,pmd_rule_path,priority"' % (cwe_mappings_file, idx))
            cwe_mappings.append([cwe, pmd_rule])

    if len(cwe_mappings) == 0:
        sys.exit('error in cwe_mappings file: "%s", empty file.' % cwe_mappings_file)

    return cwe_mappings


if __name__ == '__main__':
    main()
