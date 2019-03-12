#!../dependencies/python/Python32/python3
import os
import sys
import shutil
import subprocess
from argparse import ArgumentParser

def main():
    """
    analyze all juliet test cases with pmd
    :return: None
    """
    # parse and validate arguments
    parser = ArgumentParser('analyze.py')
    parser.add_argument('--test_cases', help='path/to/juliet/test/cases', type=str, default='..\juliet_test_cases')
    parser.add_argument('--cwe_mappings', help='path/to/cwe/mapping/file', type=str, default='cwe_mappings.txt')
    parser.add_argument('--ruleset_template', help='path/to/ruleset/template/file', type=str,
                        default='ruleset_template.xml')
    parser.add_argument('--pmd_exec', help='path/to/pmd/exec', type=str, default='..\..\pmd\pmd-dist\\target\pmd-bin-6.13.0-SNAPSHOT\\bin\pmd.bat')
    parser.add_argument('--ruleset_outdir', help='path/to/ruleset_outdir', type=str, default='cwe_rulesets')
    parser.add_argument('-q', '--quiet', help='supress terminal output', action='store_true')
    args = validate_args(parser.parse_args())

    cwe_mappings = parse_cwe_mappings_file(args.cwe_mappings)

    ruleset_files = [fout for fout in generate_rulesets(args.pmd_exec, args.test_cases, cwe_mappings, args.ruleset_template, args.ruleset_outdir)]


def validate_args(args):
    """
    Validate command line arguments. Calls sys.exit if error is found.

    :param args: ArgumentParser arguments
    :return: None
    """
    check_exists(args.test_cases, 'test_cases', False, args.quiet)
    if not os.path.isdir(os.path.join(args.test_cases, 'src', 'testcases')):
        sys.exit('invalid argument "test_cases", make sure it is a path to the juliet test cases')

    check_exists(args.cwe_mappings, 'cwe_mappings', True, args.quiet)
    check_exists(args.ruleset_template, 'ruleset_template', True, args.quiet)

    if os.path.isdir(args.ruleset_outdir):
        shutil.rmtree(args.ruleset_outdir)
    os.makedirs(args.ruleset_outdir) #  TODO verify we can make ruleset outdir

    return args


def parse_cwe_mappings_file(cwe_mappings_file):

    cwe_mappings = {}
    with open(cwe_mappings_file, 'r') as fin:
        for idx, line in enumerate(fin.readlines()):
            error = False
            line = line.split(',')
            cwe = 0
            priority = 0
            pmd_rule = ''
            if len(line) == 3:
                try:
                    cwe = int(line[0])
                    priority = int(line[2])
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
            cwe_mappings[cwe] = [pmd_rule, priority]

    if len(cwe_mappings.keys()) == 0:
        sys.exit('error in cwe_mappings file: "%s", empty file.' % cwe_mappings_file)

    return cwe_mappings


def generate_rulesets(pmd_exec, test_cases, cwe_mappings, ruleset_template, ruleset_outdir):

    ruleset_files = []
    for cwe in cwe_mappings.keys():
        ruleset_files.append(generate_ruleset(pmd_exec, test_cases, cwe, cwe_mappings[cwe], ruleset_template, ruleset_outdir))
    return ruleset_files


def generate_ruleset(pmd_exec, test_cases, cwe, cwe_rule_info, ruleset_template, ruleset_outdir):

    test_cases = os.path.join(test_cases, 'src', 'testcases')
    cwe_name = ''
    for dir_ in os.listdir(test_cases):
        if os.path.isdir(os.path.join(test_cases, dir_)) and dir_ != 'common':
            cwe_str = dir_[3:]
            cwe_str = cwe_str[:cwe_str.find('_')]
            if int(cwe_str) == cwe:
                cwe_name = dir_

    if cwe_name == '':
        sys.exit('cwe: %d defined in cwe_mappings file is not in the juliet testcases' % cwe)

    replace_map = {
        'cwe_name': cwe_name,
        'message_string': '%s -> %s' % (cwe_name, cwe_rule_info[0]),
        'rule_class': cwe_rule_info[0],
        'priority_number': str(cwe_rule_info[1])
    }
    ruleset_file = os.path.join(ruleset_outdir, '%s_ruleset.xml' % cwe_name)
    with open(ruleset_template, 'r') as fin:
         with open(ruleset_file, 'w') as fout:
            for line in fin.readlines():
                for key in replace_map.keys():
                    if line.find(line) > -1:
                        line = line.replace(key, replace_map[key])
                fout.write(line)

    run_pmd(pmd_exec, os.path.join(test_cases, cwe_name), ruleset_file, ruleset_file.replace('_ruleset.xml', '_output.txt'))


def run_pmd(pmd_exec, source, ruleset, output_file, output_type='text'):

    print(pmd_exec)
    print(source)
    print(ruleset)
    subprocess.Popen(
        [pmd_exec, '-d', source, '-R', ruleset, '-f', output_type])#, stdout=open(output_file, 'w'))


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


if __name__ == '__main__':
    main()
