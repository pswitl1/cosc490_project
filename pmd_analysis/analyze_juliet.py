#!../dependencies/python/Python32/python3
import os
import re
import sys
import time
import shutil
import subprocess


class AnalyzeJuliet(object):

    def __init__(self, juliet_dir, cwe_mappings, ruleset_template, pmd_exec, outdir, max_processes, remove_source_output, quiet):
        super(AnalyzeJuliet).__init__()

        start = time.time()

        # class members
        self.test_cases_dir = os.path.join(juliet_dir, 'src', 'testcases')
        self.ruleset_template = ruleset_template
        self.pmd_exec = pmd_exec
        self.outdir = outdir
        self.quiet = quiet

        # for each cwe
        for cwe in cwe_mappings:

            # get info
            cwe_id = cwe[0]
            pmd_rule = cwe[1]
            priority = cwe[2]
            cwe_name = self.get_cwe_name(cwe_id)

            # make cwe outdir
            cwe_outdir = os.path.join(self.outdir, cwe_name)
            os.makedirs(cwe_outdir)

            # create the ruleset
            self.create_ruleset(cwe_name, pmd_rule, priority, cwe_outdir)

            # copy source files into seperate dir
            self.copy_cwe_source_files(cwe_id, cwe_name, cwe_outdir)

            # run pmd for all tests in this cwe
            self.run_pmd(cwe_outdir, max_processes)

            # if enabled remove source files
            if remove_source_output:
                shutil.rmtree(os.path.join(cwe_outdir, 'src'))

            # analyze all tests from this cwe
            AnalyzeJuliet.analyze_cwe(cwe_outdir)

        self.analyze_all()

        # time
        print('\nAnalyzeJuliet took %.2f seconds to complete.' % (time.time() - start))

    def analyze_all(self):
        with open(os.path.join(self.outdir, 'results.txt'), 'w') as fout:
            fout.write('CWE Results\n\n')
            for cwe_outdir in os.listdir(self.outdir):
                cwe_outdir = os.path.join(self.outdir, cwe_outdir)
                if os.path.isdir(cwe_outdir):
                    results_file = os.path.join(cwe_outdir, 'results.txt')
                    if os.path.exists(results_file):
                        fout.write('%s\n' % os.path.basename(cwe_outdir))
                        with open(results_file, 'r') as fin:
                            lines = fin.readlines()
                            fout.write('%s%s\n' % (lines[1], lines[2]))

    def get_cwe_name(self, cwe_id):
        """
        Find cwe name in juliet test cases

        :param cwe_id: cwe number
        :return: cwe name
        """

        cwe_names = [dir_ for dir_ in os.listdir(self.test_cases_dir)
                     if dir_ != 'common' and os.path.isdir(os.path.join(self.test_cases_dir, dir_))]
        cwe_ids = [int(name[3:name.find('_')]) for name in cwe_names]
        try:
            name = cwe_names[cwe_ids.index(cwe_id)]
        except ValueError:
            sys.exit('cwe: %d defined in cwe_mappings file is not in the juliet testcases' % cwe_id)

        return name

    def create_ruleset(self, cwe_name, pmd_rule, priority, cwe_outdir):
        """
        Create the specific ruleset for a cwe, use the ruleset template

        :param cwe_name: name of cwe
        :param pmd_rule: the pmd rule class
        :param priority: priority of the rule
        :param cwe_outdir: the cwe out directory
        :return: None
        """
        replace_map = {
            'cwe_name': cwe_name,
            'rule_class': pmd_rule,
            'priority_number': str(priority)
        }
        ruleset_file = os.path.join(cwe_outdir, 'ruleset.xml')
        with open(self.ruleset_template, 'r') as fin:
            with open(ruleset_file, 'w') as fout:
                for line in fin.readlines():
                    for key in replace_map.keys():
                        if line.find(line) > -1:
                            line = line.replace(key, replace_map[key])
                    fout.write(line)

    def copy_cwe_source_files(self, cwe_id, name, cwe_outdir):
        """
        PMD needs a single directory with source files, so copy each test's source file(s) into one directory.

        :param cwe_id: id of cwe source files to look for
        :param name: cwe name of source files to look for
        :param cwe_outdir: outdir to copy to
        :return: None
        """
        # find dirs, since some have s01, s02, ...
        cwe_dir = os.path.join(self.test_cases_dir, name)
        if os.path.exists(os.path.join(cwe_dir, 's01')):
            cwe_dirs = []
            for s_dir in os.listdir(cwe_dir):
                s_dir = os.path.join(cwe_dir, s_dir)
                if os.path.isdir(s_dir):
                    cwe_dirs.append(s_dir)
        else:
            cwe_dirs = [cwe_dir]

        # append all test case dirs together
        test_cases = []
        for cwe_dir in cwe_dirs:
            test_cases += [os.path.join(cwe_dir, case) for case in os.listdir(cwe_dir) if case.find(name) != -1]

        # correctly divide tests into dirs and copy files
        os.makedirs(os.path.join(cwe_outdir, 'src'))
        for case in test_cases:
            case_base = os.path.basename(case)
            suffix = case_base[case_base.index(name) + len(name):]
            digit_search = re.search('\d', suffix)
            test_number = suffix[digit_search.start(): digit_search.end() + 1]
            test_name = suffix[2:digit_search.start() - 1]
            dst = os.path.join(cwe_outdir, 'src', 'src_%s_%s' % (test_name, test_number))
            if not os.path.isdir(dst):
                os.makedirs(dst)
            shutil.copy(case, dst)

    def run_pmd(self, cwe_outdir, max_processes):
        """
        Execute pmd commands on the given cwe outdir.

        :param cwe_outdir: cwe outdir to execute commands on
        :param max_processes: max number of pmd processes to spawn at one time
        :return: None
        """
        processes = []
        os.makedirs(os.path.join(cwe_outdir, 'results'))

        idx = 0
        for src_dir in os.listdir(os.path.join(cwe_outdir, 'src')):
            src_dir = os.path.join(cwe_outdir, 'src', src_dir)

            # build command
            if os.path.isdir(src_dir):
                cmd = []
                cmd.append(self.pmd_exec)
                cmd.append('-d')
                cmd.append(src_dir)
                cmd.append('-R')
                cmd.append(os.path.join(cwe_outdir, 'ruleset.xml'))
                cmd.append('-f')
                cmd.append('csv')
                cmd.append('-property')
                cmd.append('package=false')
                cmd.append('-property')
                cmd.append('priority=false')
                cmd.append('-property')
                cmd.append('desc=false')
                cmd.append('-property')
                cmd.append('ruleSet=false')
                cmd.append('-no-cache')
                cmd.append('-shortnames')
                fname = '%s.csv'.replace('src_', '') % os.path.basename(src_dir)

                # spawn processes, with a max number
                processes.append(subprocess.Popen(cmd, stdout=open(os.path.join(cwe_outdir, 'results', fname), 'w')))
                idx += 1

                if len(processes) == max_processes:
                    while processes != []:
                        processes[0].wait()
                        processes.pop(0)

        while processes != []:
            processes[0].wait()
            processes.pop(0)

    @staticmethod
    def analyze_cwe(cwe_outdir):
        """
        Analyze tests in the given cwe_outdir

        :param cwe_outdir: cwe outdir to analyze
        :return: None, outputs results.txt in cwe_outdir
        """

        # determine all failed and extra detections
        results = {'successful': [], 'failed': [], 'extra': []}
        num_tests = len(os.listdir(os.path.join(cwe_outdir, 'results')))
        for result in os.listdir(os.path.join(cwe_outdir, 'results')):
            result_file = os.path.join(cwe_outdir, 'results', result)
            with open(result_file, 'r') as fin:
                num_lines = len(fin.readlines())

                if num_lines == 2:
                    results['successful'].append(result[:len(result) - 4])
                elif num_lines == 1:
                    results['failed'].append(result[:len(result) - 4])
                else:
                    results['extra'].append(result[:len(result) - 4])

        # write results file
        with open(os.path.join(cwe_outdir, 'results.txt'), 'w') as fout:
            fout.write('Summary:\n')
            for result_type in results:
                fout.write('\t%d %s detections   (%.2f%%)\n' % (len(results[result_type]), result_type,
                                                              (float(len(results[result_type])) / float(num_tests)) * 100))
            fout.write('\nDetails:\n')
            for result_type in results:
                fout.write('\t%d %s detections\n' % (len(results[result_type]), result_type))
                for result in results[result_type]:
                    fout.write('\t\t%s\n' % result)
