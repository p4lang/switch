#!/usr/bin/env python
import os
import subprocess
import sys

def get_output_file_name(output_dir, output_file_num):
    return os.path.join(output_dir, 'p4_prefix%d.cpp' % output_file_num)

def split_pd_thrift(input_file_name, output_dir, num_output_files):
    num_input_lines = int(subprocess.check_output(
                              'wc -l %s | awk \'{print $1}\'' % input_file_name,
                              shell=True))
    for output_file_num in range(num_output_files):
        output_file_name = get_output_file_name(output_dir, output_file_num)
        os.system('grep "^#include" %s > %s' % (input_file_name,
                                                output_file_name))
        os.system('grep namespace\ p4_pd_rpc %s >> %s' % (input_file_name,
                                                         output_file_name))

    output_file_num = 0
    end_namespace = '} // namespace'
    output_line_num = 0
    with open(input_file_name) as input_file:
        for line in input_file:
            if line == 'namespace p4_pd_rpc {\n':
                break
        for line in input_file:
            if output_line_num == 0 and output_file_num < num_output_files: # {
                output_file_name = get_output_file_name(output_dir,
                                                        output_file_num)
                output_file = open(output_file_name, "a")
                output_file_num += 1
            # }
            output_file.write(line)
            output_line_num += 1
            if line == end_namespace:
                # Reached the end of the namespace (last line in file)
                break
            elif (output_line_num > (num_input_lines / num_output_files)) and \
                 (line == '}\n'): # {
                # Reached end of function. close the file
                output_file.write('%s\n' % end_namespace)
                output_file.close()
                output_line_num = 0
            # }


if __name__ == '__main__':
    assert len(sys.argv) == 4
    input_file_name = sys.argv[1]
    output_dir = sys.argv[2]
    num_output_files = sys.argv[3]
    split_pd_thrift(input_file_name, output_dir, int(num_output_files))
