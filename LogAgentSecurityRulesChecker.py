# Copyright 2025 Dynatrace LLC
#  
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#  
#     https://www.apache.org/licenses/LICENSE-2.0
#  
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This script is supported by Dynatrace.

This script checks whether an absolute filepath satisfy OneAgent's Log Module security rules.
This script is intended to work the same way as OneAgent although NO WARRANTY is given.
The newest version of the script is available on https://github.com/Dynatrace/Dynatrace-Log-Security-Rules-Checker

Official documentation for the functionality is here:
https://docs.dynatrace.com/docs/observe-and-explore/logs/lma-log-ingestion/lma-log-ingestion-via-oa/lma-security-rules

Usage:
You need to provide an absolute path without symbolic links. The script assumes that without checking. (Hint: you can resolve symlinks using `realpath` tool: https://man7.org/linux/man-pages/man1/realpath.1.html)
You need to specify OneAgent version.
You need to specify operating system.
You can optionally provide your config file which will be parsed along with the default options.
"""

# ScriptVersion=2025/02/03
current_script_version = "2025/02/03"

import argparse
import json
import os
import re
import sys
from urllib.request import urlopen

def match_dirs(dir_pattern, dir_part):
    if dir_pattern != "" and dir_pattern[-1] != '/':
        dir_pattern += '/'
    for special_char in "[]$.|?+(){}":
        dir_pattern = dir_pattern.replace(special_char, "\\" + special_char)
    prefix = ".*" if not (dir_pattern.startswith("^") or dir_pattern.startswith("**")) else ""
    dir_pattern = re.sub("\\*\\*/*", ".*", dir_pattern)
    dir_pattern = re.sub("(?<!(?<!\\\\)\\.)\\*", "[^/]*", dir_pattern)
    return re.fullmatch(prefix + dir_pattern, dir_part, re.IGNORECASE) != None

def match_files(file_pattern, file_part):
    while file_pattern != "" and file_part != "":
        if file_pattern[0] == '[':
            endGroup = file_pattern.find(']')
            if endGroup == -1:
                return False
            if file_pattern[:endGroup].find(file_part[0]) == -1:
                return False
            file_pattern = file_pattern[endGroup+1:]
            file_part = file_part[1:]
        elif file_pattern[0].lower() == file_part[0].lower():
            file_pattern = file_pattern[1:]
            file_part = file_part[1:]
        elif file_pattern[0] == '*':
            return match_files(file_pattern[1:], file_part) or match_files(file_pattern, file_part[1:])
        else:
            return False
    return (file_pattern == "" or file_pattern == "*") and file_part == ""

def append_rule_impl(rules, newRule, verbose):
    rules.append(newRule)
    if verbose:
        print ('Adding a new rule with directory pattern = "' + newRule[0] + '" filepattern = "' + newRule[1] + '" and action = "' + newRule[2] + '"')

rotation_suffix = "[-.\\_]*"

def append_rule(rules, newRule, add_suffix, verbose):
    append_rule_impl(rules, newRule, verbose)
    if newRule[1] != "" and not newRule[1].endswith("*") and newRule[2] == "INCLUDE" and add_suffix:
        append_rule_impl(rules, (newRule[0], newRule[1] + rotation_suffix, newRule[2]), verbose)

def add_default_rules(rules, add_suffix, agent_version, os, verbose):
    if verbose:
        print("loading default configuration rules")
    append_rule(rules, ("/", "*.pem", "EXCLUDE"), add_suffix, verbose)
    append_rule(rules, ("/.ssh/", "*", "EXCLUDE"), add_suffix, verbose)
    append_rule(rules, ("/.*/", "*", "EXCLUDE"), add_suffix, verbose)
    append_rule(rules, ("/", ".*", "EXCLUDE"), add_suffix, verbose)
    if os == 'aix' or os == 'linux':
        append_rule(rules, ("^/etc/**/", "*", "EXCLUDE"), add_suffix, verbose)
        append_rule(rules, ("^/boot/**/", "*", "EXCLUDE"), add_suffix, verbose)
        append_rule(rules, ("^/proc/**/", "*", "EXCLUDE"), add_suffix, verbose)
        append_rule(rules, ("^/dev/**/", "*", "EXCLUDE"), add_suffix, verbose)
        append_rule(rules, ("^/bin/**/", "*", "EXCLUDE"), add_suffix, verbose)
        append_rule(rules, ("^/sbin/**/", "*", "EXCLUDE"), add_suffix, verbose)
        if agent_version == 'until-287' or agent_version == 'since-287-until-303':
            append_rule(rules, ("^/usr/**/", "*", "EXCLUDE"), add_suffix, verbose)
    if os == 'windows':
        append_rule(rules, ("/windows/system32/winevt/Logs/", "*", "INCLUDE"), add_suffix, verbose)
        append_rule(rules, ("/winnt/system32/winevt/Logs/", "*", "INCLUDE"), add_suffix, verbose)
        append_rule(rules, ("^/windows/**/", "*", "EXCLUDE"), add_suffix, verbose)
        append_rule(rules, ("^/winnt/**/", "*", "EXCLUDE"), add_suffix, verbose)
    if agent_version == 'until-287' or agent_version == 'since-287-until-303':
        append_rule(rules, ("/", "*[-.\\_]log[-.\\_]*", "INCLUDE"), add_suffix, verbose)
    append_rule(rules, ("/", "*[-.\\_]log", "INCLUDE"), add_suffix, verbose)
    if agent_version == 'since-303':
        append_rule(rules, ("/", "*[-.\\_]txt", "INCLUDE"), add_suffix, verbose)
    append_rule(rules, ("/", "catalina.out*", "INCLUDE"), add_suffix, verbose)
    append_rule(rules, ("/log/", "*", "INCLUDE"), add_suffix, verbose)
    if agent_version == 'until-287' or agent_version == 'since-287-until-303':
        append_rule(rules, ("/log/*/", "*", "INCLUDE"), add_suffix, verbose)
    if agent_version == 'since-287-until-303':
        append_rule(rules, ("/log/*/*/", "*", "INCLUDE"), add_suffix, verbose)
    if agent_version == 'since-303':
        append_rule(rules, ("/log/**/", "*", "INCLUDE"), add_suffix, verbose)
    append_rule(rules, ("/logs/", "*", "INCLUDE"), add_suffix, verbose)
    if agent_version == 'until-287' or agent_version == 'since-287-until-303':
        append_rule(rules, ("/logs/*/", "*", "INCLUDE"), add_suffix, verbose)
    if agent_version == 'since-287-until-303':
        append_rule(rules, ("/logs/*/*/", "*", "INCLUDE"), add_suffix, verbose)
    if agent_version == 'since-303':
        append_rule(rules, ("/logs/**/", "*", "INCLUDE"), add_suffix, verbose)
    if agent_version == 'since-303':
        append_rule(rules, ("/logfile/", "*", "INCLUDE"), add_suffix, verbose)
        append_rule(rules, ("/logfile/**/", "*", "INCLUDE"), add_suffix, verbose)
        append_rule(rules, ("/logfiles/", "*", "INCLUDE"), add_suffix, verbose)
        append_rule(rules, ("/logfiles/**/", "*", "INCLUDE"), add_suffix, verbose)
        append_rule(rules, ("/applogs/", "*", "INCLUDE"), add_suffix, verbose)
        append_rule(rules, ("/applogs/**/", "*", "INCLUDE"), add_suffix, verbose)
    if os == 'aix' or os == 'linux':
        append_rule(rules, ("^/var/lib/docker/containers/*/", "*.log", "INCLUDE"), add_suffix, verbose)
        if agent_version == 'until-287' or agent_version == 'since-287-until-303':
            append_rule(rules, ("^/var/log/**/", "*", "INCLUDE"), add_suffix, verbose)

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("file_paths", nargs='*', help="absolute file paths to a log files (without symbolic links) to be checked")
parser.add_argument("-i", "--input_file", help="optional input file with newline-separated list of absolute file paths (without symbolic links) to be checked")
parser.add_argument("-c", "--config_filenames", nargs='*', help="optional config file with custom rules")
parser.add_argument("-a", "--agent_version", help="OneAgent/Log Agent version, e.g. 1.303, default value is the newest one")
parser.add_argument("-o", "--os", choices=['aix', 'linux', 'windows'], help="Operating System")
parser.add_argument('-v', "--verbose", action="store_true", help="Verbose output")
parser.add_argument('-n', "--no_version_check", action="store_true", help="Ingore checking whether the newest script version is used")
parser.add_argument('-e', "--use_error_codes", action="store_true", help="Sets non-zero error code in case of success")
parser.add_argument('-g', "--generate_include_config", help="Generates config file including all excluded files")
parser.add_argument('-u', "--generate_using", choices=['whole_paths', 'only_dirs_and_extensions', 'only_dirs', 'only_extensions'], default='whole_paths', help="Controls how wildcards are used in generated config file")
args = parser.parse_args()

try:
    if not args.no_version_check:
        with urlopen( 'https://raw.githubusercontent.com/Dynatrace/Dynatrace-Log-Security-Rules-Checker/refs/heads/main/LogAgentSecurityRulesChecker.py' ) as webpage:
            for line in webpage.read().decode().splitlines():
                match = re.search('# ScriptVersion=(.*)', line)
                if match:
                    newest_script_version = match.group(1)
                    if newest_script_version != current_script_version:
                        print("Warning: you use outdated script version (" + current_script_version + ")! Please update to the newest one (" + newest_script_version + ").", file=sys.stderr)
                    break
            else:
                print("Warning: Cannot determine current script version! Please check manually if your script version (" + current_script_version + ") is the newest one.", file=sys.stderr)
except Exception as ex:
    print("Warning: Cannot determine current script version! Please check manually if your script version (" + current_script_version + ") is the newest one.", file=sys.stderr)
    print("    urlopen failed: " + str(ex))

if args.agent_version == None:
    agent_version = 'since-303'
    if args.verbose:
        print("Using the newest known OneAgent version variant: " + agent_version)
else:
    parsed_agent_version = [int(version_part) for version_part in args.agent_version.split(sep='.')[0:2]]
    if parsed_agent_version < [1, 287]:
        agent_version = 'until-287'
    elif parsed_agent_version < [1, 303]:
        agent_version = 'since-287-until-303'
    else:
        agent_version = 'since-303'
    if args.verbose:
        print("Agent version variant: " + agent_version)


agent_adds_rule_with_suffix_automatically = agent_version != 'until-287' and agent_version != 'since-287-until-303'

rules = []

def config_filepath_sort(path):
    if os.path.split(path)[1] == "_loganalyticsconf.ctl.json":
        return (2, path)
    if os.path.split(path)[1] == "_migratedloganalytics.conf.json":
        return (0, path)
    return (1, path)

if args.config_filenames:
    args.config_filenames.sort(reverse=True, key=config_filepath_sort)

    for config_filename in args.config_filenames:
        if args.verbose:
            print("loading configuration file with custom rules: " + config_filename)
        with open(config_filename, 'r') as config_file:
            for item in json.loads(config_file.read())["allowed-log-paths-configuration"]:
                rule = (item["directory-pattern"], item["file-pattern"], item["action"])
                if rule[2] != "INCLUDE" and rule[2] != "EXCLUDE":
                    raise RuntimeError("invalid action type (only INCLUDE and EXCLUDE are allowed): " + rule[2])
                append_rule(rules, rule, agent_adds_rule_with_suffix_automatically, args.verbose)

add_default_rules(rules, agent_adds_rule_with_suffix_automatically, agent_version, args.os, args.verbose)

file_paths = args.file_paths
if args.input_file:
    with open(args.input_file, 'r') as input_file:
        file_paths.extend(filter(None, (line.strip() for line in input_file)))
if args.verbose:
    print ("File paths to be checked: " + ', '.join(file_paths))

if len(file_paths) != 1 and args.use_error_codes:
    raise RuntimeError("You should not '--use_error_codes' with multiple input paths") 

if args.generate_include_config and args.use_error_codes:
    raise RuntimeError("You should not '--use_error_codes' with '--generate_include_config'") 

excluded_paths = []

for file_path in file_paths:
    if args.verbose:
        print ("Matching '" + file_path + "'...")
    (dir_part, file_part) = os.path.split(os.path.splitdrive(file_path)[1])
    dir_part = dir_part.replace('\\', '/') + "/"

    for (dir_pattern, file_pattern, action) in rules:
        if args.os == 'windows':
            dir_pattern = dir_pattern.replace('\\', '/')
        (dir_match, file_match) = (match_dirs(dir_pattern, dir_part), match_files(file_pattern, file_part))
        if args.verbose:
            print ("Try to match rule { " + dir_pattern + " }{ " + file_pattern + " }{ " + action + " } to { " + dir_part + " }{ " + file_part + " } --- ", end="")
            if dir_match:
                print ("directory part MATCHED, ", end="")
            else:
                print ("directory part NOT matched, ", end="")
            if file_match:
                print ("file part MATCHED --- ", end="")
            else:
                print ("file part NOT matched --- ", end="")
        if dir_match and file_match:
            if args.verbose:
                print("the rule is matched. '" + file_path + "' is " + action + "D.")
            else:
                print ("'" + file_path + "' is " + action + "D. Check verbose logs for more details.")
            if action == "EXCLUDE":
                excluded_paths.append(file_path)
            if args.use_error_codes:
                if action == "INCLUDE":
                    sys.exit(64)
                else:
                    sys.exit(65)
            break
        else:
            if args.verbose:
                print("the rule is not matched.")
    else:
        if args.verbose:
            print("No rule has been matched. '" + file_path + "' is EXCLUDED.")
        else:
            print("'" + file_path + "' is EXCLUDED. Check verbose logs for more details.")
        excluded_paths.append(file_path)
        if args.use_error_codes:
            sys.exit(66)

if args.generate_include_config and len(excluded_paths) > 0:
    if args.verbose:
        print("Generating new config file '" + args.generate_include_config + "' with option " + args.generate_using, end="")
        if agent_adds_rule_with_suffix_automatically:
            print(".")
        else:
            print(" including additional rules with rotation suffixes (needed for selected OneAgent version).")
    rule_list = []
    for path in excluded_paths:
        (dir_part, file_part) = os.path.split(os.path.splitdrive(path)[1])
        dir_part = dir_part.replace('\\', '/') + "/"
        if args.generate_using == 'only_extensions':
            dir_part = '/'
        if args.generate_using == 'only_dirs':
            file_part = '*'
        if args.generate_using == 'only_extensions' or args.generate_using == 'only_dirs_and_extensions':
            ext_start = file_part.find('.')
            if ext_start != -1:
                ext_second_start = file_part.find('.', ext_start + 1)
                if ext_second_start != -1:
                    file_part = '*' + file_part[ext_start:ext_second_start]
                else:
                    file_part = '*' + file_part[ext_start:]
        rule_list.append((dir_part, file_part))
        if not agent_adds_rule_with_suffix_automatically and file_part != '*':
            rule_list.append((dir_part, file_part + rotation_suffix))
    rule_list_text = []
    for (dir_part, file_part) in rule_list:
        rule = '    {\n'
        rule += '      "directory-pattern":"' + dir_part.replace('\\', '\\\\') + '",\n'
        rule += '      "file-pattern":"' + file_part.replace('\\', '\\\\') + '",\n'
        rule += '      "action":"INCLUDE"\n'
        rule += '    }'
        rule_list_text.append(rule)
    with open(args.generate_include_config, 'w', newline='\n') as config_output:
        config_output.write('{\n')
        config_output.write('  "@version":"1.0.0",\n')
        config_output.write('  "allowed-log-paths-configuration":[\n')
        config_output.write(',\n'.join(sorted(list(set({v.casefold(): v for v in rule_list_text}.values())))) + '\n')
        config_output.write('  ]\n')
        config_output.write('}\n')
