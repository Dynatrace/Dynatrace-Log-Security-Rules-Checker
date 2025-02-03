# Dynatrace Log Security Rules Checker

[Log monitoring security rules](https://docs.dynatrace.com/docs/observe-and-explore/logs/lma-log-ingestion/lma-log-ingestion-via-oa/lma-security-rules) protect non-logs from customers' environments (like configs and secrets) from being ingested and accessed by bad actors. This is a necessary layer of security. It is essential to understand how overriding the default configuration works.

Dynatrace Log Security Rules Checker is a standalone tool (in a form of an open-source script) which allows for testing security rules. It helps with the following use cases when:
* you want to check if your log filepath is allowed or you need to add a custom security rule config file,
* you want to validate your custom configuration file before you upload it to Log Agent,
* you want to troubleshoot why security rule configuration works another way than you expected.

Technology: Python 3. No non-standard dependencies.

## Support lifecycle

Dynatrace Log Security Rules Checker is a standalone tool (in a form of Python3 script) which is updated every time when default Security Rules change (which is pretty rare). The script automatically checks whether you use the current version (which might be disabled by using `-n` option).

It is supported by Dynatrace Incorporated, support is provided by the Dynatrace Support team, as described on the [support page](https://support.dynatrace.com/).
Github issues will also be considered on a case-by-case basis regardless of support contracts and commercial relationships with Dynatrace.

## Usage

`LogAgentSecurityRuleChecker.py --help` displays all the options.

`LogAgentSecurityRulesChecker.py -o linux /usr/sap/BQH/HDB03/cssbq3d01/trace/available.log` - check if given log filepath is accepted on Linux. The path needs to be absolute, with all symbolic links resolved.

`LogAgentSecurityRulesChecker.py -a 1.301 -o linux /usr/sap/BQH/HDB03/cssbq3d01/trace/available.log` - check if it is accepted by older agent version.

`LogAgentSecurityRulesChecker.py -a 1.301 -o linux /usr/sap/BQH/HDB03/cssbq3d01/trace/available.log -g custom_config.json` - if it is not accepted, generate custom security rule configuration file which can be provided to OneAgent to make it accept the log file.

`LogAgentSecurityRulesChecker.py -a 1.301 -o linux /usr/sap/BQH/HDB03/cssbq3d01/trace/available.log -c already_present_config.json` - check also against custom security rule configuration file.

`LogAgentSecurityRulesChecker.py -a 1.301 -o linux -i my_file_with_multiple_paths_to_check.txt` - load log filepaths from an input file.

In all cases the `--verbose` option provides a lot of explanation why given log file meets security criteria or not.

### Use-case example

I have OneAgent 1.301 and I would like to monitor a file `/usr/sap/BQH/HDB03/cssbq3d01/trace/available.log`. I run `LogAgentSecurityRulesChecker.py -a 1.301 -o linux /usr/sap/BQH/HDB03/cssbq3d01/trace/available.log` and get:
```
'/usr/sap/BQH/HDB03/cssbq3d01/trace/available.log' is EXCLUDED. Check verbose logs for more details.
```
so the file does not meet security criteria. I am checking the details by running with verbose option `LogAgentSecurityRulesChecker.py -a 1.301 -o linux /usr/sap/BQH/HDB03/cssbq3d01/trace/available.log -v` and get:
```
Agent version variant: since-287-until-303
[...]
Try to match rule { ^/usr/**/ }{ * }{ EXCLUDE } to { /usr/sap/BQH/HDB03/cssbq3d01/trace/ }{ available.log } --- directory part MATCHED, file part MATCHED --- the rule is matched. '/usr/sap/BQH/HDB03/cssbq3d01/trace/available.log' is EXCLUDED.
```

I see that the default security rules have changed since version 1.303, so I am checking if upgrading OneAgent solves the issue `LogAgentSecurityRulesChecker.py -o linux /usr/sap/BQH/HDB03/cssbq3d01/trace/available.log -v`:
```
Using the newest known Agent version variant: since-303
[...]
Try to match rule { / }{ *[-.\_]log }{ INCLUDE } to { /usr/sap/BQH/HDB03/cssbq3d01/trace/ }{ available.log } --- directory part MATCHED, file part MATCHED --- the rule is matched. '/usr/sap/BQH/HDB03/cssbq3d01/trace/available.log' is INCLUDED.
```
and I see that since version 1.303 the file will be monitored on default security rules.

In case I cannot upgrade (or if upgrade would not solve the issue, or if I already use the latest version) I need to alter the security rules. I can write a custom config file manually, but the tool can do it for me `LogAgentSecurityRulesChecker.py -a 1.301 -o linux -n /usr/sap/BQH/HDB03/cssbq3d01/trace/available.log -g my_config.json -v`:
```
[...]
Generating new config file 'my_config.json' with option whole_paths and automatic rotation suffixes.
```

Let's double-check if the log file passes security rules when my custom configuration file is provided `LogAgentSecurityRulesChecker.py -a 1.301 -o linux -n /usr/sap/BQH/HDB03/cssbq3d01/trace/available.log -c my_config.json -v`:
```
Agent version variant: since-287-until-303
loading configuration file with custom rules: my_config.json
Adding a new rule with directory pattern = "/usr/sap/BQH/HDB03/cssbq3d01/trace/" filepattern = "available.log" and action = "INCLUDE"
Adding a new rule with directory pattern = "/usr/sap/BQH/HDB03/cssbq3d01/trace/" filepattern = "available.log[-.\_]*" and action = "INCLUDE"
loading default configuration rules
[...]
File paths to be checked: /usr/sap/BQH/HDB03/cssbq3d01/trace/available.log
Matching '/usr/sap/BQH/HDB03/cssbq3d01/trace/available.log'...
Try to match rule { /usr/sap/BQH/HDB03/cssbq3d01/trace/ }{ available.log }{ INCLUDE } to { /usr/sap/BQH/HDB03/cssbq3d01/trace/ }{ available.log } --- directory part MATCHED, file part MATCHED --- the rule is matched. '/usr/sap/BQH/HDB03/cssbq3d01/trace/available.log' is INCLUDED.
```
and we can see that the log file is indeed accepted. Now I only need to deploy the custom configuration file to the host running OneAgent.

## License

Dynatrace Log Security Rules Checker is under Apache 2.0 license. See [LICENSE](LICENSE) for details.