qualysguard_remediation_ignore_non-running_kernels
==================================================

Mark QualysGuard remediation tickets ignored that are linked to vulnerabilities from non-running kernels.

Instructions
=====

Python 2.6+ script proof of concept that will take in 2 Qualys XML vulnerability scan reports. The two XML vulnerability scan reports input parameters are (order does not matter):

- All vulns.
- All vulns with option to ignore inactive kernel vulnerabilities.

The script then extracts the remediation tickets numbers for vulnerabilities that were discovered on an inactive kernel. Note that this is on a per host level, not at a per QID level.

The script then prints out the ticket numbers to a file: inactive_kernel_ticket_numbers_DATE_TIME.txt

Workflow
========

Below is the workflow to be able to ignore inactive kernel vulnerabilities for raw data downloaded via the API.

1. Generate report daily or whatever frequency for all vulns for target asset groups.
2. Generate report daily or whatever frequency for (all vulns -  ignore inactive vulns).
3. Find delta vulns.
    - Delta vulns does not mean finding deltas at the QID level. This is making a dangerous assumption in which a QID discovered on a host's inactive kernel is also only discovered on other hosts' inactive kernels. It is very likely that this is not the case if you do not have the exact same configuration across all hosts.
    - I recommend performing the delta on a more granular level, at the individual vulnerability per host level.
4. Find remediation tickets corresponding to delta vulns.
5. Important, this step is out of scope for this script. Programmatically resolve-ignore vulns with comment like, "Discovered on inactive kernel" via cron job run daily or whatever frequency.
    - Make sure to prepend any necessary '0's in your call. For example, to ignore tickets from ticket # 1800 to ticket # 2800, use the following URL:

            https://qualysapi.qualys.com/msp/ticket_edit.php?change_state=IGNORED&add_comment=Vulnerability+on+non-running+kernel.&ticket_numbers=001800-002800


Example
=======

The XML file and ticket number text file is found under the directory example.

Example run output:

	$ python qualysguard_remediation_ignore_non-running_kernels.py example/Scan_Report_exclude_non_running_kernels.xml example/Scan_Report_do_not_exclude_non_running_kernels.xml 
	Total number of vulnerabilities found: 3106
	Total number of vulnerabilities ignoring non-running kernels found: 3083
	Number of vulnerabilites found on non-running kernels: 23
	Ticket numbers of non-running kernels vulnerabilities exported to inactive_kernel_ticket_numbers_20130925-105135.txt
