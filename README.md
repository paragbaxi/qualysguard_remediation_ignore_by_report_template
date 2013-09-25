qualysguard_remediation_ignore_non-running_kernels
==================================================

Mark QualysGuard remediation tickets ignored that are linked to vulnerabilities from non-running kernels.

Example
=======

The XML file and ticket number text file is found under the directory example.

Example run output:

	$ python qualysguard_remediation_ignore_non-running_kernels.py Scan_Report_exclude_non_running_kernels.xml Scan_Report_do_not_exclude_non_running_kernels.xml 
	Total number of vulnerabilities found: 3106
	Total number of vulnerabilities found ignoring inactive kernels: 3083
	Number of inactive vulnerabilites found: 23
	Ticket numbers of inactive vulnerabilites found exported to inactive_kernel_ticket_numbers_20130925-105135.txt