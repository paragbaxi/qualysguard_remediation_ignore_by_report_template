#!/usr/bin/env python
__author__ = 'Parag Baxi <parag.baxi@gmail.com>'

''' $ python qualysguard_remediation_ignore_non-running_kernels.py ALL_VULNS_XML_REPORT EXCLUDE_NON-RUNNING_KERNEL_VULNS_XML_REPORT

'''

import sys
import time
try:
    from lxml import etree
except ImportError:
    try:
        # Python 2.5
        import xml.etree.cElementTree as etree
    except ImportError:
        try:
            # Python 2.5
            import xml.etree.ElementTree as etree
        except ImportError:
            try:
                # normal cElementTree install
                import cElementTree as etree
            except ImportError:
                try:
                    # normal ElementTree install
                    import elementtree.ElementTree as etree
                except ImportError:
                    print("Failed to import ElementTree from any known place.")
                    exit(1)

# Read in first vulns XML report.
tree = etree.parse(sys.argv[1])
# Find all TICKET_NUMBER elements that contain associated remediation ticket numbers.
vulns1 = tree.findall(".//TICKET_NUMBER")
# Read in second vulns XML report.
tree = etree.parse(sys.argv[2])
# Find all TICKET_NUMBER elements that contain associated remediation ticket numbers.
vulns2 = tree.findall(".//TICKET_NUMBER")
# Figure out by size which report is the all vulns report vs the exclude non-running kernel report.
if len(vulns1) > len(vulns2):
    all_vulns = vulns1
    exclude_nonrunning_kernel_vulns = vulns2
else:
    all_vulns = vulns2
    exclude_nonrunning_kernel_vulns = vulns1
# Extract associated text of above elements.
all_vulns_tickets = set()
# Parse elements for associated ticket number text.
for e in all_vulns:
    all_vulns_tickets.add(e.text)
# Extract associated text of above elements.
exclude_nonrunning_kernel_vulns_tickets = set()
# Parse elements for associated ticket number text.
for e in exclude_nonrunning_kernel_vulns:
    exclude_nonrunning_kernel_vulns_tickets.add(e.text)
# Communicate metrics.
print 'Total number of vulnerabilities found:', len(all_vulns_tickets)
print 'Total number of vulnerabilities found ignoring inactive kernels:', len(exclude_nonrunning_kernel_vulns_tickets)
# Find delta of ticket numbers which are the tickets for non-running kernel vulns.
nonrunning_kernel_vulns_tickets = all_vulns_tickets.difference(exclude_nonrunning_kernel_vulns_tickets)
print 'Number of inactive vulnerabilites found:', len(nonrunning_kernel_vulns_tickets)
# Print ticket numbers to file.
timestr = time.strftime("%Y%m%d-%H%M%S")
filename = 'inactive_kernel_ticket_numbers_%s.txt' % timestr
print 'Ticket numbers of inactive vulnerabilites found exported to %s' % filename
# Combine all tickets with newline in between.
output = "\n".join(i for i in nonrunning_kernel_vulns_tickets)
with open(filename, 'w') as the_file:
    the_file.write(output)
