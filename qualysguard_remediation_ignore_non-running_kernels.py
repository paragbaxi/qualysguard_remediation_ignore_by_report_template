#!/usr/bin/env python
__author__ = 'Parag Baxi <parag.baxi@gmail.com>'

''' $ python qualysguard_remediation_ignore_non-running_kernels.py ALL_VULNS_XML_REPORT EXCLUDE_NON-RUNNING_KERNEL_VULNS_XML_REPORT

'''

import argparse
import datetime, logging, os
import qualysapi
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

# Start of script.
# Declare the command line flags/options we want to allow.
parser = argparse.ArgumentParser(description = 'Mark QualysGuard remediation tickets ignored that are linked to vulnerabilities from non-running kernels.')
# TODO
#parser.add_argument('-a', '--all_vulns_template_id',
#                    help = 'Report template ID that displays all vulnerabilities.')
parser.add_argument('-A', '--all_vulns_xml',
                    help = 'XML report that displays all vulnerabilities. Supercedes all_vulns_template_id.')
parser.add_argument('-c', '--comment', default = 'Programmatically marked vulnerability on non-running kernel ignored.',
                    help = 'Comment to include on remediation ticket. (Default = Programmatically marked vulnerability on non-running kernel ignored.)')
# TODO
#parser.add_argument('-e', '--exclude_non_running_kernel_vulns_report_template_id',
#                    help = 'Report template ID that excludes non-running kernel vulnerabilities.')
parser.add_argument('-E', '--exclude_non_running_kernel_vulns_xml',
                    help = 'XML report that excludes non-running kernel vulnerabilities. Supercedes exclude_non_running_kernel_vulns_report_template_id.')
parser.add_argument('-x', '--mark_remediation_tickets_resolved_ignore', action='store_true',
                    help = 'Automatically mark remediation tickets ignored that are linked to vulnerabilities from non-running kernels.')
parser.add_argument('--config',
                    help = 'Configuration for Qualys connector.')
# Parse arguments.
c_args = parser.parse_args()
# Create log directory.
PATH_LOG = 'log'
if not os.path.exists(PATH_LOG):
    os.makedirs(PATH_LOG)
# Set log options.
now = datetime.datetime.now()
LOG_FILENAME = '%s/%s-%s.log' % (PATH_LOG,
                                 __file__,
                                 datetime.datetime.now().strftime('%Y-%m-%d.%H-%M-%S'))
# Set logging level.
logging.basicConfig(filename = LOG_FILENAME, format = '%(asctime)s %(message)s',
                    level = logging.INFO)
# Validate arguments.
# TODO
# if (not (c_args.all_vulns_template_id or c_args.all_vulns_xml) and (c_args.exclude_non_running_kernel_vulns_report_template_id or c_args.exclude_non_running_kernel_vulns_xml)):
if (not (c_args.all_vulns_xml and c_args.exclude_non_running_kernel_vulns_xml)):
    print 'One of each report is required.'
    parser.print_help()
    exit(1)
# Configure Qualys API connector.
if c_args.mark_remediation_tickets_resolved_ignore:
    if c_args.config:
        qgc = qualysapi.connect(c_args.config)
    else:
        qgc = qualysapi.connect()
#
# Read in first vulns XML report.
tree = etree.parse(c_args.all_vulns_xml)
# Find all TICKET_NUMBER elements that contain associated remediation ticket numbers.
vulns1 = tree.findall(".//TICKET_NUMBER")
# Read in second vulns XML report.
tree = etree.parse(c_args.exclude_non_running_kernel_vulns_xml)
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
print 'Total number of vulnerabilities ignoring non-running kernels found:', len(exclude_nonrunning_kernel_vulns_tickets)
# Find delta of ticket numbers which are the tickets for non-running kernel vulns.
nonrunning_kernel_vulns_tickets = all_vulns_tickets.difference(exclude_nonrunning_kernel_vulns_tickets)
print 'Number of vulnerabilites found on non-running kernels:', len(nonrunning_kernel_vulns_tickets)
# Print ticket numbers to file.
timestr = time.strftime("%Y%m%d-%H%M%S")
filename = 'non-active_kernels_ticket_numbers_%s.txt' % timestr
print 'Ticket numbers of non-running kernels vulnerabilities exported to %s file.' % filename
# Combine all tickets with newline in between.
output = "\n".join(i for i in nonrunning_kernel_vulns_tickets)
with open(filename, 'w') as the_file:
    the_file.write(output)
if not c_args.mark_remediation_tickets_resolved_ignore:
    exit(0)
# Combine all tickets with comma in between.
tickets_to_mark_ignored = ','.join(i for i in nonrunning_kernel_vulns_tickets)
print 'Marking QualysGuard remediation tickets ignored that are linked to vulnerabilities from non-running kernels...'
output_xml = qgc.request('ticket_edit.php',{'ticket_numbers': tickets_to_mark_ignored, 'change_state': 'IGNORED', 'add_comment': c_args.comment})
with open('output.xml', 'w') as the_file:
    the_file.write(output_xml)
