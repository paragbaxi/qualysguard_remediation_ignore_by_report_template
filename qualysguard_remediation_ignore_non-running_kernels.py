#!/usr/bin/env python
__author__ = 'Parag Baxi <parag.baxi@gmail.com>'

''' $ python qualysguard_remediation_ignore_non-running_kernels.py ALL_VULNS_XML_REPORT EXCLUDE_NON-RUNNING_KERNEL_VULNS_XML_REPORT

'''

import argparse
import datetime, logging, os
import qualysapi
import time
import types

from StringIO import StringIO

try:
    from lxml import etree, objectify
except ImportError:
    try:
        # Python 2.5
        import xml.etree.cElementTree as etree
    except ImportError:
        print("Failed to import ElementTree from any known place.")
        exit(1)

def load_scan(report_template, report_title):
    """ Returns an objectified QualysGuard scan report of QualysGuard's scan's scan_ref.

    """
    global qgc
    # Generate report.
    print 'Generating report against %s ...' % (report_template),
    request_parameters = {'action': 'launch', 'template_id': str(report_template), 'report_type': 'Scan', 'output_format': 'xml', 'report_title': report_title}
    logger.debug(request_parameters)
    xml_output = qgc.request('api/2.0/fo/report', request_parameters)
    report_id = etree.XML(xml_output).find('.//VALUE').text
    logger.debug('report_id: %s' % (report_id))
    # Wait for report to finish spooling.
    # Time in seconds to wait between checks.
    POLLING_DELAY = 30
    # Time in seconds to wait before checking.
    STARTUP_DELAY = 30
    # Maximum number of times to check for report.  About 10 minutes.
    MAX_CHECKS = 10
    print 'Report sent to spooler. Checking for report in %s seconds.' % (STARTUP_DELAY)
    time.sleep(STARTUP_DELAY)
    for n in range(0, MAX_CHECKS):
        # Check to see if report is done.
        xml_output = qgc.request('api/2.0/fo/report', {'action': 'list', 'id': report_id})
        # Store XML.
        with open('scan.xml', 'w') as text_file:
            text_file.write(xml_output)
        tag_status = etree.XML(xml_output).findtext(".//STATE")
        print tag_status
        logger.debug('tag_status: %s' % (tag_status))
        if not type(tag_status) == types.NoneType:
            # Report is showing up in the Report Center.
            if tag_status == 'Finished':
                # Report creation complete.
                break
        # Report not finished, wait.
        print 'Report still spooling. Trying again in %s seconds.' % (POLLING_DELAY)
        time.sleep(POLLING_DELAY)
    # We now have to fetch the report. Use the report id.
    report_xml = qgc.request('api/2.0/fo/report', {'action': 'fetch', 'id': report_id})
    print 'done.'
    # Store XML.
    # with open(scan_filename, 'w') as text_file:
    #     text_file.write(report_xml)
    # Return XML.
    return StringIO(report_xml)

# Start of script.
# Declare the command line flags/options we want to allow.
parser = argparse.ArgumentParser(description = 'Mark QualysGuard remediation tickets Closed/Ignored that are linked to vulnerabilities from non-running kernels.')
parser.add_argument('-a', '--all_vulns_template_id',
                   help = 'Report template ID that displays all vulnerabilities.')
parser.add_argument('-A', '--all_vulns_xml',
                    help = 'XML report that displays all vulnerabilities. Supercedes all_vulns_template_id.')
parser.add_argument('-c', '--comment', default = 'Programmatically marked vulnerability on non-running kernel Closed/Ignored.',
                    help = 'Comment to include on remediation ticket. (Default = Programmatically marked vulnerability on non-running kernel Closed/Ignored.)')
parser.add_argument('-e', '--exclude_non_running_kernel_vulns_report_template_id',
                   help = 'Report template ID that excludes non-running kernel vulnerabilities.')
parser.add_argument('-E', '--exclude_non_running_kernel_vulns_xml',
                    help = 'XML report that excludes non-running kernel vulnerabilities. Supercedes exclude_non_running_kernel_vulns_report_template_id.')
parser.add_argument('-r', '--reopen_ignored_days',
                    help = 'Used to reopen Closed/Ignored tickets in a set number of days. Specify the due date in N days, where N is a number of days from today.')
parser.add_argument('-t', '--title', default="Programmatically mark non-running kernel remediation tickets Closed/Ignored.",
                    help = 'Title of report to launch. (Default: Programmatically mark non-running kernel remediation tickets Closed/Ignored.')
parser.add_argument('-v', '--verbose', action = 'store_true',
                    help = 'Outputs additional information to log.')
parser.add_argument('-w', '--write_remediation_ticket_numbers_to_file', action='store_true',
                    help = 'Outputs remediation ticket numbers to file. (Default: Enabled.)')
parser.add_argument('-x', '--mark_remediation_tickets_resolved_ignore', action='store_true',
                    help = 'Automatically mark remediation tickets Closed/Ignored that are linked to vulnerabilities from non-running kernels.')
parser.add_argument('--config',
                    help = 'Configuration for Qualys connector.')
# Parse arguments.
c_args = parser.parse_args()
# Set log directory.
PATH_LOG = 'log'
if not os.path.exists(PATH_LOG):
    os.makedirs(PATH_LOG)
LOG_FILENAME = '%s/%s.log' % (PATH_LOG, datetime.datetime.now().strftime('%Y-%m-%d.%H-%M-%S'))
# My logging.
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# logger.propagate = False
# Set log options.
logging_level = logging.INFO
# Log qualysapi.
logger_qc = logging.getLogger('qualysapi.connector')
if c_args.verbose:
    logging_level = logging.DEBUG
logger_qc.setLevel(logging_level)
# Create file handler logger.
logger_file = logging.FileHandler(LOG_FILENAME)
logger_file.setLevel(logging_level)
logger_file.setFormatter(logging.Formatter('%(asctime)s %(name)-12s %(levelname)s %(funcName)s %(lineno)d %(message)s','%m-%d %H:%M'))
# Define a Handler which writes WARNING messages or higher to the sys.stderr.
logger_console = logging.StreamHandler()
logger_console.setLevel(logging.ERROR)
# Set a format which is simpler for console use.
# Tell the handler to use this format.
logger_console.setFormatter(logging.Formatter('%(name)-12s: %(levelname)-8s %(lineno)d %(message)s'))
# Add the handlers to the loggers
logger.addHandler(logger_file)
if c_args.verbose:
    logger.addHandler(logger_console)
# logger_qc.addHandler(logger_file)
# logger_qc.addHandler(logger_console)
# Validate arguments.
if (not (c_args.all_vulns_template_id or c_args.all_vulns_xml) and (c_args.exclude_non_running_kernel_vulns_report_template_id or c_args.exclude_non_running_kernel_vulns_xml)):
# if (not (c_args.all_vulns_xml and c_args.exclude_non_running_kernel_vulns_xml)):
    print 'One of each report is required.'
    parser.print_help()
    exit(1)
# Configure Qualys API connector.
if (c_args.mark_remediation_tickets_resolved_ignore or c_args.all_vulns_template_id or c_args.exclude_non_running_kernel_vulns_report_template_id):
    if c_args.config:
        qgc = qualysapi.connect(c_args.config)
    else:
        qgc = qualysapi.connect()
#
# Read in XML report including non-running kernels.
if c_args.all_vulns_xml:
    # Read in XML file.
    tree = etree.parse(c_args.all_vulns_xml)
else:
    # Grab XML from QualysGuard.
    tree = etree.parse(load_scan(c_args.all_vulns_template_id, c_args.title))
# Find all TICKET_NUMBER elements that contain associated remediation ticket numbers.
all_vulns = tree.findall(".//TICKET_NUMBER")
# Read in XML report excluding non-running kernels.
if c_args.exclude_non_running_kernel_vulns_xml:
    # Read in XML file.
    tree = etree.parse(c_args.exclude_non_running_kernel_vulns_xml)
else:
    # Grab XML from QualysGuard.
    tree = etree.parse(load_scan(c_args.exclude_non_running_kernel_vulns_report_template_id,  c_args.title))
# Find all TICKET_NUMBER elements that contain associated remediation ticket numbers.
exclude_nonrunning_kernel_vulns = tree.findall(".//TICKET_NUMBER")
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
# Write ticket numbers to file, if requested.
if c_args.write_remediation_ticket_numbers_to_file:
    timestr = time.strftime("%Y%m%d-%H%M%S")
    filename = 'non-active_kernels_ticket_numbers_%s.txt' % timestr
    # Combine all tickets with newline in between.
    output = "\n".join(i for i in nonrunning_kernel_vulns_tickets)
    with open(filename, 'w') as the_file:
        the_file.write(output)
    print 'Ticket numbers of non-running kernels vulnerabilities exported to %s file.' % filename
if not c_args.mark_remediation_tickets_resolved_ignore:
    exit(0)
# Combine all tickets with comma in between.
tickets_to_mark_ignored = ','.join(i for i in nonrunning_kernel_vulns_tickets)
print 'Marking QualysGuard remediation tickets ignored that are linked to vulnerabilities from non-running kernels...'
if c_args.reopen_ignored_days:
    parameters = {'ticket_numbers': tickets_to_mark_ignored, 'change_state': 'IGNORED', 'add_comment': c_args.comment, 'reopen_ignored_days': c_args.reopen_ignored_days}
else:
    parameters = {'ticket_numbers': tickets_to_mark_ignored, 'change_state': 'IGNORED', 'add_comment': c_args.comment}
output_xml = qgc.request('ticket_edit.php', parameters)
print 'Completed.'