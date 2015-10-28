import os
import sys
import argparse
from collections import defaultdict
import netsnmp
import json

__author__ = 'peter (att) simiya.com (Peter Harrison)'

def main():
    """Main Function

    1) Processes CLI arguments
    2) Determines whether the device is accessible
    3) If accesible print a json file that maps interface
       number to interface name and description
         name provided on the CLI
    """

    # Process the CLI
    (snmpcmd) = process_cli()

    # Get sysID
    device_oid_id = get_sys_object_id(snmpcmd)

    # Stop completely before creating new files if SNMP
    # isn't working
    if not device_oid_id:
        print ('ERROR: Cannot contact %s. Check connectivity or '
    'SNMP parameters') % (snmpcmd['ipaddress'])
        sys.exit(2)

    do_mib_interfaces_mapping(snmpcmd)

def is_number(val):
    """Check if argument is a number

    Args:
        val: String to check

    Returns:
        True if a number
    """

    try:
        float(val)
        return True
    except ValueError:
        return False

def get_oid_last_octet(oid):
    """Get the last octet of OID

    Args:
        oid: OID to check

    Returns:
        Last octet
    """

    octets = oid.split('.')
    return octets[-1]

def do_snmpwalk(snmpcmd, oid_to_get):
    """Do an SNMPwalk

    Args:
        snmpcmd: SNMP variables required to do SNMP queries on device
        oid_to_get: OID to walk

    Returns:
        Dictionary of tuples (OID, value)
    """

    return do_snmpquery(snmpcmd, oid_to_get, False)

def do_snmpget(snmpcmd, oid_to_get):
    """Do an SNMPget

    Args:
        snmpcmd: SNMP variables required to do SNMP queries on device
        oid_to_get: OID to walk

    Returns:
        Dictionary of tuples (OID, value)
    """

    return do_snmpquery(snmpcmd, oid_to_get, True)

def do_snmpquery(snmpcmd, oid_to_get, snmpget):
    """Do an SNMP query

    Args:
        snmpcmd: SNMP variables required to do SNMP queries on device
        oid_to_get: OID to walk
        snmpget: Flag determining whether to do a GET or WALK

    Returns:
        Dictionary of tuples (OID, value)
    """

    # Initialize variables
    return_results = {}
    results_objs = False
    session = False

    # Get OID
    try:
        session = netsnmp.Session(DestHost=snmpcmd['ipaddress'],
            Version=snmpcmd['version'], Community=snmpcmd['community'],
            SecLevel='authPriv', AuthProto=snmpcmd['authprotocol'],
            AuthPass=snmpcmd['authpassword'], PrivProto=snmpcmd['privprotocol'],
            PrivPass=snmpcmd['privpassword'], SecName=snmpcmd['secname'],
            UseNumeric=True)
        results_objs = netsnmp.VarList(netsnmp.Varbind(oid_to_get))

        if snmpget:
            session.get(results_objs)
        else:
            session.walk(results_objs)

    except Exception as exception_error:
    # Check for errors and print out results
        print ('ERROR: Occurred during SNMPget for OID %s from %s: '
               '(%s)') % (oid_to_get, snmpcmd['ipaddress'], exception_error)
        sys.exit(2)

    # Crash on error
    if (session.ErrorStr):
        print ('ERROR: Occurred during SNMPget for OID %s from %s: '
               '(%s) ErrorNum: %s, ErrorInd: %s') % (
                oid_to_get, snmpcmd['ipaddress'], session.ErrorStr,
                session.ErrorNum, session.ErrorInd)
        sys.exit(2)

    # Construct the results to return
    for result in results_objs:
        if is_number(result.val):
            return_results[('%s.%s') % (result.tag, result.iid)] = (
                float(result.val))
        else:
            return_results[('%s.%s') % (result.tag, result.iid)] = (
                result.val)

    return return_results

def get_sys_object_id(snmpcmd):
    """Get the sysObjectID of the device

    Args:
        snmpcmd: SNMP variables required to do SNMP queries on device

    Returns:
        val: OID value
    """

    sysobjectid = '.1.3.6.1.2.1.1.2.0'
    snmp_results = do_snmpget(snmpcmd, sysobjectid)
    for val in snmp_results.values():
        return val

def do_mib_interfaces_mapping(snmpcmd):
    """Create interface mappings

    Args:
        snmpcmd: SNMP variables required to do SNMP queries on device

    Returns:
        Nothing
    """

    # Initialize variables
    ifmap = defaultdict(lambda: defaultdict(dict))

    # Descriptions
    ifdesc_oid = '.1.3.6.1.2.1.2.2.1.2'
    ifdesc_results = do_snmpwalk(snmpcmd, ifdesc_oid)
    for oid, val in sorted(ifdesc_results.items()):
        last_octet = get_oid_last_octet(oid)
        ifmap[last_octet]['desc'] = val

    # Names
    ifname_oid = '.1.3.6.1.2.1.31.1.1.1.1'
    ifname_results = do_snmpwalk(snmpcmd, ifname_oid)
    for oid, val in sorted(ifname_results.items()):
        last_octet = get_oid_last_octet(oid)
        ifmap[last_octet]['name'] = val

    # Index
    ifindex_oid = '.1.3.6.1.2.1.2.2.1.1'
    ifindex_results = do_snmpwalk(snmpcmd, ifindex_oid)
    for oid, val in sorted(ifindex_results.items()):
        last_octet = get_oid_last_octet(oid)
        ifmap[last_octet]['index'] = int(val)

    # Print mapping
    print json.dumps(ifmap)

def process_cli():
    """Process command line args

    Args:
        None

    Returns:
        snmpcmd: SNMP variables required to do SNMP queries on device
    """

    # Initialize SNMP variables
    snmpcmd = {}
    snmpcmd['community'] = None
    snmpcmd['ipaddress'] = None
    snmpcmd['secname'] = None
    snmpcmd['version'] = None
    snmpcmd['authpassword'] = None
    snmpcmd['authprotocol'] = None
    snmpcmd['privpassword'] = None
    snmpcmd['privprotocol'] = None
    snmpcmd['port'] = 161

    # Parse the CLI
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', help='SNMP version',
        type=int, required=True)
    parser.add_argument('-c', '--community', help='SNMPv2 community string')
    parser.add_argument('-i', '--ipaddress',
        help='IP address of device to query', required=True)
    parser.add_argument('-u', '--secname', help='SNMPv3 secname')
    parser.add_argument('-A', '--authpassword', help='SNMPv3 authpassword')
    parser.add_argument('-a', '--authprotocol',
        help='SNMPv3 authprotocol (MD5, SHA)')
    parser.add_argument('-X', '--privpassword', help='SNMPv3 privpassword')
    parser.add_argument('-x', '--privprotocol',
        help='SNMPv3 privprotocol (DES, 3DES, AES128)')
    parser.add_argument('--port', help='SNMP UDP port', type=int)

    # Parse arguments and die if error
    try:
        args = parser.parse_args()
    except Exception:
        sys.exit(2)

    # Assign and verify SNMP arguments
    if args.version:
        snmpcmd['version'] = args.version
    if args.community:
        snmpcmd['community'] = args.community
    if args.ipaddress:
        snmpcmd['ipaddress'] = args.ipaddress
    if (snmpcmd['version'] != 2) and (snmpcmd['version'] != 3):
        print 'ERROR: Only SNMPv2 and SNMPv3 are supported'
        sys.exit(2)
    if args.secname:
        snmpcmd['secname'] = args.secname
    if (not snmpcmd['secname']) and (snmpcmd['version'] == 3):
        print 'ERROR: SNMPv3 must specify a secname'
        sys.exit(2)
    if args.authpassword:
        snmpcmd['authpassword'] = args.authpassword
    if args.authprotocol:
        snmpcmd['authprotocol'] = args.authprotocol.upper()
    if args.privpassword:
        snmpcmd['privpassword'] = args.privpassword
    if args.privprotocol:
        snmpcmd['privprotocol'] = args.privprotocol.upper()
    if args.port:
        snmpcmd['port'] = args.port

    if not snmpcmd['version']:
        print 'ERROR: SNMP version not specified'
        sys.exit(2)

    if (snmpcmd['version'] == 2) and (not snmpcmd['community']):
        print 'ERROR: SNMPv2 community string not defined'
        sys.exit(2)

    if (not snmpcmd['ipaddress']):
        print 'ERROR: IP address of device to query is not defined'
        sys.exit(2)

    return (snmpcmd)

if __name__ == "__main__":
    main()
