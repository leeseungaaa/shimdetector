#-*- coding:utf-8 -*-
#!/usr/bin/env python
# shimdetector.py
#
# Copyright 2012 Mandiant
#
# Mandiant licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.
#
# Identifies and parses Application Compatibility Shim Cache entries for forensic data.

import sys
import struct
import zipfile
import argparse
import binascii
import datetime
import codecs
import cStringIO as sio
import xml.etree.cElementTree as et
from os import close, path
from csv import writer

# Values used by Windows 10
WIN10_STATS_SIZE = 0x30
WIN10_CREATORS_STATS_SIZE = 0x34
WIN10_MAGIC = '10ts'
CACHE_HEADER_SIZE_NT6_4 = 0x30
CACHE_MAGIC_NT6_4 = 0x30

bad_entry_data = 'N/A'
g_verbose = False
g_usebom = False
output_header  = ["Last Modified", "Last Update", "Path", "File Size", "Exec Flag"]

# Date Formats
DATE_MDY = "%m/%d/%y %H:%M:%S"
DATE_ISO = "%Y-%m-%d %H:%M:%S"
g_timeformat = DATE_ISO

# Add keywords related to anti-forensics. 
def add_keyword(keyword):
    
    with open('list_anti.txt', 'a') as f:
            f.write(keyword+"\n")
            f.close()

# Update list of keywords to be used for filtering.
def update_list():
    
    list_anti = []
    with open('list_anti.txt', 'r') as txt_file:
        lines = txt_file.readlines()
        list_anti = [line.rstrip('\n') for line in lines] 
    return list_anti
    
# Convert FILETIME to datetime.
# Based on http://code.activestate.com/recipes/511425-filetime-to-datetime/
def convert_filetime(dwLowDateTime, dwHighDateTime):
    
    try:
        date = datetime.datetime(1601, 1, 1, 0, 0, 0)
        temp_time = dwHighDateTime
        temp_time <<= 32
        temp_time |= dwLowDateTime
        return date + datetime.timedelta(microseconds=temp_time/10)
    except OverflowError, err:
        return None

# Return a unique list while preserving ordering.
def unique_list(li):

    ret_list = []
    for entry in li:
        if entry not in ret_list:
            ret_list.append(entry)
    return ret_list

# Write the Log.
def write_it(rows, outfile=None):
 
    try:
        if not rows:
            print "[-] No data to write..."
            return
        
        # Output to cmd only
        if not outfile: 
            list_anti = update_list()

            # Print headers
            print " | ".join(rows[0])

            # Filter with list of keywords
            for row in rows:
                for x in row:
                    test ="%s"%x
                    if any(anti_tool in test for anti_tool in list_anti):
                        print " ".join(["%s"%x for x in row])

    except UnicodeEncodeError, err:
        print "[-] Error writing output file: %s" % str(err)
        return

# Read the Shim Cache format, return a list of last modified dates/paths.
def read_cache(cachebin, quiet=False):

    if len(cachebin) < 16:
        # Data size less than minimum header size.
        return None

    try:
        # Get the format type
        magic = struct.unpack("<L", cachebin[0:4])[0]

        # Windows 10 will use a different magic dword, check for it
        if len(cachebin) > WIN10_STATS_SIZE and cachebin[WIN10_STATS_SIZE:WIN10_STATS_SIZE+4] == WIN10_MAGIC:
            if not quiet:
                print "[+] Found Windows 10 Apphelp Cache data..."
            return read_win10_entries(cachebin, WIN10_MAGIC)

        # Windows 10 Creators Update will use a different STATS_SIZE, account for it
        elif len(cachebin) > WIN10_CREATORS_STATS_SIZE and cachebin[WIN10_CREATORS_STATS_SIZE:WIN10_CREATORS_STATS_SIZE+4] == WIN10_MAGIC:
            if not quiet:
                print "[+] Found Windows 10 Creators Update Apphelp Cache data..."
            return read_win10_entries(cachebin, WIN10_MAGIC, creators_update=True)

        else:
            print "[-] Got an unrecognized magic value of 0x%x... bailing" % magic
            return None

    except (RuntimeError, TypeError, NameError), err:
        print "[-] Error reading Shim Cache data: %s" % err
        return None

# Read Windows 10 Apphelp Cache entry format
def read_win10_entries(bin_data, ver_magic, creators_update=False):

    offset = 0
    entry_meta_len = 12
    entry_list = []

    # Skip past the stats in the header
    if creators_update:
        cache_data = bin_data[WIN10_CREATORS_STATS_SIZE:]
    else:
        cache_data = bin_data[WIN10_STATS_SIZE:]

    data = sio.StringIO(cache_data)
    while data.tell() < len(cache_data):
        header = data.read(entry_meta_len)
        # Read in the entry metadata
        # Note: the crc32 hash is of the cache entry data
        magic, crc32_hash, entry_len = struct.unpack('<4sLL', header)

        # Check the magic tag
        if magic != ver_magic:
            raise Exception("Invalid version magic tag found: 0x%x" % struct.unpack("<L", magic)[0])

        entry_data = sio.StringIO(data.read(entry_len))

        # Read the path length
        path_len = struct.unpack('<H', entry_data.read(2))[0]
        if path_len == 0:
            path = 'None'
        else:
            path = entry_data.read(path_len).decode('utf-16le', 'replace').encode('utf-8')

        # Read the remaining entry data
        low_datetime, high_datetime = struct.unpack('<LL', entry_data.read(8))

        last_mod_date = convert_filetime(low_datetime, high_datetime)
        try:
            last_mod_date = last_mod_date.strftime(g_timeformat)
        except ValueError:
            last_mod_date = bad_entry_data

        # Skip the unrecognized Microsoft App entry format for now
        if last_mod_date == bad_entry_data:
            continue

        row = [last_mod_date, 'N/A', path, 'N/A', 'N/A']
        entry_list.append(row)

    return entry_list

# Acquire the current system's Shim Cache data. 
def get_local_data():

    tmp_list = []
    out_list = []
    global g_verbose

    try:
        import _winreg as reg
    except ImportError:
        print "[-] \'winreg.py\' not found... Is this a Windows system?"
        sys.exit(1)

    hReg = reg.ConnectRegistry(None, reg.HKEY_LOCAL_MACHINE)
    hSystem = reg.OpenKey(hReg, r'SYSTEM')
    for i in xrange(1024):
        try:
            control_name = reg.EnumKey(hSystem, i)
            if 'controlset' in control_name.lower():
                hSessionMan = reg.OpenKey(hReg,
                                          'SYSTEM\\%s\\Control\\Session Manager' % control_name)
                for i in xrange(1024):
                    try:
                        subkey_name = reg.EnumKey(hSessionMan, i)
                        if ('appcompatibility' in subkey_name.lower()
                            or 'appcompatcache' in subkey_name.lower()):

                            appcompat_key = reg.OpenKey(hSessionMan, subkey_name)
                            bin_data = reg.QueryValueEx(appcompat_key,
                                                        'AppCompatCache')[0]
                            tmp_list = read_cache(bin_data)
                            if tmp_list:
                                path_name = 'SYSTEM\\%s\\Control\\Session Manager\\%s' % (control_name, subkey_name)
                                for row in tmp_list:
                                    if g_verbose: 
                                        row.append(path_name) 
                                    if row not in out_list:
                                        out_list.append(row)
                    except EnvironmentError:
                        break
        except EnvironmentError:
            break

    if len(out_list) == 0:
        return None
    else:
        #Add the header and return the list.
        if g_verbose:
            out_list.insert(0, output_header + ['Key Path'])
            return out_list
        else:
        #Only return unique entries.
            out_list = unique_list(out_list)
            out_list.insert(0, output_header)
            return out_list

# Do the work.
def main(argv=[]):

    global g_verbose
    global g_timeformat
    global g_usebom

    parser = argparse.ArgumentParser(description="Parses Application Compatibilty Shim Cache data")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Toggles verbose output")
    parser.add_argument("-t","--isotime", action="store_const", dest="timeformat", const=DATE_ISO, default=DATE_MDY,
        help="Use YYYY-MM-DD ISO format instead of MM/DD/YY default")
    parser.add_argument("-B", "--bom", action="store_true", help="Write UTF8 BOM to CSV for easier Excel 2007+ import")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-l", "--local", action="store_true", help="Reads data from local system")
    group.add_argument("-a", "--add", type= str, help="Reads data from local system")
    
    args = parser.parse_args(argv[1:])

    if args.verbose:
        g_verbose = True

    # Set date/time format
    g_timeformat = args.timeformat

    # Enable UTF8 Byte Order Mark (BOM) so Excel imports correctly
    if args.bom:
        g_usebom = True

    # Add keyword to list_anti
    # You can see the list of anti forensic keywords
    if args.add:
        add_keyword(args.add)
        list_anti_tools = update_list()

        print "[+] Added: %s..." % args.add
        print "List of anti forensic keywords:",

        print " ".join(list_anti_tools)

    # Read the local Shim Cache data from the current system 
    elif args.local:
        print "[+] Dumping Shim Cache data from the current system..."
        entries = get_local_data()
        if not entries:
            print "[-] No Shim Cache entries found..."
        else:
            write_it(entries)

if __name__ == '__main__':
    main(sys.argv)