from optparse import OptionParser, OptionGroup
from colorama import *
import os
import sys
#import StringIO
from io import StringIO
import zlib
import gzip

BANNER = """
===============================================================================
                     -- Compression Identifier --
===============================================================================
  Supported compression formats:
  - Zlib (RFC 1950)
  - Deflate (RFC 1951)
  - Gzip (RFC 1952)
"""


# -----------------------------------------------------------------------------
# --- Utils functions ---------------------------------------------------------
# -----------------------------------------------------------------------------
def hexdump(src, length=16):
    filters = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c + length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and filters[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length * 3, hex, printable))
    return ''.join(lines)


def print_title(title: object) -> object:
    print(Style.BRIGHT + Fore.YELLOW + title + Style.RESET_ALL)


def print_error(reason):
    print(Style.BRIGHT + Fore.RED + '[!] ' + reason.strip() + Style.RESET_ALL)


def print_success(reason):
    print(Style.BRIGHT + Fore.GREEN + '[+] ' + Style.NORMAL + reason.strip() + Style.RESET_ALL)


def print_info(info):
    print(Style.BRIGHT + "[~] " + Style.RESET_ALL + info.strip())


def write_to_file(filename, data):
    try:
        with open(filename, 'w') as f:
            f.write(data)
        print_success('Output written into file "{0}"'.format(filename))
    except Exception as e:
        print_error('An error occured when writing to file: {0}'.format(e))


# -----------------------------------------------------------------------------
# --- Zlib functions ----------------------------------------------------------
# -----------------------------------------------------------------------------

def compress_zlib(data):
    compressed = None
    zlib_compress = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS)
    try:
        compressed = zlib_compress.compress(data) + zlib_compress.flush()
    except Exception as e:
        print_error('Error when compressing with Zlib: {0}'.format(e))
    return compressed


# def decompress_zlib(data):
#     decompressed = None
#     i = -15

#     # The absolute value of wbits is the base two logarithm of the size of the history buffer (the "window size") 
#     # used when compressing data
#     valid_wbits = []
#     truncated_wbits = []
#     decompressed = None

#     for i in range(-15,16):
#         try:
#             decompressed = zlib.decompress(data, i)
#             valid_wbits.append(i)
#         except zlib.error as e:
# 			# Error -5 : incomplete or truncated data input implies that it's zlib compressed but the stream is not complete
# 			if str(e).startswith('Error -5'):
# 				tuncated_wbits.append(i) 
# 	return (valid_wbits, truncated_wbits, decompressed)

def decompress_zlib(data):
    decompressed = None
    decomp_obj = zlib.decompressobj()
    try:
        decompressed = decomp_obj.decompress(data)
    except:
        pass
    return decompressed


def print_zlib_header(data):
    #    0   1
    #    +---+---+
    #    |CMF|FLG|   (more-->)
    #    +---+---+
    # (if FLG.FDICT set) where FDICT 5th bit of of FLG
    #      0   1   2   3
    #    +---+---+---+---+
    #    |     DICTID    |
    #    +---+---+---+---+
    cm = ord(data[0]) & 0x0F
    cinfo = (ord(data[0]) & 0xF0) >> 4
    fcheck = ord(data[1]) & 0x1F
    fdict = (ord(data[1]) & 0x20) >> 5
    flevel = (ord(data[1]) & 0xc0) >> 6
    flevel_str = ['Fastest algorithm', 'Fast algorithm', 'Default algorithm', 'Maximum compression']
    header_len = 6 if fdict else 2

    print_info('Header: {0}'.format(' '.join(["%02x" % ord(x) for x in data[0:header_len]])))
    print_info('   +--- CMF = {0:02x}'.format(ord(data[0])))
    print_info('   |  +--- CM (Compression Method)  = {0} {1}'.format(cm, '- Deflate' if (cm == 8) else ''))
    print_info('   |  +--- CINFO (Compression Info) = {0}'.format(cinfo))
    print_info('   +--- FLG = {0:02x}'.format(ord(data[1])))
    print_info('   |  +--- FCHECK = {0}'.format(fcheck))
    print_info('   |  +--- FDICT  = {0} {1}'.format(fdict, '- DICTID field present' if fdict else '- No DICTID field'))
    print_info('   |  +--- FLEVEL = {0} {1}'.format(flevel, '- ' + flevel_str[flevel] if (cm == 8) else ''))
    if fdict:
        print_info('   +--- DICTID = {0}'.format(' '.join(["%02x" % ord(x) for x in data[2:4]])))


def print_zlib_compressed(data):
    print_zlib_header(data)
    print()
    print_info('Full hexdump of compressed data:')
    print(hexdump(data))
    print()


# -----------------------------------------------------------------------------
# --- Deflate functions -------------------------------------------------------
# -----------------------------------------------------------------------------
def compress_deflate(data):
    compressed = None
    deflate_compress = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    try:
        compressed = deflate_compress.compress(data) + deflate_compress.flush()
    except Exception as e:
        print_error('Error when compressing with Deflate: {0}'.format(e))
    return compressed


def decompress_deflate(data):
    decompressed = None
    try:
        decompressed = zlib.decompress(data, -zlib.MAX_WBITS)
    except:
        pass
    return decompressed


# -----------------------------------------------------------------------------
# --- Gzip functions ----------------------------------------------------------
# -----------------------------------------------------------------------------
def compress_gzip(data):
    compressed = None
    gzip_compress = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    try:
        compressed = gzip_compress.compress(data) + gzip_compress.flush()
    except Exception as e:
        print_error('Error when compressing with Gzip: {0}'.format(e))
    return compressed


# def decompress_gzip(data):
# 	decompressed=None
# 	try:
# 		decompressed = zlib.decompress(gzip_data, zlib.MAX_WBITS|16)
# 	except:
# 		pass
# 	return decompressed

def decompress_gzip(data):
    decompressed = None
    try:
        stream = StringIO.StringIO(data)
        gzipper = gzip.GzipFile(fileobj=stream)
        decompressed = gzipper.read()
    except:
        pass
    return decompressed


def print_gzip_header(data):
    #    +---+---+---+---+---+---+---+---+---+---+
    #    |ID1|ID2|CM |FLG|     MTIME     |XFL|OS | (more-->)
    #    +---+---+---+---+---+---+---+---+---+---+
    # (if FLG.FEXTRA set)
    #    +---+---+=================================+
    #    | XLEN  |...XLEN bytes of "extra field"...| (more-->)
    #    +---+---+=================================+
    # (if FLG.FNAME set)
    #    +=========================================+
    #    |...original file name, zero-terminated...| (more-->)
    #    +=========================================+
    # (if FLG.FCOMMENT set)
    #    +===================================+
    #    |...file comment, zero-terminated...| (more-->)
    #    +===================================+
    # (if FLG.FHCRC set)
    #    +---+---+
    #    | CRC16 |
    #    +---+---+
    ftext = ord(data[3]) & 0x01
    fhcrc = (ord(data[3]) & 0x02) >> 1
    fextra = (ord(data[3]) & 0x04) >> 2
    fname = (ord(data[3]) & 0x08) >> 3
    fcomment = (ord(data[3]) & 0x10) >> 4
    freserved = (ord(data[3]) & 0xE0) >> 5
    fextra_field = None
    fname_field = None
    fcomment_field = None
    fhcrc_field = None

    header_len = 10
    if fextra:
        fextra_len = int("{0:x}{1:x}".format(ord(data[10]), ord(data[11])), 16)
        header_len += 2 + fextra_len
        fextra_field = data[10:10 + 2 + int("{0:x}{1:x}".format(ord(data[10]), ord(data[11])), 16)]
    if fname:
        beg = header_len
        fname_len = 0
        while data[fname_len] != 0x00:
            fname_len += 1
        fname_len += 1
        fname_field = data[beg:beg + fname_len]
        header_len += fname_len
    if fcomment:
        beg = header_len
        fcomment_len = 0
        while data[fcomment_len] != 0x00:
            fcomment_len += 1
        fcomment_len += 1
        fcomment_field = data[beg:beg + fcomment_len]
        header_len += fcomment_len
    if fhcrc:
        fhcrc_field = data[header_len:header_len + 2]
        header_len += 2

    print_info('Header: {0}'.format(' '.join(["%02x" % ord(x) for x in data[0:header_len]])))
    print_info('   +--- ID1 = {0:02x}'.format(ord(data[0])))
    print_info('   +--- ID2 = {0:02x}'.format(ord(data[1])))
    print_info('   +--- CM  = {0:02x}'.format(ord(data[2]), '- Deflate' if (ord(data[2]) == 8) else ''))
    print_info('   +--- FLG = {0:02x}'.format(ord(data[3])))
    print_info('   |  +--- FTEXT 	= {0} {1}'.format(ftext,
                                                       '- Probably ASCII text' if ftext else '- Probably not ASCII text'))
    print_info('   |  +--- FHCRC 	= {0} {1}'.format(fhcrc,
                                                       '- CRC16 field present in header' if fhcrc else '- No CRC16 field in header'))
    print_info('   |  +--- FEXTRA 	= {0} {1}'.format(fextra,
                                                        '- Extra field present in header' if fextra else '- No extra field in header'))
    print_info('   |  +--- FNAME 	= {0} {1}'.format(fname,
                                                       '- Original filename in header' if fname else '- No original filename in header'))
    print_info('   |  +--- FCOMMENT\t= {0} {1}'.format(fcomment,
                                                       '- File comment in header' if fcomment else '- No file comment in header'))
    print_info('   |  +--- Reserved\t= {0:x}'.format(freserved))
    if fextra:
        print_info('   +--- Extra Field = {0}'.format(' '.join(["%02x" % ord(x) for x in fextra_field])))
    if fname:
        print_info('   +--- Original file Name = {0}'.format(' '.join(["%02x" % ord(x) for x in fname_field])))
    if fcomment:
        print_info('   +--- File comment = {0}'.format(' '.join(["%02x" % ord(x) for x in fcomment_field])))
    if fhcrc:
        print_info('   +--- CRC16 = {0}'.format(' '.join(["%02x" % ord(x) for x in fhcrc_field])))


def print_gzip_compressed(data):
    print_gzip_header(data)
    print
    print_info('Full hexdump of compressed data:')
    print(hexdump(data))
    print()


# -----------------------------------------------------------------------------
# --- Automatic detection -----------------------------------------------------
# -----------------------------------------------------------------------------
def auto_detect(data):
    found = False
    pos = 0
    output = None

    for pos in range(0, len(data)):
        output = decompress_gzip(data[pos:])
        if output:
            return ('gzip', pos, output)
    for pos in range(0, len(data)):
        output = decompress_zlib(data[pos:])
        if output:
            return ('zlib', pos, output)
    for pos in range(0, len(data)):
        output = decompress_deflate(data[pos:])
        if output:
            return ('deflate', pos, output)

    return (None, None, None)


# -----------------------------------------------------------------------------
# --- Command parsing ---------------------------------------------------------
# -----------------------------------------------------------------------------
print(Style.BRIGHT + BANNER + Style.RESET_ALL)
print()

# Command-line parsing
usage = 'Usage: %prog <option>'
parser = OptionParser(usage)

input_data = OptionGroup(parser, 'Input')
input_data.add_option('-d', '', help='Raw data', action='store', type='string', dest='raw_data', default=None)
input_data.add_option('-f', '', help='File containing raw data', action='store', type='string', dest='file_raw', \
                      default=None)
input_data.add_option('', '--offset', help='Beginning offset for decompression', action='store', type='string', \
                      dest='offset', default=0)

output = OptionGroup(parser, 'Output')
output.add_option('-o', '', help='Output file (raw)', action='store', type='string', dest='output_file', default=None)

ident = OptionGroup(parser, 'Automatic identification')
ident.add_option('', '--scan', help='Scan input and search for compressed data', action='store_true', \
                 dest='auto_detect', default=False)

zlib_format = OptionGroup(parser, 'Zlib compressed format (RFC 1950)')
zlib_format.add_option('', '--zlib-c', help='Compress using Zlib', action='store_true', dest='compress_zlib',\
                       default=False)
zlib_format.add_option('', '--zlib-d', help='Decompress using Zlib', action='store_true', dest='decompress_zlib',\
                       default=False)

deflate_format = OptionGroup(parser, 'Deflate compressed format (RFC 1951)')
deflate_format.add_option('', '--deflate-c', help='Compress using Deflate', action='store_true',\
                          dest='compress_deflate', default=False)
deflate_format.add_option('', '--deflate-d', help='Decompress using Deflate', action='store_true',\
                          dest='decompress_deflate', default=False)

gzip_format = OptionGroup(parser, 'Gzip compressed format (RFC 1952)')
gzip_format.add_option('', '--gzip-c', help='Compress using Gzip', action='store_true', dest='compress_gzip',default=False)
gzip_format.add_option('', '--gzip-d', help='Decompress using Gzip', action='store_true', dest='decompress_gzip',default=False)

parser.add_option_group(input_data)
parser.add_option_group(output)
parser.add_option_group(ident)
parser.add_option_group(zlib_format)
parser.add_option_group(deflate_format)
parser.add_option_group(gzip_format)

options, arguments = parser.parse_args()

if (options.raw_data is None and options.file_raw is None) or \
        (options.raw_data is not None and options.file_raw is not None):
    print_error('Input data must be provided (using -d or -f)')
    print()
    parser.print_help()
    print()
    exit(0)

# Extract input data
if options.file_raw is not None:
    filename = options.file_raw.strip()
    if not os.access(filename, os.F_OK):
        print_error('Input file ({0}) does not exist'.format(options.file_raw))
        exit(0)
    f = open(filename, "r")
    data = f.read()
else:
    data = ''
    try:
        for c in options.raw_data.replace(' ', '').strip().split(','):
            data += chr(int(c))
    except Exception as e:
        print_error('Input raw data in wrong format')

# Offset
offset = 0
if options.offset:
    if options.offset.isdigit():
        offset = int(options.offset)
    elif options.offset[0:2] == '0x' or options.offset[0:2] == '0X':
        offset = int(options.offset, 16)
    else:
        print_error("Specified offset ({0}) is not valid numeric value. Supported: decimal / hexa. Will use offset=0" \
                    .format(options.offset))
    print_info('Offset = {0} ({1})'.format(offset, hex(offset)))

# Check output file presence
if options.output_file is not None:
    filename = options.output_file.strip()
    if os.access(filename, os.F_OK):
        print_error('Output file ({0}) already exists, choose a new for a new file'.format(options.output_file))
        print()
        exit(0)

# -----------------------------------------------------------------------------
# --- Processing --------------------------------------------------------------
# -----------------------------------------------------------------------------
data = data[offset:]
output = None

# Zlib compressed format (RFC 1950)
if options.compress_zlib:
    print_title('Compression using Zlib (RFC 1950)')
    print()
    output = compress_zlib(data)
    if not output:
        print_error('Unable to compress')
    else:
        print_success('Data compressed using Zlib with success')
        print
        print_zlib_compressed(output)

if options.decompress_zlib:
    print_title('Decompression using Zlib (RFC 1950)')
    print
    # (valid_wbits, truncated_wbits, decompressed) = decompress_zlib(data)
    output = decompress_zlib(data)
    # if truncated_wbits:
    #	print_info('Zlib decompression attempts failed with error indicating incomplete/truncated data input')
    #	print_info('It probably implies that stream is not complete. Error returned for wbits = {0}'.format(str(truncated_wbits)))
    if not output:
        print_error('Unable to decompress input using Zlib')
    else:
        print_success('Data decompressed using Zlib with success')
        print()
        print_zlib_header(data)
        print()
        print_info('Full hexdump of decompressed data:')
        print(hexdump(output))

# Deflate compressed format (RFC 1951)
if options.compress_deflate:
    print_title('Compression using Deflate (RFC 1951)')
    print
    output = compress_deflate(data)
    if not output:
        print_error('Unable to compress')
    else:
        print_success('Data compressed using Deflate with success')
        print()
        print(hexdump(output))

if options.decompress_deflate:
    print_title('Decompression using Deflate (RFC 1951)')
    print()
    output = decompress_deflate(data)
    if not output:
        print_error('Unable to decompress input using Deflate')
    else:
        print_success('Data decompressed using Deflate with success')
        print()
        print(hexdump(output))

# Gzip compressed format (RFC 1951)
if options.compress_gzip:
    print_title('Compression using Gzip (RFC 1952)')
    print
    output = compress_gzip(data)
    if not output:
        print_error('Unable to compress')
    else:
        print_success('Data compressed using Gzip with success')
        print()
        print_gzip_compressed(output)

if options.decompress_gzip:
    print_title('Decompression using Gzip (RFC 1952)')
    print()
    output = decompress_gzip(data)
    if not output:
        print_error('Unable to decompress input using Gzip')
    else:
        print_success('Data decompressed using Gzip with success')
        print()
        print_gzip_header(data)
        print()
        print_info('Full hexdump of decompressed data:')
        print(hexdump(output))

# Automatic detection
if options.auto_detect:
    print_title('Automatic detection of compressed data')
    print ()
    print_info('Scan input and search for compression at the different offsets...')
    (compr_format, pos, output) = auto_detect(data)

    if compr_format == 'zlib':
        print_success('Zlib compressed data found at offset 0x{0:02X}'.format(pos))
        print()
        print_zlib_header(data[pos:])
        print()
        print_info('Full hexdump of decompressed data:')
        print(hexdump(output))
    elif compr_format == 'deflate':
        print_success('Deflate compressed data found at offset 0x{0:02X}'.format(pos))
        print()
        print(hexdump(output))
    elif compr_format == 'gzip':
        print_success('Gzip compressed data found at offset 0x{0:02X}'.format(pos))
        print()
        print_gzip_header(data[pos:])
        print()
        print_info('Full hexdump of decompressed data:')
        print(hexdump(output))
    else:
        print_error('No compressed data found')
        print()
        exit(0)

# Output into file
if options.output_file and output:
    write_to_file(options.output_file, output)

print ()
