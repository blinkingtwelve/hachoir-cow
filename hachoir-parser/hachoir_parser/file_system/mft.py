"""
NTFS MFT parser.

Sources:
- Based on hachoir ntfs.py parser
  by Victor Stinner, Jan 3rd 2007
- "File System Forensic Analysis"
  by Brian Carrier, ISBN 978-0-321-26817-4

Creation date: June 20th, 2014
Author: Wicher Minnaard (wicher@nontrivialpursuit.org)
"""

from hachoir_parser import Parser
from hachoir_core.field import (FieldSet, Enum,
    UInt8, UInt16, UInt32, UInt64, TimestampWin64,
    String, Bytes, Bit, StaticFieldSet,
    NullBits, NullBytes, PaddingBytes, RawBytes)
from hachoir_core.endian import LITTLE_ENDIAN
from hachoir_core.text_handler import textHandler, hexadecimal, filesizeHandler
from hachoir_core.tools import humanFilesize, createDict
from hachoir_parser.common.msdos import MSDOSFileAttr32

from hachoir_core.log import log
import struct

SECTOR_SIZE = 512

ATTR_INFO = {}
ATTR_NAME = {}
ATTR_CLASS = {}

FILENAME_NAMESPACE = {
    0: "POSIX",
    1: "Win32",
    2: "DOS",
    3: "Win32 & DOS",
}

class IndexEntryFlags(StaticFieldSet):
    #Carrier 375 13.16
    format = (
    (Bit, "Child node exists"),
    (Bit, "Last entry in list"),
    (NullBits, "reserved[]", 30),
    )


class NodeHeaderFlags(StaticFieldSet):
    #Carrier 373
    format = (
    (Bit, "haschildren"),
    (NullBits, "reserved[]", 31),
    )


class FixupArray(FieldSet):
    def createFields(self):
        yield RawBytes(self, "fixup", 2)
        while self._current_size < self._size: # but please initialize me with a size!
            yield RawBytes(self, 'replacement[]', 2)

    def createDescription(self):
        fixupval = struct.unpack('<H', self['fixup'].value)[0]
        return '0x%.4x for %s' % (fixupval, ', '.join(map(lambda a: a.display, self.array('replacement'))))


class MFT_Flags(FieldSet):
    static_size = 16
    def createFields(self):
        yield Bit(self, "in_use")
        yield Bit(self, "is_directory")
        yield NullBits(self, "padding", 14)


class Attribute(FieldSet):
    
    def __init__(self, *args):
        FieldSet.__init__(self, *args)
        self._size = self["size"].value * 8
        self._name = ATTR_NAME.get(self['type'].value, str(self['type']))
        self.isres = not bool(self['non_resident'].value)

    def createDescription(self):
        res = 'R' if self.isres else 'Nonr'
        return "%sesident attribute %s" % (res, self["type"].display)

    def createFields(self):
        #first 16 bytes, Carrier 356 13.2
        yield Enum(textHandler(UInt32(self, "type"), hexadecimal), ATTR_UPNAME)
        yield UInt32(self, "size", "Total size of attribute")
        yield UInt8(self, "non_resident", "Non-resident flag")
        yield UInt8(self, "name_length", "Name length (in UTF-16 chars)")
        yield UInt16(self, "name_offset", "Name offset")
        yield UInt16(self, "flags")
        yield textHandler(UInt16(self, "attribute_id"), hexadecimal)

        if self.isres:
            yield ResidentAttributeHeader(self, 'resident_header', 'Resident attribute header')
        else:
            yield NonresidentAttributeHeader(self, 'nonresident_header', 'Nonresident attribute header')

        # per Linux-NTFS documentation
        yield UInt8(self, "indexed_flag")
        yield NullBytes(self, "padding[]", 1)

        if self["name_length"].value: #this is a named attribute
            seekfwd = (self["name_offset"].value - (self._current_size // 8))
            if seekfwd:
                yield RawBytes(self, "slack[]", seekfwd)
            yield String(self, "name", self["name_length"].value*2, charset="UTF-16-LE")

        if self.isres: # descend into resident attribute data
            content_offset = self['resident_header']['offset'].value
            content_len    = self['resident_header']['length'].value
            seekfwd = (content_offset - (self._current_size // 8))
            if seekfwd:
                yield RawBytes(self, "padding[]", seekfwd)
            if content_len:
                thename, theclass = ATTR_INFO[self['type'].value][1:3]
                if theclass:
                    yield theclass(self, thename, size=content_len*8)
                else:
                    yield RawBytes(self, "unparsed_attribute", content_len)

        size = (self._size - self._current_size) // 8
        if size:
            yield RawBytes(self, "slack[]", size)


class Data(FieldSet):
    def createFields(self):
        yield Bytes(self, "data", self._size//8)


class ResidentAttributeHeader(FieldSet):
    # Carrier 356 13.3
    static_size = 6*8
    def createFields(self):
        yield UInt32(self, "length", "Length of attribute content")
        yield UInt16(self, "offset", "Offset to attribute content")


class NonresidentAttributeHeader(FieldSet):
    # Carrier 357 13.4
    static_size = 48*8
    def createFields(self):
        yield UInt64(self, "startvcn", "Starting VCN of the runlist")
        yield UInt64(self, "stopvcn", "Ending VCN of the runlist")
        yield UInt16(self, "runlistoffset", "Offset to the runlist")
        yield UInt16(self, "compunit", "Compression unit size")
        yield RawBytes(self, "padding[]", 4)
        yield UInt64(self, "alloc_size", "Allocated size of attribute content")
        yield UInt64(self, "actual_size", "Actual size of attribute content")
        yield UInt64(self, "initialized_size", "Initialized size of attribute content")


class StandardInformation(FieldSet):
    #Carrier 360 13.5
    static_size = 72*8
    def createFields(self):
        yield TimestampWin64(self, "btime", "File Birth")
        yield TimestampWin64(self, "mtime", "File Modified")
        yield TimestampWin64(self, "ctime", "MFT Entry Changed")
        yield TimestampWin64(self, "atime", "File Accessed")
        yield MSDOSFileAttr32(self, "flags")
        yield UInt32(self, "max_version", "Maximum Number of Versions")
        yield UInt32(self, "version", "Version Number")
        yield UInt32(self, "class_id")
        yield UInt32(self, "owner_id")
        yield UInt32(self, "security_id")
        yield filesizeHandler(UInt64(self, "quota_charged", "Quota Charged"))
        yield UInt64(self, "usn", "Update Sequence Number (USN)")


class IndexRoot(FieldSet):
    # Carrier 370 13.12
    def createFields(self):
        yield Enum(textHandler(UInt32(self, "ixtype", "indexed attribute type"), hexadecimal), ATTR_NAME)
        yield UInt32(self, "collsort", "collation sorting rule")
        yield UInt32(self,"ixrecsz(b)", "size of each index record (bytes)")
        yield UInt8(self,"ixrecsz(c)", "size of each index record (clusters)")
        yield PaddingBytes(self, "padding[]", 3)
        yield IndexNodeHeader(self, 'nodeheader')
        while self._current_size//8 <= self['nodeheader/used_offset'].value: # <=; for the lists ends with an empty entry with 'last' flag set
            yield DirectoryIndexEntry(self, 'entry[]')


class IndexNodeHeader(FieldSet):
    # Carrier 373 13.14
    def createFields(self):
        yield UInt32(self, "start_offset", "offset to start of index entry list")
        yield UInt32(self, "used_offset", "offset to end of used portion of index entry list")
        yield UInt32(self, "alloc_offset", "offset to end of allocated portion of index entry list")
        yield Bit(self, "haschildren", "one or more ixentries in this node point to child nodes in $INDEX_ALLOCATION")
        yield NullBits(self, "reserved[]", 31)
        seekfwd = self['start_offset'].value*8 - self._current_size
        if seekfwd:
            yield RawBytes(self, "padding[]", seekfwd)


class DirectoryIndexEntry(FieldSet):

    def __init__(self, *args):
        FieldSet.__init__(self, *args)
        self._size = (self["entry_len"].value)*8

    def createFields(self):
        # Carrier 376 13.17
        yield UInt64(self, "mft_ref", "MFT reference for file name")
        yield UInt16(self, "entry_len", "Length of this entry")
        yield UInt16(self, "fname_attrib_len", "Length of $FILE_NAME attribute")
        yield IndexEntryFlags(self, 'flags')
        if self['fname_attrib_len'].value:
            yield FileName(self, 'filename', size=self['fname_attrib_len'].value*8)
        seekfwd = self['entry_len'].value - self._current_size // 8
        if self['flags/Child node exists'].value:
            # last 8 bytes will point to VCN. should start on 8-byte boundary.
            seektofield = seekfwd - 8
            if seektofield >= 0:
                yield RawBytes(self, "padding[]", seektofield)
                yield UInt64(self, "child_vcn", "VCN of child node in $INDEX_ALLOCATION")
        elif seekfwd > 0:
            yield RawBytes(self, "padding[]", seekfwd)


class FileName(FieldSet):
    #Carrier 362 13.7

    def createFields(self):
        yield UInt64(self, "ref", "File reference to the parent directory")
        yield TimestampWin64(self, "btime", "File Birth")
        yield TimestampWin64(self, "mtime", "File Modified")
        yield TimestampWin64(self, "ctime", "MFT Entry Changed")
        yield TimestampWin64(self, "atime", "File Accessed")
        yield filesizeHandler(UInt64(self, "alloc_size", "Allocated size of the file"))
        yield filesizeHandler(UInt64(self, "real_size", "Real size of the file"))
        yield MSDOSFileAttr32(self, "flags")
        yield UInt32(self, "reparse_value")
        yield UInt8(self, "name_length", "Filename length in characters")
        yield Enum(UInt8(self, "namespace"), FILENAME_NAMESPACE)
        size = self["name_length"].value * 2
        if size:
            yield String(self, "name", size, charset="UTF-16-LE")


class Bitmap(FieldSet):
    def createFields(self):
        size = (self.size - self.current_size)
        for index in xrange(size):
            yield Bit(self, "bit[]")


class File(FieldSet):
    #Carrier 353 13.1
    def __init__(self, *args):
        FieldSet.__init__(self, *args)
        self._size = self["bytes_allocated"].value * 8
        if hasattr(self.stream, 'patchable'):
            self.applyFixups()
        else:
            log.warning('Cannot apply NTFS fixups as input stream is non-patchable')

    def applyFixups(self):
        # On-disk data is actually intentionally predictably corrupted, see Carrier 352.
        # and also http://web.archive.org/web/20061209150816/http://www.linux-ntfs.org/content/view/104/43/#concept_fixup
        # The corruption is reversible. This should be done before the
        # on-disk structures are actually parsed.
        # It's a rather unorthodox method for integrity checking.
        addr = self.absolute_address // 8
        fixup_amt = self['fixup_len'].value - 1
        repval = self['fixups/fixup'].value
        vals = [f.value for f in self['fixups'].array('replacement')]
        addresses = [addr-2 + SECTOR_SIZE + num*SECTOR_SIZE for num in range(len(vals))]
        # the addresses should currently hold the replacement value
        from binascii import hexlify as hx
        cur_val = set((self.stream._input[a:a+2] for a in addresses))
        assert((len(cur_val) == 1) and (repval in cur_val)) # values should be same
        for args in zip(addresses, vals):
            self.stream.patch(*args)

    def createFields(self):
        yield Bytes(self, "signature", 4, "Usually the magic is 'FILE'")
        yield UInt16(self, "fixup_offset", "Fixup array offset")
        yield UInt16(self, "fixup_len", "Length of fixup array")
        yield UInt64(self, "lsn", "$LogFile sequence number for this record")
        yield UInt16(self, "sequence_number", "Number of times this mft record has been reused")
        yield UInt16(self, "link_count", "Number of hard links")
        yield UInt16(self, "attrs_offset", "Byte offset to the first attribute")
        yield MFT_Flags(self, "flags")
        yield UInt32(self, "bytes_in_use", "Number of bytes used in this record")
        yield UInt32(self, "bytes_allocated", "Number of bytes allocated for this record")
        yield UInt64(self, "base_mft_record")
        yield UInt16(self, "next_attr_instance")

        # The below fields are specific to NTFS 3.1+ (Windows XP and above)
        yield NullBytes(self, "reserved", 2)
        yield UInt32(self, "mft_record_number", "Number of this mft record")

        seekfwd = self['fixup_offset'].value - self._current_size //8
        if seekfwd:
            yield RawBytes(self, "padding[]", seekfwd)

        yield FixupArray(self,'fixups',size=self['fixup_len'].value*2*8)

        seekfwd = self['attrs_offset'].value - self._current_size //8
        if seekfwd:
            yield RawBytes(self, "padding[]", seekfwd)

        while not self.eof:
            addr = self.absolute_address + self.current_size
            if self.stream.readBytes(addr, 4) == "\xFF\xFF\xFF\xFF":
                yield Bytes(self, "attr_end_marker", 8)
                break
            yield Attribute(self, "attr[]")

        size = self["bytes_in_use"].value - self.current_size//8
        if size:
            yield Bytes(self, "end_rawdata", size)

        size = (self.size - self.current_size) // 8
        if size:
            yield RawBytes(self, "slack", size, "Unused but allocated bytes")

    def createDescription(self):
        text = "File"
        if "filename[0]/FILE_NAME/name" in self:
            text += ' "%s"' % self["filename[0]/FILE_NAME/name"].value
        if "filename[0]/FILE_NAME/real_size" in self:
            text += ' (%s)' % self["filename[0]/FILE_NAME/real_size"].display
        if "standard_info/STANDARD_INFORMATION/file_attr" in self:
            text += ', %s' % self["standard_info/STANDARD_INFORMATION/file_attr"].display
        return text

class MFT(Parser):
    # MFT may be fragmented. The layout of the MFT is is specified in the
    # $MFT (entry 0); so we need to parse the MFT to *fully* determine
    # where we can find the MFT. It sounds circular, and it is, to some extent.
    # While this parser will to some extent work if started at the MFT offset
    # specified in the volume's boot record, it's not the best way.
    # For now, extract the MFT from an NTFS partition with the Sleuthkit's icat:
    #   icat /path/to/NTFSvolume 0 > MFT.img
    # and then run this parser on the resulting MFT file.
    MAGIC = "FILE"
    PARSER_TAGS = {
        "id": "mft",
        "category": "file_system",
        "description": "MFT of NTFS file system",
        "min_size": 1024*8, #1 entry
        "magic": ((MAGIC, 0),),
    }
    endian = LITTLE_ENDIAN

    def createFields(self):
        while not self.eof:
            yield File(self, "file[]")


ATTR_INFO = {
    # type id, friendly name, official name + '[]' if multiple attributes of
    # this type could be present in enveloping class, handling class)
    0x10: ('standard_info', 'STANDARD_INFORMATION', StandardInformation),
    0x20: ('attr_list', 'ATTRIBUTE_LIST', None),
    0x30: ('filename[]', 'FILE_NAME', FileName),
    0x40: ('vol_ver', 'VOLUME_VERSION', None),
    0x40: ('obj_id', 'OBJECT_ID', None),
    0x50: ('security', 'SECURITY_DESCRIPTOR', None),
    0x60: ('vol_name', 'VOLUME_NAME', None),
    0x70: ('vol_info', 'VOLUME_INFORMATION', None),
    0x80: ('data[]', 'DATA', Data),
    0x90: ('index_root[]', 'INDEX_ROOT', IndexRoot),
    0xA0: ('index_alloc', 'INDEX_ALLOCATION', None),
    0xB0: ('bitmap', 'BITMAP', Bitmap),
    0xC0: ('sym_link', 'SYMBOLIC_LINK', None),
    0xC0: ('reparse', 'REPARSE_POINT', None),
    0xD0: ('ea_info', 'EA_INFORMATION', None),
    0xE0: ('ea', 'EA', None),
    0xF0: ('prop_set', 'PROPERTY_SET', None),
    0x100: ('log_util', 'LOGGED_UTILITY_STREAM', None),
}
ATTR_NAME = createDict(ATTR_INFO, 0)
ATTR_UPNAME = createDict(ATTR_INFO, 1)
ATTR_CLASS = createDict(ATTR_INFO, 2)
