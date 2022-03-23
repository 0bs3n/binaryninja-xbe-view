from binaryninja import Architecture, BinaryReader, BinaryView, BinaryWriter, Platform, Architecture, RelocationType
from binaryninja.enums import SectionSemantics, SegmentFlag
from binaryninja import _binaryninjacore as core

from .xbe_file import XbeFile

def get_cstr(buf):
    cursor = 0
    while buf[cursor] != 0:
        cursor += 1
    return buf[:cursor]

class XbeView(BinaryView):
    name = 'XBE File'

    @staticmethod
    def is_valid_for_data(data):
        if data[0:4] == b'XBEH':
            return True
        return False

    def __init__(self, data):
        """
        Once our view is selected, this method is called to actually create it.
        :param data: the file data
        """
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)

    def init(self):
        self.platform = Platform["windows-x86"]
        self.arch = Architecture["x86"]
        self.xbe = XbeFile(self.parent_view)
        self.set_segments_sections()
        print(self.xbe.entry)
        self.add_entry_point(self.xbe.entry)
        return True

    def perform_is_executable(self):
        return True

    def perform_is_relocatable(self):
        return True

    def set_segments_sections(self):
        """
        This is a helper function to parse our BS format
        :param data:
        :return:
        """

        for section in self.xbe.sections:

            print(section.name)

            executable = SegmentFlag.SegmentExecutable if section.flags.executable else 0
            writable   = SegmentFlag.SegmentWritable if section.flags.writable else 0
            readable   = SegmentFlag.SegmentReadable

            if executable != 0:
                semantics = SectionSemantics.ReadOnlyCodeSectionSemantics
            else:
                semantics = SectionSemantics.ReadWriteDataSectionSemantics

            # XBE inexplicably sets the executable flag for .data and .rdata sections
            # this is wrong and messes up analysis, correcting here
            if section.name == b".data" or section.name == b".rdata":
                executable = SegmentFlag.SegmentDenyExecute

            if section.name == b".rdata":
                semantics =  SectionSemantics.ReadOnlyDataSectionSemantics

            self.add_auto_segment(section.m_virtual_addr, 
                                  section.m_virtual_size, 
                                  section.m_raw_addr, 
                                  section.m_sizeof_raw,
                                  readable | writable | executable)
            self.add_auto_section(section.name, section.m_virtual_addr, section.m_virtual_size, semantics)
        
