import struct
import sys

def get_cstr(buf):
    cursor = 0
    while buf[cursor] != 0:
        cursor += 1
    return buf[:cursor]

def u32(b):
    return struct.unpack("<I", b)[0]

class SectionFlags:
    def __init__(self, flagword):
        self.writable = flagword & 1
        self.preload  = flagword & 2
        self.executable = flagword & 4
        self.inserted_file = flagword & 8
        self.head_page_read_only = flagword & 0x10
        self.tail_page_read_only = flagword & 0x20

class SectionHeader:
    def __init__(self, data):
        self.flags = SectionFlags(u32(data[0:4]))
        self.m_virtual_addr = u32(data[4:8])
        self.m_virtual_size = u32(data[8:0xc])
        self.m_raw_addr     = u32(data[0xc:0x10])
        self.m_sizeof_raw   = u32(data[0x10:0x14])
        self.m_section_name_addr = u32(data[0x14:0x18])
        self.m_section_reference_count = u32(data[0x18:0x1c])
        self.m_head_shared_ref_count_addr = u32(data[0x1c:0x20])
        self.m_tail_shared_ref_count_addr = u32(data[0x20:0x24])
        self.name = None

    def __repr__(self):
        return f"Virtual Address: {self.m_virtual_addr:#x}\n"+\
               f"Virtual Size: {self.m_virtual_size:#x}\n"+\
            f"File Offset: {self.m_raw_addr:#x}\n"+\
            f"File Size: {self.m_sizeof_raw:#x}\n"+\
            f"Section Name Address: {self.m_section_name_addr:#x}\n"+\
            f"Section Ref Count: {self.m_section_reference_count:#x}\n"+\
            f"Head Shared Ref Count Address: {self.m_head_shared_ref_count_addr:#x}\n"+\
            f"Tail Shared Ref Count Address: {self.m_tail_shared_ref_count_addr:#x}\n"

class XbeFile:
    def __init__(self, data):
        self.data = data
        self.magic = data[0:4]
        self.base_address =         u32(data[0x104:0x108])

        self.all_headers_size =     u32(data[0x108:0x10c])
        self.image_size =           u32(data[0x10c:0x110])
        self.image_header_size =    u32(data[0x110:0x114])
        self.num_sections =         u32(data[0x11c:0x120])
        self.section_headers_addr = u32(data[0x120:0x124])
        self.init_flags =           u32(data[0x124:0x128])
        self.ciphered_entry =       u32(data[0x128:0x12c])
        self.stack_size =           u32(data[0x130:0x134])
        # ignoring original PE_* values here, stop ignoring if things don't work
        self.debug_pathname_addr =  u32(data[0x14c:0x150])
        self.debug_filename_addr =  u32(data[0x150:0x154])
        self.debug_utf16_filename_addr = u32(data[0x154:0x158])
        self.cipher_kernel_image_thunk_addr = u32(data[0x158:0x15c])
        self.nonkernel_import_dir_addr = u32(data[0x15c:0x160])
        self.num_libversions = u32(data[0x160:0x164])
        self.libversions_addr = u32(data[0x164:0x168])
        self.kernel_libversions_addr = u32(data[0x168:0x16c])
        self.xapi_libversion_addr = u32(data[0x16c:0x170])
        self.sections = []

        SECTION_HEADER_SIZE = 0x38
        for i in range(0, self.num_sections * SECTION_HEADER_SIZE, SECTION_HEADER_SIZE):
            print("data start:", data[0:4])
            curr_section_header = self.section_headers_addr + i
            print(f"current_header_addr: {curr_section_header:#x}")
            section_hdr = SectionHeader(self.get_data_range(curr_section_header, curr_section_header + SECTION_HEADER_SIZE))
            section_hdr.name = get_cstr(self.get_data_range(section_hdr.m_section_name_addr, end = None))
            print(section_hdr)
            self.sections.append(section_hdr)

        self.entry = None
        self.kernel_thunk_addr = None
        self.decode_addrs() # see function implementation

    def get_data_range(self, start, end):
        if end is None:
            return self.data[start - self.base_address:]
        elif start is None:
            return self.data[:end - self.base_address]
        return self.data[start - self.base_address:end - self.base_address]

    def decode_addrs(self):
        entry_debug_key = 0x94859D4B
        entry_retail_key = 0xA8FC57AB

        thunk_debug_key = 0xEFB1F152
        thunk_retail_key = 0x5B6D40B6

        debug_entry = self.ciphered_entry ^ entry_debug_key
        retail_entry = self.ciphered_entry ^ entry_retail_key

        text_sec = self.get_section_by_name(b".text")
        if retail_entry > text_sec.m_virtual_addr and retail_entry < (text_sec.m_virtual_addr + text_sec.m_virtual_size):
            self.entry = retail_entry
            self.kernel_thunk_addr = self.cipher_kernel_image_thunk_addr ^ thunk_retail_key
        elif debug_entry > text_sec.m_virtual_addr and debug_entry < (text_sec.m_virtual_addr + text_sec.m_virtual_size):
            self.entry = debug_entry
            self.kernel_thunk_addr = self.cipher_kernel_image_thunk_addr ^ thunk_debug_key


    def get_section_by_name(self, section_name):
        for section in self.sections:
            cand_section_name = get_cstr(self.get_data_range(section.m_section_name_addr, end = None))
            print(cand_section_name)
            print(f"section name addr: {section.m_section_name_addr:#x}")
            print(f"section name addr + len: {section.m_section_name_addr + len(section_name):#x}")
            if section_name == cand_section_name:
                return section
        return None
