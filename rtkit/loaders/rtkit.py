import os
import idaapi
import struct


def accept_file(f, n):
    print(f"HELLO {n}")

    f.seek(-0x20, os.SEEK_END)
    if f.read(4) == b'fwsg':
        return "RTKit Firmware"
    return 0


def load_file(f, neflags, format):
    idaapi.set_processor_type("arm:armv8", idaapi.SETPROC_LOADER)

    f.seek(-0x20, os.SEEK_END)
    nseg, = struct.unpack("<12xI16x", f.read(0x20))
    print(f"Number of segments: {nseg}")

    for sno in range(nseg):
        f.seek(-0x20-0x20*(nseg-sno), os.SEEK_END)
        mem_addr, file_addr, size, name = struct.unpack("<QII8x8s", f.read(0x20))
        name, _, _ = name.partition(b'\0')
        name = name.decode()
        print(f"Segment {sno}: {name} at mem={hex(mem_addr)} file={hex(file_addr)} size={hex(size)}")

        ida_seg_type = None
        if name == "__TEXT":
            ida_seg_type = "CODE"
        if name == "__DATA":
            ida_seg_type = "DATA"

        idaapi.add_segm(0, mem_addr, mem_addr + size, name, ida_seg_type)
        f.file2base(file_addr, mem_addr, mem_addr + size, True)

    f.seek(-0x20-0x20*nseg, os.SEEK_END)
    footer_start = f.tell()
    footer_end = footer_start + 0x20 + 0x20 * nseg
    idaapi.add_segm(0, footer_start, footer_end, "__FOOTER", "DATA")
    f.file2base(footer_start, footer_start, footer_end, True)

    header_start = footer_start + 0x20 * nseg
    idaapi.add_extra_line(header_start, True, "")
    idaapi.add_extra_cmt(header_start, True, f"File Header")
    idaapi.create_strlit(header_start, 4, 0)
    idaapi.set_cmt(header_start, "Magic", False)
    idaapi.create_dword(header_start + 4, 4)
    idaapi.set_cmt(header_start + 4, "Version?", False)
    idaapi.create_dword(header_start + 8, 4)
    idaapi.set_cmt(header_start + 8, "File length minus headers", False)
    idaapi.create_dword(header_start + 12, 4)
    idaapi.set_cmt(header_start + 12, "Section count", False)
    for sno in range(nseg):
        header_start = footer_start + 0x20 * sno
        idaapi.add_extra_line(header_start, True, "")
        idaapi.add_extra_cmt(header_start, True, f"Segment {sno + 1}")
        idaapi.create_qword(header_start, 8)
        idaapi.set_cmt(header_start, "Memory Address", False)
        idaapi.create_dword(header_start + 8, 4)
        idaapi.set_cmt(header_start + 8, "File Offset", False)
        idaapi.create_dword(header_start + 12, 4)
        idaapi.create_qword(header_start + 16, 8)
        idaapi.set_cmt(header_start + 12, "Segment Length", False)
        idaapi.create_strlit(header_start + 24, 8, 0)
        idaapi.set_cmt(header_start + 24, "Segment Name", False)

    idaapi.add_entry(0, 0, "start", 1)

    return 1
