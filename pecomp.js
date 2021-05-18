#!/usr/bin env

"use strict";

const fs = require("fs").promises,
	assert = require("assert").strict;

class PEC {
	
	innerbuf = null;
	stub = null;
	err = "";
	
	constructor(prepare = false) {
		if (prepare) this.writeout();
	} //ctor
	
	static init(...args) {
		return new PEC(...args);
	} //init
	
	static msdostub(prt = "BA10000E1FB409CD21B8014CCD219090546869732070726F6772616D206D7573742062652072756E20756E6465722057696E58580D0A2437") {
		const stub = Buffer.allocUnsafeSlow(0x110 / 2);
		
		let i = stub.writeUInt16LE(0x5A4D, 0);	// e_magic:		4d 5a		// Magic number 'MZ'
		i = stub.writeUInt16LE(0x90, i);		// e_cblp:		FF 00		// Bytes on last page of file
		i = stub.writeUInt16LE(3, i);			// e_cp:		03 00		// Pages in file
		i = stub.writeUInt16LE(0, i);			// e_crlc:		00 00		// Relocations
		i = stub.writeUInt16LE(4, i);			// e_cparhdr:	04 00		// Size of header in paragraphs
		i = stub.writeUInt16LE(0, i);			// e_minalloc:	00 00		// Minimum extra paragraphs needed
		i = stub.writeUInt16LE(0xFFFF, i);		// e_maxalloc:	ff ff		// Maximum extra paragraphs needed
		i = stub.writeUInt16LE(0, i);			// e_ss:		00 00		// Initial (relative) SS value
		i = stub.writeUInt16LE(0xB8, i);		// e_sp:		b8 00		// Initial SP value
		i = stub.writeUInt16LE(0, i);			// e_csum:		00 00		// Checksum
		i = stub.writeUInt16LE(0, i);			// e_ip:		00 00		// Initial IP value
		i = stub.writeUInt16LE(0, i);			// e_cs:		00 00		// Initial (relative) CS value
		i = stub.writeUInt16LE(0x40, i);		// e_lfarlc:	40 00		// File address of relocation table
		//i = stub.writeUInt16LE(0, i);			// e_ovno:		00 00		// Overlay number
		i = stub.writeBigUInt64LE(0n, i + 2);	// e_res:		00 00 00 00 00 00 00 00	// Reserved
		i = stub.writeUInt16LE(0, i);			// e_oemid:		00 00		// OEM identifier (for e_oeminfo)
		i = stub.writeUInt16LE(0, i);			// e_oeminfo:	00 00		// OEM information; e_oemid specific
		i = stub.writeBigUInt64LE(0n, i);		// e_res2:		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00	// Reserved
		i = stub.writeBigUInt64LE(0n, i);		// 
		i = stub.writeUInt32LE(0, i);			// 
		i = stub.writeUInt32LE(0x80, i);		// e_lfanew:	80 00 00 00	// File address of the PE header
		
		i += stub.write(prt, i, prt.length / 2, "hex");
		
		if (i < 128) i += stub.write("00".repeat(128 - i), i, 128 - i, "hex");
		
		i = stub.write("50450000", 0x80, 4, "hex");
		
		return stub;
	} //msdostub
	
	isValid() {
		let retstr = "";
		
		assert(this.stub, "Stub needs to be created first, load a file.");
		
		if (this.innerbuf.length < 20) return "Binary does not have valid length\n";
		if (this.stub.isimg && this.innerbuf.length < 148) return "Binary(Img) does not have valid length\n";
		if (this.stub.isopt == 0x10b && this.stub.optionalsize.readUInt16LE() < 96)
			retstr += "OPT size broken\n";
		if (this.stub.isopt == 0x20b && this.stub.optionalsize.readUInt16LE() < 112)
			retstr += "OPT+ size broken\n";
		if (this.stub.isimg && this.stub.sig.toString("binary") != "PE\u0000\u0000")
			retstr += "PE signature broken\n";
		if (!(this.stub.isopt == 0x10b || this.stub.isopt == 0x20b))
			retstr += "OPT signature broken\n";
		if (this.stub.isimg && this.stub.e_res.toString("binary") != "\u0000".repeat(8))
			retstr += "PE Reserved Space #1 should be all-zero-filled\n";
		if (this.stub.isimg && this.stub.e_res2.toString("binary") != "\u0000".repeat(20))
			retstr += "PE Reserved Space #2 should be all-zero-filled\n";
		if (this.isimg && (this.stub.symtabptr.readUInt16LE() || this.stub.symbnum.readUInt16LE()))
		retstr += "Debug COFF symbol table deprecated on images\n";
		if (!this.stub.isimg && this.stub.optionalsize.readUInt16LE()) retstr += "Optional header invalid on object files\n";
		if (this.stub.sectnum.readUInt16LE() < 2) retstr += "Sections must be at least 2\n";
		if (this.stub.sectnum.readUInt16LE() > 96) retstr += "Sections must be at most 96\n";
		if ((this.stub.chrctrs.readUInt16LE() & PEC.MSDStub.Characteristics.LINE_NUMS_STRIPPED) == PEC.MSDStub.Characteristics.LINE_NUMS_STRIPPED)
			retstr += "The LINE_NUMS_STRIPPED Characteristic is deprecated\n";
		if ((this.stub.chrctrs.readUInt16LE() & PEC.MSDStub.Characteristics.LOCAL_SYMS_STRIPPED) == PEC.MSDStub.Characteristics.LOCAL_SYMS_STRIPPED)
			retstr += "The LOCAL_SYMS_STRIPPED Characteristic is deprecated\n";
		if ((this.stub.chrctrs.readUInt16LE() & PEC.MSDStub.Characteristics.AGGRESSIVE_WS_TRIM) == PEC.MSDStub.Characteristics.AGGRESSIVE_WS_TRIM)
			retstr += "The AGGRESSIVE_WS_TRIM Characteristic is deprecated\n";
		if ((this.stub.chrctrs.readUInt16LE() & PEC.MSDStub.Characteristics.RESERVED) == PEC.MSDStub.Characteristics.RESERVED)
			retstr += "Characteristic Flag Reserved for future use is used\n";
		if ((this.stub.chrctrs.readUInt16LE() & PEC.MSDStub.Characteristics.BYTES_REVERSED_HI) == PEC.MSDStub.Characteristics.BYTES_REVERSED_HI)
			retstr += "The BYTES_REVERSED_HI Characteristic is deprecated\n";
		
		return retstr;
	} //isValid
	
	parseStub() {
		let i = 0;
		
		if (!this.stub) this.stub = PEC.MSDStub.init();
		
		if (this.innerbuf.length < 20) {
			this.err = this.isValid();
			
			return this.stub;
		}
		
		this.stub.e_magic = this.innerbuf.slice(0, 2);			// e_magic:		4d 5a		// Magic number 'MZ'
		
		if (this.stub.e_magic.toString("binary") == "MZ" && this.innerbuf.length >= 128) { //IMAGE
			//PE - 128B
			
			this.stub.e_cblp = this.innerbuf.slice(2, 4);		// e_cblp:		FF 00		// Bytes on last page of file
			this.stub.e_cp = this.innerbuf.slice(4, 6);			// e_cp:		03 00		// Pages in file
			this.stub.e_crlc = this.innerbuf.slice(6, 8);		// e_crlc:		00 00		// Relocations
			this.stub.e_cparhdr = this.innerbuf.slice(8, 10);	// e_cparhdr:	04 00		// Size of header in paragraphs
			this.stub.e_minalloc = this.innerbuf.slice(10, 12);	// e_minalloc:	00 00		// Minimum extra paragraphs needed
			this.stub.e_maxalloc = this.innerbuf.slice(12, 14);	// e_maxalloc:	ff ff		// Maximum extra paragraphs needed
			this.stub.e_ss = this.innerbuf.slice(14, 16);		// e_ss:		00 00		// Initial (relative) SS value
			this.stub.e_sp = this.innerbuf.slice(16, 18);		// e_sp:		b8 00		// Initial SP value
			this.stub.e_csum = this.innerbuf.slice(18, 20);		// e_csum:		00 00		// Checksum
			this.stub.e_ip = this.innerbuf.slice(20, 22);		// e_ip:		00 00		// Initial IP value
			this.stub.e_cs = this.innerbuf.slice(22, 24);		// e_cs:		00 00		// Initial (relative) CS value
			this.stub.e_lfarlc = this.innerbuf.slice(24, 26);	// e_lfarlc:	40 00		// File address of relocation table
			this.stub.e_ovno = this.innerbuf.slice(26, 28);		// e_ovno:		00 00		// Overlay number
			this.stub.e_res = this.innerbuf.slice(28, 36);		// e_res:		00 00 00 00 00 00 00 00	// Reserved
			this.stub.e_oemid = this.innerbuf.slice(36, 38);	// e_oemid:		00 00		// OEM identifier (for e_oeminfo)
			this.stub.e_oeminfo = this.innerbuf.slice(38, 40);	// e_oeminfo:	00 00		// OEM information; e_oemid specific
			this.stub.e_res2 = this.innerbuf.slice(40, 60);		// e_res2:		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00	// Reserved
			this.stub.e_lfanew = this.innerbuf.slice(60, 64);	// e_lfanew:	80 00 00 00	// File address of the PE header
			
			i = this.stub.e_lfanew.readUInt16LE();
			this.stub.sig = this.innerbuf.slice(i, i += 4);		// sig			00 00 45 50	// PE magic
			
			this.stub.isimg = true;
		}
		
		if (this.stub.isimg && this.innerbuf.length < 148) {
			this.err = this.isValid();
			
			return this.stub;
		}
		
		//COFF - 20B
		
		this.stub.machine = this.innerbuf.slice(i, i += 2);			// machine		00 00		// Machine/Platform identifier (0 is all)
		this.stub.sectnum = this.innerbuf.slice(i, i += 2);			// sectnum		05 00		// At least 2
		this.stub.timestamp = this.innerbuf.slice(i, i += 4);		// timestamp	00 00 00 00	// The low 32 bits of the number of seconds since 00:00 January 1, 1970
		this.stub.symtabptr = this.innerbuf.slice(i, i += 4);		// symtabptr	00 00 00 00	// Object debug symbol table - zero for image
		this.stub.symbnum = this.innerbuf.slice(i, i += 4);			// symbnum		00 00 00 00	// Object debug symbol table - zero for image
		this.stub.optionalsize = this.innerbuf.slice(i, i += 2);	// optionalsize	?? ??		// Size of optional header - zero for object
		this.stub.chrctrs = this.innerbuf.slice(i, i += 2);			// chrctrs		00 00		// Characteristics
		
		if (this.stub.optionalsize.readUInt16LE() > 96) {
			// OPT
			
			this.stub.o_magic = this.innerbuf.slice(i, i += 2);		// o_magic:		0b 01/02	// Magic number [0x10b exe, 0x107 rom, 0x20b pe32+]
			this.stub.isopt = this.stub.o_magic.readUInt16LE();
			
			if ((this.stub.isopt == 0x10b && this.stub.optionalsize.readUInt16LE() < 96) ||
				(this.stub.isopt == 0x20b && this.stub.optionalsize.readUInt16LE() < 112)) {
				this.err = this.isValid();
				
				return this.stub;
			}
			
			this.stub.o_major = this.innerbuf.slice(i, ++i);			// o_major:			00			// Linker major version
			this.stub.o_minor = this.innerbuf.slice(i, ++i);			// o_minor:			00			// Linker minor version
			this.stub.o_code_sz = this.innerbuf.slice(i, i += 4);		// o_code_sz:		00 00 00 00	// Size of code sections
			this.stub.o_initdat_sz = this.innerbuf.slice(i, i += 4);	// o_initdat_sz:	00 00 00 00	// Size of initialized data sections
			this.stub.o_uninitdat_sz = this.innerbuf.slice(i, i += 4);	// o_uninitdat_sz:	00 00 00 00	// Size of uninitialized data sections
			this.stub.o_entry = this.innerbuf.slice(i, i += 4);			// o_entry:			00 00 00 00	// Entry relative to base
			this.stub.o_base = this.innerbuf.slice(i, i += 4);			// o_base:			00 00 00 00	// Memory base relative to image
		} else if (this.stub.optionalsize.readUInt16LE()) {
			this.err = this.isValid();
			
			return this.stub;
		}
		
		this.err = this.isValid();
		
		return this.stub;
	} //parseStub
	
	async writeout(file) {
		if (!this.innerbuf) {
			this.innerbuf = PEC.msdostub();
			this.parseStub();
		}
		
		if (!file) return this.innerbuf;
		else {
			return await fs.writeFile(file, this.innerbuf);
		}
	} //writeout
	
	static async read(file) {
		assert(file, "'file' needs to be provided");
		
		const pec = PEC.init(false);
		
		pec.innerbuf = await fs.readFile(file);
		
		pec.parseStub();
		
		return pec;
	} //read
	
} //PEC

class MSDStub {
	
	e_magic = null; e_cblp = null;
	e_cp = null; e_crlc = null;
	e_cparhdr = null; e_minalloc = null;
	e_maxalloc = null; e_ss = null;
	e_sp = null; e_csum = null;
	e_ip = null; e_cs = null;
	e_lfarlc = null; e_ovno = null;
	e_res = null; e_oemid = null;
	e_oeminfo = null; e_res2 = null;
	e_lfanew = null; e_sig = null;
	machine = null; sectnum = null;
	timestamp = null; symtabptr = null;
	symbnum = null; optionalsize = null;
	chrctrs = null; isimg = false;
	o_magic = null; o_major = null;
	o_minor = null; o_code_sz = null;
	o_initdat_sz = null; o_uninitdat_sz = null;
	o_entry = null; o_base = null;
	o_database = null; isopt = 0;
	
	constructor(...args) {
		for (const i in this)
			if (!this[i]) this[i] = Buffer.from("00000000", "hex");
	} //ctor
	
	get str() {
		return this.toString();
	} //g-str
	
	toString() {
		const head = `\t\t\t\t\x1b[4;3;1mVALUES DISPLAYED IN LE ENDIANNESS.\x1b[0m `,
			pe = this.isimg ? `\t\x1b[4;1m${'-'.repeat(35)} MSDOS STUB ${'-'.repeat(35)}\x1b[0m 
pe_magic\t\t(2b : e_magic)\t\t=\t${this.e_magic.toString("binary")}\t\t(${this.e_magic.toString("hex")})
bytes_last_page\t\t(2b : e_cblp)\t\t=\t${this.e_cblp.readUInt16LE()}\t\t(${this.e_cblp.toString("hex")})
pages\t\t\t(2b : e_cp)\t\t=\t${this.e_cp.readUInt16LE()}\t\t(${this.e_cp.toString("hex")})
relocs\t\t\t(2b : e_crlc)\t\t=\t${this.e_crlc.readUInt16LE()}\t\t(${this.e_crlc.toString("hex")})
header_size_paragraphs\t(2b : e_cparhdr)\t=\t${this.e_cparhdr.readUInt16LE()}\t\t(${this.e_cparhdr.toString("hex")})
min_extra_paragraphs\t(2b : e_minalloc)\t=\t${this.e_minalloc.readUInt16LE()}\t\t(${this.e_minalloc.toString("hex")})
max_extra_paragraphs\t(2b : e_maxalloc)\t=\t${this.e_maxalloc.readUInt16LE()}\t\t(${this.e_maxalloc.toString("hex")})
rel_stack_seg\t\t(2b : e_ss)\t\t=\t${this.e_ss.readUInt16LE()}\t\t(${this.e_ss.toString("hex")})
init_stack_ptr\t\t(2b : e_sp)\t\t=\t${this.e_sp.readUInt16LE()}\t\t(${this.e_sp.toString("hex")})
checksum\t\t(2b : e_csum)\t\t=\t${this.e_csum.readUInt16LE()}\t\t(${this.e_csum.toString("hex")})
init_instr_ptr\t\t(2b : e_ip)\t\t=\t${this.e_ip.readUInt16LE()}\t\t(${this.e_ip.toString("hex")})
rel_cs_addr\t\t(2b : e_cs)\t\t=\t${this.e_cs.readUInt16LE()}\t\t(${this.e_cs.toString("hex")})
reloctable_addr\t\t(2b : e_lfarlc)\t\t=\t${this.e_lfarlc.readUInt16LE()}\t\t(${this.e_lfarlc.toString("hex")})
overlay_num\t\t(2b : e_ovno)\t\t=\t${this.e_ovno.readUInt16LE()}\t\t(${this.e_ovno.toString("hex")})
reserve1\t\t(8b : e_res)\t\t=\t${this.e_res.toString("hex")}
oem_id\t\t\t(2b : e_oemid)\t\t=\t${this.e_oemid.readUInt16LE()}\t\t(${this.e_oemid.toString("hex")})
oem_info\t\t(2b : e_oeminfo)\t=\t${this.e_oeminfo.readUInt16LE()}\t\t(${this.e_oeminfo.toString("hex")})
reserve2\t\t(20b: e_res2)\t\t=\t${this.e_res2.toString("hex")}
pe_addr\t\t\t(4b : e_lfanew)\t\t=\t${this.e_lfanew.readUInt32LE()}\t\t(${this.e_lfanew.toString("hex")})
pe_sig\t\t\t(4b : sig)\t\t=\t${this.e_sig.toString("binary")}\t\t(${this.e_sig.toString("hex")})\n` : "",
		coff = `\t\x1b[4;1m${'-'.repeat(35)}    COFF    ${'-'.repeat(35)}\x1b[0m 
machine\t\t\t(2b : machine)\t\t=\t${Object.keys(PEC.MSDStub.Machine).find(k => PEC.MSDStub.Machine[k] == this.machine.readUInt16LE()) || this.machine.readUInt16LE()}\t\t(${this.machine.toString("hex")})
sector_num\t\t(2b : sectnum)\t\t=\t${this.sectnum.readUInt16LE()}\t\t(${this.sectnum.toString("hex")})
timestamp\t\t(4b : timestamp)\t=\t${this.timestamp.readUInt32LE()}\t(${this.timestamp.toString("hex")})
symtable_ptr\t\t(4b : symtabptr)\t=\t${this.symtabptr.readUInt32LE()}\t\t(${this.symtabptr.toString("hex")})
symbol_num\t\t(4b : symbnum)\t\t=\t${this.symbnum.readUInt32LE()}\t\t(${this.symbnum.toString("hex")})
opt_hdr_size\t\t(2b : optionalsize)\t=\t${this.optionalsize.readUInt16LE()}\t\t(${this.optionalsize.toString("hex")})
characteristics\t\t(2b : chrctrs)\t\t=\t${Object.keys(PEC.MSDStub.Characteristics).filter(k => (this.chrctrs.readUInt16LE() & PEC.MSDStub.Characteristics[k]) == PEC.MSDStub.Characteristics[k]).join(", ") || this.chrctrs.readUInt16LE()}\t(${this.chrctrs.toString("hex")})\n`,
		opt = this.isopt ? `\t\x1b[4;1m${'-'.repeat(35)}    OPT     ${'-'.repeat(35)}\x1b[0m 
o_magic\t\t\t(2b : o_magic)\t\t=\t${this.opt == 0x10b ? "PE" : (this.opt == 0x20b ? "PE+" : (this.opt == 0x107 ? "ROM" : this.opt))}\t(${this.o_magic.toString("hex")})
link_major\t\t(1b : o_major)\t\t=\t${this.o_major.readUInt8()}\t[${this.o_major.toString("hex")}]
link_minor\t\t(1b : o_minor)\t\t=\t${this.o_minor.readUInt8()}\t[${this.o_minor.toString("hex")}]
code_sz\t\t\t(4b : o_code_sz)\t=\t${this.o_code_sz.readUInt32LE()}\t[${this.o_code_sz.toString("hex")}]
initdat_sz\t\t(4b : o_initdat_sz)\t=\t${this.o_initdat_sz.readUInt32LE()}\t[${this.o_initdat_sz.toString("hex")}]
uninitdat_sz\t\t(4b : o_uninitdat_sz)\t=\t${this.o_uninitdat_sz.readUInt32LE()}\t[${this.o_uninitdat_sz.toString("hex")}]
entry\t\t\t(4b : o_entry)\t\t=\t${this.o_entry.readUInt32LE()}\t[${this.o_entry.toString("hex")}]
base\t\t\t(4b : o_base)\t\t=\t${this.o_base.readUInt32LE()}\t[${this.o_base.toString("hex")}]
databse\t\t\t(4b : o_database)\t=\t${this.o_database.readUInt32LE()}\t[${this.o_database.toString("hex")}]\n` : "";
		
		return pe + coff + opt;
	} //toString
	
	[Symbol.toPrimitive](hint) {
		if (hint == "string") return this.str;
		else return this;
	}
	
	static init(...args) {
		return new PEC.MSDStub(...args);
	} //init
	
} //Stub

Object.defineProperty(MSDStub, "Machine", {
	value: {
		UNKNOWN:	0x0,	// The content of this field is assumed to be applicable to any machine type
		AM33:		0x1d3,	// Matsushita AM33
		AMD64:		0x8664,	// x64
		ARM:		0x1c0,	// ARM little endian
		ARM64:		0xaa64,	// ARM64 little endian
		ARMNT:		0x1c4,	// ARM Thumb-2 little endian
		EBC:		0xebc,	// EFI byte code
		I386:		0x14c,	// Intel 386 or later processors and compatible processors
		IA64:		0x200,	// Intel Itanium processor family
		M32R:		0x9041,	// Mitsubishi M32R little endian
		MIPS16:		0x266,	// MIPS16
		MIPSFPU:	0x366,	// MIPS with FPU
		MIPSFPU16:	0x466,	// MIPS16 with FPU
		POWERPC:	0x1f0,	// Power PC little endian
		POWERPCFP:	0x1f1,	// Power PC with floating point support
		R4000:		0x166,	// MIPS little endian
		RISCV32:	0x5032,	// RISC-V 32-bit address space
		RISCV64:	0x5064,	// RISC-V 64-bit address space
		RISCV128:	0x5128,	// RISC-V 128-bit address space
		SH3:		0x1a2,	// Hitachi SH3
		SH3DSP:		0x1a3,	// Hitachi SH3 DSP
		SH4:		0x1a6,	// Hitachi SH4
		SH5:		0x1a8,	// Hitachi SH5
		THUMB:		0x1c2,	// Thumb
		WCEMIPSV2:	0x169,	// MIPS little-endian WCE v2
	}
});
Object.defineProperty(MSDStub, "Characteristics", {
	value: {
		RELOCS_STRIPPED:			0x0001,	// Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files.
		EXECUTABLE_IMAGE:			0x0002,	// Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.
		LINE_NUMS_STRIPPED:			0x0004,	// COFF line numbers have been removed. This flag is deprecated and should be zero.
		LOCAL_SYMS_STRIPPED:		0x0008,	// COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
		AGGRESSIVE_WS_TRIM:			0x0010,	// Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
		LARGE_ADDRESS_AWARE:		0x0020,	// Application can handle > 2-GB addresses.
		RESERVED:					0x0040,	// This flag is reserved for future use.
		BYTES_REVERSED_LO:			0x0080,	// Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
		BIT32_MACHINE:				0x0100,	// Machine is based on a 32-bit-word architecture.
		DEBUG_STRIPPED:				0x0200,	// Debugging information is removed from the image file.
		REMOVABLE_RUN_FROM_SWAP:	0x0400,	// If the image is on removable media, fully load it and copy it to the swap file.
		NET_RUN_FROM_SWAP:			0x0800,	// If the image is on network media, fully load it and copy it to the swap file.
		SYSTEM:						0x1000,	// The image file is a system file, not a user program.
		DLL:						0x2000,	// The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
		UP_SYSTEM_ONLY:				0x4000,	// The file should be run only on a uniprocessor machine.
		BYTES_REVERSED_HI:			0x8000,	// Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
	}
});
PEC.MSDStub = MSDStub;
global._pec = PEC.init(true);
global.PEC = exports.PEC = PEC;
