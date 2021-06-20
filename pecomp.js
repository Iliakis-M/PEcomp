"use strict";

/**
 * @todo https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#grouped-sections-object-only
 */

const fs = require("fs").promises,
	assert = require("assert").strict,
	os = require("os"),
	dbg = require("util").debuglog("PE");

function pad(str = "", min = 1, by = ' ', post = true) {
	str = (str !== undefined ? str : "") + '';
	
	if (str.length < min) {
		if (post) return by.repeat(min - str.length) + str;
		else return str + by.repeat(min - str.length);
	}
	
	return str;
} //pad

dbg("Loading...");

class PEC {
	
	innerbuf = null;
	/**
	 * @type Hdr
	 */
	hdr = null;
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
		
		dbg("Validity Check");
		
		assert(this.hdr, "Stub needs to be created first, load a file.");
		
		//sizecheck/always
		
		if (this.innerbuf.length < 20) return "Binary does not have valid length" + os.EOL;
		else if (this.hdr.isimg && this.innerbuf.length < 148) return "Binary (Img) does not have valid length" + os.EOL;
		
		if (this.hdr.isimg && !this.hdr.isopt)
			return "Images need to define the Optional Header" + os.EOL;
		if (this.hdr.isopt == 0x10b && this.hdr.optionalsize.readUInt16LE() < 96)
			return "OPT size (optionalsize) broken" + os.EOL;
		else if (this.hdr.isopt == 0x20b && this.hdr.optionalsize.readUInt16LE() < 112)
			return "OPT+ size (optionalsize) broken" + os.EOL;
		if (this.hdr.isopt && this.hdr.o_rva_sz.readUInt32LE() % 8)
			retstr += "RVA number should be a multiple of 8" + os.EOL;
		
		if (this.hdr.sectnum.readUInt16LE() < 2)
			retstr += "Sections must be at least 2" + os.EOL;
		else if (this.hdr.sectnum.readUInt16LE() > 96)
			retstr += "Sections must be at most 96" + os.EOL;
		
		//chrctrs
		
		if ((this.hdr.chrctrs.readUInt16LE() & PEC.Hdr.Characteristics.LINE_NUMS_STRIPPED) == PEC.Hdr.Characteristics.LINE_NUMS_STRIPPED)
			retstr += "The LINE_NUMS_STRIPPED Characteristic (chrctrs) is deprecated" + os.EOL;
		if ((this.hdr.chrctrs.readUInt16LE() & PEC.Hdr.Characteristics.LOCAL_SYMS_STRIPPED) == PEC.Hdr.Characteristics.LOCAL_SYMS_STRIPPED)
			retstr += "The LOCAL_SYMS_STRIPPED Characteristic (chrctrs) is deprecated" + os.EOL;
		if ((this.hdr.chrctrs.readUInt16LE() & PEC.Hdr.Characteristics.AGGRESSIVE_WS_TRIM) == PEC.Hdr.Characteristics.AGGRESSIVE_WS_TRIM)
			retstr += "The AGGRESSIVE_WS_TRIM Characteristic (chrctrs) is deprecated" + os.EOL;
		if ((this.hdr.chrctrs.readUInt16LE() & PEC.Hdr.Characteristics.BYTES_REVERSED_HI) == PEC.Hdr.Characteristics.BYTES_REVERSED_HI)
			retstr += "The BYTES_REVERSED_HI Characteristic (chrctrs) is deprecated" + os.EOL;
		if ((this.hdr.chrctrs.readUInt16LE() & PEC.Hdr.Characteristics.RESERVED) == PEC.Hdr.Characteristics.RESERVED)
			retstr += "Characteristic Flag Reserved for future (chrctrs) use is used" + os.EOL;
		
		//pe
		
		if (this.hdr.isimg && this.hdr.e_sig.toString("binary") != "PE\u0000\u0000")
			retstr += "PE signature (sig) broken" + os.EOL;
		if (this.hdr.isimg && this.hdr.e_res.toString("binary") != "\u0000".repeat(8))
			retstr += "PE Reserved Space #1 (e_res) should be all-zero-filled" + os.EOL;
		if (this.hdr.isimg && this.hdr.e_res2.toString("binary") != "\u0000".repeat(20))
			retstr += "PE Reserved Space #2 (e_res2) should be all-zero-filled" + os.EOL;
		if (this.hdr.isimg && (this.hdr.symtabptr.readUInt16LE() || this.hdr.symbnum.readUInt16LE()))
			retstr += "Debug COFF symbol table (symtabptr/symbnum) deprecated on images" + os.EOL;
		if (this.hdr.isimg && this.hdr.o_imbase.readUInt32LE() % (64 * 1024))
			retstr += "Image Base (o_imbase) must be multiple of 64KB" + os.EOL;
		if (!this.hdr.isimg && this.hdr.optionalsize.readUInt16LE())
			retstr += "Optional header (optionalsize != 0) invalid on object files" + os.EOL;
		
		//sect
		
		for (const s of this.hdr.sects) {
			const sectname = s.name.toString("binary");
			
			if (this.hdr.isimg && sectname.startsWith('/'))
				retstr += `Images cannot have string references at Sections (sects)[${sectname}]` + os.EOL;
			if (this.hdr.isimg && sectname.includes('$'))
				retstr += `Section ${sectname} cannot have a dollar ($) notation since the binary is an Image` + os.EOL;
			if (this.hdr.isimg && s.rawdatptr.readUInt32LE() % this.hdr.o_filealign)
				retstr += `Section ${sectname} raw data pointers (rawdatptr) should be multiples of File Alignment (o_filealign) for Images` + os.EOL;
			else if (s.rawdatptr.readUInt32LE() % 4)
				retstr += `Section ${sectname} raw data pointers (rawdatptr) should be multiples of 4B for Objects` + os.EOL;
			if (this.hdr.isimg && (s.relocptr.readUInt32LE() || s.relocnum.readUInt16LE()))
				retstr += `Section ${sectname} relocations (relocptr/relocnum) should be zero for Images` + os.EOL;
			if (this.hdr.isimg && (s.linenonum.readUInt16LE() || s.linenoptr.readUInt32LE()))
				retstr += `Section ${sectname} lines (linenonum/linenoptr) are deprecated for Images` + os.EOL;
			
			//sect chrctrs
			
			if (this.hdr.isimg && (s.chrctrs & PEC.Hdr.SectCharacteristics.TYPE_NO_PAD))
				retstr += `Section ${s.name.toString("binary")} Characteristic TYPE_NO_PAD is invalid for Images` + os.EOL;
			if (!this.hdr.isimg && (s.chrctrs & PEC.Hdr.SectCharacteristics.LNK_INFO))
				retstr += `Section ${s.name.toString("binary")} Characteristic LNK_INFO is invalid for Images` + os.EOL;
			if (!this.hdr.isimg && (s.chrctrs & PEC.Hdr.SectCharacteristics.LNK_REMOVE))
				retstr += `Section ${s.name.toString("binary")} Characteristic LNK_REMOVE is invalid for Images` + os.EOL;
			if (!this.hdr.isimg && (s.chrctrs & PEC.Hdr.SectCharacteristics.LNK_COMDAT))
				retstr += `Section ${s.name.toString("binary")} Characteristic LNK_COMDAT is invalid for Images` + os.EOL;
			
			if (!this.hdr.isimg && (s.chrctrs & PEC.Hdr.SectCharacteristics.ALIGN_1BYTES))
				retstr += `Section ${s.name.toString("binary")} Characteristic ALIGN_1BYTES is invalid for Images` + os.EOL;
			if (!this.hdr.isimg && (s.chrctrs & PEC.Hdr.SectCharacteristics.ALIGN_2BYTES))
				retstr += `Section ${s.name.toString("binary")} Characteristic ALIGN_2BYTES is invalid for Images` + os.EOL;
			if (!this.hdr.isimg && (s.chrctrs & PEC.Hdr.SectCharacteristics.ALIGN_4BYTES))
				retstr += `Section ${s.name.toString("binary")} Characteristic ALIGN_4BYTES is invalid for Images` + os.EOL;
			if (!this.hdr.isimg && (s.chrctrs & PEC.Hdr.SectCharacteristics.ALIGN_8BYTES))
				retstr += `Section ${s.name.toString("binary")} Characteristic ALIGN_8BYTES is invalid for Images` + os.EOL;
			if (!this.hdr.isimg && (s.chrctrs & PEC.Hdr.SectCharacteristics.ALIGN_16BYTES))
				retstr += `Section ${s.name.toString("binary")} Characteristic ALIGN_16BYTES is invalid for Images` + os.EOL;
			if (!this.hdr.isimg && (s.chrctrs & PEC.Hdr.SectCharacteristics.ALIGN_32BYTES))
				retstr += `Section ${s.name.toString("binary")} Characteristic ALIGN_32BYTES is invalid for Images` + os.EOL;
			if (!this.hdr.isimg && (s.chrctrs & PEC.Hdr.SectCharacteristics.ALIGN_64BYTES))
				retstr += `Section ${s.name.toString("binary")} Characteristic ALIGN_64BYTES is invalid for Images` + os.EOL;
			if (!this.hdr.isimg && (s.chrctrs & PEC.Hdr.SectCharacteristics.ALIGN_128BYTES))
				retstr += `Section ${s.name.toString("binary")} Characteristic ALIGN_128BYTES is invalid for Images` + os.EOL;
			if (!this.hdr.isimg && (s.chrctrs & PEC.Hdr.SectCharacteristics.ALIGN_256BYTES))
				retstr += `Section ${s.name.toString("binary")} Characteristic ALIGN_256BYTES is invalid for Images` + os.EOL;
			if (!this.hdr.isimg && (s.chrctrs & PEC.Hdr.SectCharacteristics.ALIGN_512BYTES))
				retstr += `Section ${s.name.toString("binary")} Characteristic ALIGN_512BYTES is invalid for Images` + os.EOL;
			if (!this.hdr.isimg && (s.chrctrs & PEC.Hdr.SectCharacteristics.ALIGN_1024BYTES))
				retstr += `Section ${s.name.toString("binary")} Characteristic ALIGN_1024BYTES is invalid for Images` + os.EOL;
			if (!this.hdr.isimg && (s.chrctrs & PEC.Hdr.SectCharacteristics.ALIGN_2048BYTES))
				retstr += `Section ${s.name.toString("binary")} Characteristic ALIGN_2048BYTES is invalid for Images` + os.EOL;
			if (!this.hdr.isimg && (s.chrctrs & PEC.Hdr.SectCharacteristics.ALIGN_4096BYTES))
				retstr += `Section ${s.name.toString("binary")} Characteristic ALIGN_4096BYTES is invalid for Images` + os.EOL;
			if (!this.hdr.isimg && (s.chrctrs & PEC.Hdr.SectCharacteristics.ALIGN_8192BYTES))
				retstr += `Section ${s.name.toString("binary")} Characteristic ALIGN_8192BYTES is invalid for Images` + os.EOL;
			
			/*
LNK_NRELOC_OVFL indicates that the count of relocations for the section exceeds the 16 bits that are reserved for it in the section header.
If the bit is set and the NumberOfRelocations field in the section header is 0xffff, the actual relocation count is stored in the 32-bit VirtualAddress field of the first relocation.
It is an error if IMAGE_SCN_LNK_NRELOC_OVFL is set and there are fewer than 0xffff relocations in the section.
			*/
			
			//+ lookup '/'name from strings table
		}
		
		//opt
		
		if (!(this.hdr.isopt == 0x10b || this.hdr.isopt == 0x20b || this.hdr.isopt == 0x107))
			retstr += "OPT signature broken" + os.EOL;
		if (this.hdr.isopt && this.hdr.o_win32res.readUInt32LE())
			retstr += "Win32Res should be all-zero-filled" + os.EOL;
		if (this.hdr.isopt && this.hdr.o_ldflag.readUInt32LE())
			retstr += "Loader Flags (o_ldflag) should be all-zero-filled" + os.EOL;
		if (this.hdr.isopt && (this.hdr.o_filealign.readUInt32LE() < 0x200 || this.hdr.o_filealign.readUInt32LE() > 64 * 1024))
			retstr += "File Alignment (o_filealign) must be between 512 and 64KB (and if section alignment is less than arch's page size, must be equal to it)" + os.EOL;
		if (this.hdr.isopt && this.hdr.o_sectalign.readUInt32LE() < this.hdr.o_filealign.readUInt32LE())
			retstr += "Section Alignment (o_sectalign) must greater or equal to File Alignment (o_filealign)" + os.EOL;
		if (this.hdr.isopt && this.hdr.o_imgsz.readUInt32LE() % this.hdr.o_sectalign.readUInt32LE())
			retstr += "Image Size (o_imgsz) must be multiple of Section Alignment (o_sectalign)" + os.EOL;
		if (this.hdr.isopt && this.hdr.o_hdrsz.readUInt32LE() % this.hdr.o_filealign.readUInt32LE())
			retstr += "Headers Size (o_hdrsz) must be multiple of File Alignment (o_filealign)" + os.EOL;
		if (this.hdr.isopt && (this.hdr.o_dllchrctrs.readUInt16LE() & (PEC.Hdr.DLLCharacteristics.RESERVED1 | PEC.Hdr.DLLCharacteristics.RESERVED2 | PEC.Hdr.DLLCharacteristics.RESERVED3 | PEC.Hdr.DLLCharacteristics.RESERVED4)))
			retstr += "Reserved DLL Characteristics (o_dllchrctrs) are being used" + os.EOL;
		if (this.hdr.isopt == 0x20b && (this.hdr.o_stackcomm.readBigUInt64LE() > this.hdr.o_stackres.readBigUInt64LE() || this.hdr.o_heapcomm.readBigUInt64LE() > this.hdr.o_heapres.readBigUInt64LE()) ||
			this.hdr.isopt != 0x20b && ((this.hdr.o_stackcomm.readUInt32LE() > this.hdr.o_stackres.readUInt32LE() || this.hdr.o_heapcomm.readUInt32LE() > this.hdr.o_heapres.readUInt32LE())))
			retstr += "Reserved (o_stackres/o_heapres) sizes must be greater or equal than Commited (o_stackcomm/o_heapcomm)" + os.EOL;
		if (this.hdr.isopt && (this.hdr.o_rvas[15] && (this.hdr.o_rvas[15].addr.readUInt32LE() || this.hdr.o_rvas[15].size.readUInt32LE()) || this.hdr.o_rvas[7] && (this.hdr.o_rvas[7].addr.readUInt32LE() || this.hdr.o_rvas[7].size.readUInt32LE()) || this.hdr.o_rvas[8] && this.hdr.o_rvas[8].size.readUInt32LE()))
			retstr += "Reserved Sections must be all-zero-filled" + os.EOL;
		
		return retstr;
	} //isValid
	
	parseStub() {
		var i = 0;
		
		dbg("Parse");
		
		if (!this.hdr) this.hdr = PEC.Hdr.init();
		
		if (this.innerbuf.length < 20) {
			this.err = this.isValid();
			
			return this.hdr;
		}
		
		this.hdr.e_magic		=	this.innerbuf.slice(0, 2);		// e_magic:		4d 5a		// Magic number 'MZ'
		
		if (this.hdr.e_magic.toString("binary") == "MZ" && this.innerbuf.length >= 128) { //IMAGE
			// PE - 128B
			
			this.hdr.e_cblp		=	this.innerbuf.slice(2, 4);		// e_cblp:		FF 00					// Bytes on last page of file
			this.hdr.e_cp		=	this.innerbuf.slice(4, 6);		// e_cp:		03 00					// Pages in file
			this.hdr.e_crlc		=	this.innerbuf.slice(6, 8);		// e_crlc:		00 00					// Relocations
			this.hdr.e_cparhdr	=	this.innerbuf.slice(8, 11);		// e_cparhdr:	04 00					// Size of header in paragraphs
			this.hdr.e_minalloc	=	this.innerbuf.slice(10, 12);	// e_minalloc:	00 00					// Minimum extra paragraphs needed
			this.hdr.e_maxalloc	=	this.innerbuf.slice(12, 14);	// e_maxalloc:	ff ff					// Maximum extra paragraphs needed
			this.hdr.e_ss		=	this.innerbuf.slice(14, 16);	// e_ss:		00 00					// Initial (relative) SS value
			this.hdr.e_sp		=	this.innerbuf.slice(16, 18);	// e_sp:		b8 00					// Initial SP value
			this.hdr.e_csum		=	this.innerbuf.slice(18, 20);	// e_csum:		00 00					// Checksum
			this.hdr.e_ip		=	this.innerbuf.slice(20, 22);	// e_ip:		00 00					// Initial IP value
			this.hdr.e_cs		=	this.innerbuf.slice(22, 24);	// e_cs:		00 00					// Initial (relative) CS value
			this.hdr.e_lfarlc	=	this.innerbuf.slice(24, 26);	// e_lfarlc:	40 00					// File address of relocation table
			this.hdr.e_ovno		=	this.innerbuf.slice(26, 28);	// e_ovno:		?? ??					// Overlay number
			this.hdr.e_res		=	this.innerbuf.slice(28, 36);	// e_res:		00 00 00 00 00 00 00 00	// Reserved
			this.hdr.e_oemid	=	this.innerbuf.slice(36, 38);	// e_oemid:		00 00					// OEM identifier (for e_oeminfo)
			this.hdr.e_oeminfo	=	this.innerbuf.slice(38, 40);	// e_oeminfo:	00 00					// OEM information; e_oemid specific
			this.hdr.e_res2		=	this.innerbuf.slice(40, 60);	// e_res2:		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00	// Reserved
			this.hdr.e_lfanew	=	this.innerbuf.slice(60, 64);	// e_lfanew:	80 00 00 00				// File address of the PE header
			
			i = this.hdr.e_lfanew.readUInt16LE();
			this.hdr.e_sig			=	this.innerbuf.slice(i, i += 4);	// sig			00 00 45 50	// PE magic
			
			this.hdr.isimg = true;
		} //IMAGE
		
		if (this.hdr.isimg && this.innerbuf.length < 148) {
			this.err = this.isValid();
			
			return this.hdr;
		}
		
		// COFF - 20B
		
		this.hdr.machine		=	this.innerbuf.slice(i, i += 2);	// machine		64 86		// Machine/Platform identifier (0 is all)
		this.hdr.sectnum		=	this.innerbuf.slice(i, i += 2);	// sectnum		05 00		// At least 2
		this.hdr.timestamp		=	this.innerbuf.slice(i, i += 4);	// timestamp	00 00 00 00	// The low 32 bits of the number of seconds since 00:00 January 1, 1970
		this.hdr.symtabptr		=	this.innerbuf.slice(i, i += 4);	// symtabptr	00 00 00 00	// Object debug symbol table - zero for image
		this.hdr.symbnum		=	this.innerbuf.slice(i, i += 4);	// symbnum		00 00 00 00	// Object debug symbol table - zero for image
		this.hdr.optionalsize	=	this.innerbuf.slice(i, i += 2);	// optionalsize	f0 00		// Size of optional header - zero for object
		this.hdr.chrctrs		=	this.innerbuf.slice(i, i += 2);	// chrctrs		23 00		// Characteristics
		
		const optsz = this.hdr.optionalsize.readUInt16LE();
		if (optsz > 96) {
			// OPT - 96/112 B
			
			let d = 0;
			
			if (optsz - d >= 4)	this.hdr.o_magic		=	this.innerbuf.slice(i + d, i + (d += 2));	else d = optsz;	// o_magic:		0b 01/02	// Magic number [0x10b exe, 0x107 rom, 0x20b pe32+]
			this.hdr.isopt = this.hdr.o_magic.readUInt16LE();
			
			if ((this.hdr.isopt == 0x10b && optsz < 96) ||
				(this.hdr.isopt == 0x20b && optsz < 112)) {
				this.err = this.isValid();
				
				return this.hdr;
			}
			
			if (optsz - d >= 4)	this.hdr.o_major		=	this.innerbuf.slice(i + d, i + ++d);		else d = optsz;	// o_major:			00			// Linker major version
			if (optsz - d >= 4)	this.hdr.o_minor		=	this.innerbuf.slice(i + d, i + ++d);		else d = optsz;	// o_minor:			00			// Linker minor version
			if (optsz - d >= 4)	this.hdr.o_code_sz		=	this.innerbuf.slice(i + d, i + (d += 4));	else d = optsz;	// o_code_sz:		00 00 00 00	// Size of code sections
			if (optsz - d >= 4)	this.hdr.o_initdat_sz	=	this.innerbuf.slice(i + d, i + (d += 4));	else d = optsz;	// o_initdat_sz:	00 00 00 00	// Size of initialized data sections
			if (optsz - d >= 4)	this.hdr.o_uninitdat_sz	=	this.innerbuf.slice(i + d, i + (d += 4));	else d = optsz;	// o_uninitdat_sz:	00 00 00 00	// Size of uninitialized data sections
			if (optsz - d >= 4)	this.hdr.o_entry		=	this.innerbuf.slice(i + d, i + (d += 4));	else d = optsz;	// o_entry:			00 00 00 00	// Entry relative to base
			if (optsz - d >= 4)	this.hdr.o_base			=	this.innerbuf.slice(i + d, i + (d += 4));	else d = optsz;	// o_base:			00 10 00 00// Memory code section relative to image
			
			if (this.hdr.isopt == 0x10b)
				this.hdr.o_database	=	this.innerbuf.slice(i + d, i + (d += 4));	// o_database:		00 00 00 00	// Memory data section relative to image
			
			// + 28/24 B
			
			if (optsz - d >= this.hdr.isopt == 0x20b ? 8 : 4)	this.hdr.o_imbase		=	this.innerbuf.slice(i + d, i + (d += (this.hdr.isopt == 0x20b ? 8 : 4)));	else d = optsz;	// o_imbase:	10 00 00 00 / 00 00 00 00 00 40 00 00	// Base of Image [0x10000000 dll, 0x00010000 ce-exe, 0x00400000 else]
			if (optsz - d >= 4)									this.hdr.o_sectalign	=	this.innerbuf.slice(i + d, i + (d += 4));									else d = optsz;	// o_sectalign	page_size								// >= FileAlignment
			if (optsz - d >= 4)									this.hdr.o_filealign	=	this.innerbuf.slice(i + d, i + (d += 4));									else d = optsz;	// o_filealign	00 02 00 00								// 64KB > . > 512 | If the SectionAlignment is less than the architecture's page size, then FileAlignment must match SectionAlignment.
			if (optsz - d >= 2)									this.hdr.o_majosver		=	this.innerbuf.slice(i + d, i + (d += 2));									else d = optsz;	// o_majosver	00 00									// 
			if (optsz - d >= 2)									this.hdr.o_minosver		=	this.innerbuf.slice(i + d, i + (d += 2));									else d = optsz;	// o_minosver	00 00									// 
			if (optsz - d >= 2)									this.hdr.o_majimver		=	this.innerbuf.slice(i + d, i + (d += 2));									else d = optsz;	// o_majimver	00 00									// 
			if (optsz - d >= 2)									this.hdr.o_minimver		=	this.innerbuf.slice(i + d, i + (d += 2));									else d = optsz;	// o_minimver	00 00									// 
			if (optsz - d >= 2)									this.hdr.o_majsubsver	=	this.innerbuf.slice(i + d, i + (d += 2));									else d = optsz;	// o_majsubsver	00 00									// 
			if (optsz - d >= 2)									this.hdr.o_minsubsver	=	this.innerbuf.slice(i + d, i + (d += 2));									else d = optsz;	// o_minsubsver	00 00									// 
			if (optsz - d >= 4)									this.hdr.o_win32res		=	this.innerbuf.slice(i + d, i + (d += 4));									else d = optsz;	// o_win32res	00 00 00 00								// Reserved, must be zero
			if (optsz - d >= 4)									this.hdr.o_imgsz		=	this.innerbuf.slice(i + d, i + (d += 4));									else d = optsz;	// o_imgsz		00 00 00 00								// The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment.
			if (optsz - d >= 4)									this.hdr.o_hdrsz		=	this.innerbuf.slice(i + d, i + (d += 4));									else d = optsz;	// o_hdrsz		00 04 00 00								// The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment.
			if (optsz - d >= 4)									this.hdr.o_chksum		=	this.innerbuf.slice(i + d, i + (d += 4));									else d = optsz;	// o_chksum		00 00 00 00								// The image file checksum. The algorithm for computing the checksum is incorporated into IMAGHELP.DLL. The following are checked for validation at load time: all drivers, any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process.
			if (optsz - d >= 2)									this.hdr.o_subs			=	this.innerbuf.slice(i + d, i + (d += 2));									else d = optsz;	// o_subs		00 00									// The subsystem that is required to run this image.
			if (optsz - d >= 2)									this.hdr.o_dllchrctrs	=	this.innerbuf.slice(i + d, i + (d += 2));									else d = optsz;	// o_dllchrctrs	40 01									// 
			if (optsz - d > this.hdr.isopt == 0x20b ? 8 : 4)	this.hdr.o_stackres		=	this.innerbuf.slice(i + d, i + (d += (this.hdr.isopt == 0x20b ? 8 : 4)));	else d = optsz;	// o_stackres	00 00 00 00 / 00 00 00 00 00 00 00 00	// The size of the stack to reserve. Only SizeOfStackCommit is committed; the rest is made available one page at a time until the reserve size is reached.
			if (optsz - d > this.hdr.isopt == 0x20b ? 8 : 4)	this.hdr.o_stackcomm	=	this.innerbuf.slice(i + d, i + (d += (this.hdr.isopt == 0x20b ? 8 : 4)));	else d = optsz;	// o_stackcomm	00 00 00 00 / 00 00 00 00 00 00 00 00	// The size of the stack to commit.
			if (optsz - d > this.hdr.isopt == 0x20b ? 8 : 4)	this.hdr.o_heapres		=	this.innerbuf.slice(i + d, i + (d += (this.hdr.isopt == 0x20b ? 8 : 4)));	else d = optsz;	// o_heapres	00 00 00 00 / 00 00 00 00 00 00 00 00	// The size of the local heap space to reserve. Only SizeOfHeapCommit is committed; the rest is made available one page at a time until the reserve size is reached.
			if (optsz - d > this.hdr.isopt == 0x20b ? 8 : 4)	this.hdr.o_heapcomm		=	this.innerbuf.slice(i + d, i + (d += (this.hdr.isopt == 0x20b ? 8 : 4)));	else d = optsz;	// o_heapcomm	00 00 00 00 / 00 00 00 00 00 00 00 00	// The size of the local heap space to commit.
			if (optsz - d >= 4)									this.hdr.o_ldflag		=	this.innerbuf.slice(i + d, i + (d += 4));									else d = optsz;	// o_ldflag		00 00 00 00								// Reserved, must be zero
			if (optsz - d >= 4)									this.hdr.o_rva_sz		=	this.innerbuf.slice(i + d, i + (d += 4));									else d = optsz;	// o_rva_sz		10 00 00 00								// The number of data-directory entries in the remainder of the optional header. Each describes a location and size.
			
			// +  68/88 B
			
			if (i + d == this.innerbuf.length) {
				this.err = this.isValid();
				
				return this.hdr;
			}
			
			// RVAs - 128B
			
			const rvasz = this.hdr.o_rva_sz.readUInt32LE();
			for (var idx = 0; idx < rvasz; idx++) {
				if (optsz - d >= 8) this.hdr.o_rvas.push(PEC.Hdr.RVA.init(this.innerbuf.slice(i + d, i + (d += 4)), this.innerbuf.slice(i + d, i + (d += 4)), idx + 1));
				else {
					d = optsz;
					break;
				}
			}
			
			if (this.err = this.isValid()) return this.hdr;
			
			i += d;
			
			// 224/240 B
		} else if (this.isimg && !this.isopt) {
			this.err = this.isValid();
			
			return this.hdr;
		} //OPT
		
		// SECTS -  [128B PE +]  224/240 B w/ OPT  |  20B w/o OPT
		
		const sectsnum = this.hdr.sectnum.readUInt16LE() * 40;
		
		if (i + sectsnum > this.innerbuf.length) {
			this.err = this.isValid();
			
			return this.hdr;
		}
		
		for (let secnd = 0; secnd < sectsnum; secnd += 40) {
			const flds = new Sect({
				name:		this.innerbuf.slice(i, i += 8),	// 						// An 8-byte, null-padded UTF-8 encoded string. If the string is exactly 8 characters long, there is no terminating null. For longer names, this field contains a slash (/) that is followed by an ASCII representation of a decimal number that is an offset into the string table. Executable images do not use a string table and do not support section names longer than 8 characters. Long names in object files are truncated if they are emitted to an executable file.
				virtsize :	this.innerbuf.slice(i, i += 4),	// 						// The total size of the section when loaded into memory. If this value is greater than SizeOfRawData, the section is zero-padded. This field is valid only for executable images and should be set to zero for object files.
				virtaddr:	this.innerbuf.slice(i, i += 4),	// 						// For executable images, the address of the first byte of the section relative to the image base when the section is loaded into memory. For object files, this field is the address of the first byte before relocation is applied; for simplicity, compilers should set this to zero. Otherwise, it is an arbitrary value that is subtracted from offsets during relocation.
				rawdatsz:	this.innerbuf.slice(i, i += 4),	// 						// The size of the section (for object files) or the size of the initialized data on disk (for image files). For executable images, this must be a multiple of FileAlignment from the optional header. If this is less than VirtualSize, the remainder of the section is zero-filled. Because the SizeOfRawData field is rounded but the VirtualSize field is not, it is possible for SizeOfRawData to be greater than VirtualSize as well. When a section contains only uninitialized data, this field should be zero.
				rawdatptr:	this.innerbuf.slice(i, i += 4),	// 						// The file pointer to the first page of the section within the COFF file. For executable images, this must be a multiple of FileAlignment from the optional header. For object files, the value should be aligned on a 4-byte boundary for best performance. When a section contains only uninitialized data, this field should be zero.
				relocptr:	this.innerbuf.slice(i, i += 4),	// 						// The file pointer to the beginning of relocation entries for the section. This is set to zero for executable images or if there are no relocations.
				linenoptr:	this.innerbuf.slice(i, i += 4),	// 						// The file pointer to the beginning of line-number entries for the section. This is set to zero if there are no COFF line numbers. This value should be zero for an image because COFF debugging information is deprecated.
				relocnum:	this.innerbuf.slice(i, i += 2),	// 						// The number of relocation entries for the section. This is set to zero for executable images.
				linenonum:	this.innerbuf.slice(i, i += 2),	// 						// The number of line-number entries for the section. This value should be zero for an image because COFF debugging information is deprecated.
				chrctrs:	this.innerbuf.slice(i, i += 4),	// 						// The flags that describe the characteristics of the section.
			});
			
			this.hdr.sects.push(flds);
		}
		
		this.err = this.isValid();
		
		return this.hdr;
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

class Hdr {
	
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
	o_imbase = null; o_sectalign = null;
	o_filealign = null; o_majosver = null;
	o_minosver = null; o_majimver = null;
	o_minimver = null; o_majsubsver = null;
	o_minsubsver = null; o_win32res = null;
	o_imgsz = null; o_hdrsz = null;
	o_chksum = null; o_subs = null;
	o_dllchrctrs = null; o_stackres = null;
	o_stackcomm = null; o_heapres = null;
	o_heapcomm = null; o_ldflag = null;
	o_rva_sz = null;
	/**
	 * @type RVA[]
	 */
	o_rvas = [ ];
	/**
	 * @type Sect[]
	 */
	sects = [ ];
	
	constructor(...args) {
		for (const i in this) {
			if (!this[i]) {
				this[i] = Buffer.from("00000000", "hex");
				this[i].unalloc = true;
			}
		}
		
		Object.defineProperties(this, {
			o_rvas: {
				value: [ ]
			},
			sects: {
				value: [ ]
			}
		});
		Object.defineProperty(this.o_rvas, "cleaned", {
			get() {
				return this.map(c => c.parsed).filter(c => c.addr || c.size);
			}
		});
		Object.defineProperty(this.sects, "cleaned", {
			get() {
				return this.map(c => c.parsed);
			}
		});
	} //ctor
	
	get str() {
		return this.toString();
	} //g-str
	
	toString() {
		const head = `\t\t\t\t\x1b[4;3;1mVALUES DISPLAYED IN LE ENDIANNESS.\x1b[0m ${os.EOL}`,
			pe = this.isimg ? `\t\x1b[4;1m${'-'.repeat(35)} MSDOS STUB ${'-'.repeat(35)}\x1b[0m ${os.EOL}
pe_magic              \t(2b : e_magic)       \t=\t${pad(this.e_magic.toString("binary").replace(/\u0000/g, ''), 11, ' ', true)}\t(${this.e_magic.toString("hex")})
bytes_last_page       \t(2b : e_cblp)        \t=\t${pad(this.e_cblp.readUInt16LE(), 11, ' ', true)}\t(${this.e_cblp.toString("hex")})
pages                 \t(2b : e_cp)          \t=\t${pad(this.e_cp.readUInt16LE(), 11, ' ', true)}\t(${this.e_cp.toString("hex")})
relocs                \t(2b : e_crlc)        \t=\t${pad(this.e_crlc.readUInt16LE(), 11, ' ', true)}\t(${this.e_crlc.toString("hex")})
header_size_paragraphs\t(2b : e_cparhdr)     \t=\t${pad(this.e_cparhdr.readUInt16LE(), 11, ' ', true)}\t(${this.e_cparhdr.toString("hex")})
min_extra_paragraphs  \t(2b : e_minalloc)    \t=\t${pad(this.e_minalloc.readUInt16LE(), 11, ' ', true)}\t(${this.e_minalloc.toString("hex")})
max_extra_paragraphs  \t(2b : e_maxalloc)    \t=\t${pad(this.e_maxalloc.readUInt16LE(), 11, ' ', true)}\t(${this.e_maxalloc.toString("hex")})
rel_stack_seg         \t(2b : e_ss)          \t=\t${pad(this.e_ss.readUInt16LE(), 11, ' ', true)}\t(${this.e_ss.toString("hex")})
init_stack_ptr        \t(2b : e_sp)          \t=\t${pad(this.e_sp.readUInt16LE(), 11, ' ', true)}\t(${this.e_sp.toString("hex")})
pe_checksum           \t(2b : e_csum)        \t=\t${pad(this.e_csum.readUInt16LE(), 11, ' ', true)}\t(${this.e_csum.toString("hex")})
init_instr_ptr        \t(2b : e_ip)          \t=\t${pad(this.e_ip.readUInt16LE(), 11, ' ', true)}\t(${this.e_ip.toString("hex")})
rel_cs_addr           \t(2b : e_cs)          \t=\t${pad(this.e_cs.readUInt16LE(), 11, ' ', true)}\t(${this.e_cs.toString("hex")})
reloctable_addr       \t(2b : e_lfarlc)      \t=\t${pad(this.e_lfarlc.readUInt16LE(), 11, ' ', true)}\t(${this.e_lfarlc.toString("hex")})
overlay_num           \t(2b : e_ovno)        \t=\t${pad(this.e_ovno.readUInt16LE(), 11, ' ', true)}\t(${this.e_ovno.toString("hex")})
reserve1              \t(8b : e_res)         \t=\t${pad(this.e_res.toString("hex"), 11, ' ', false)}
oem_id                \t(2b : e_oemid)       \t=\t${pad(this.e_oemid.readUInt16LE(), 11, ' ', true)}\t(${this.e_oemid.toString("hex")})
oem_info              \t(2b : e_oeminfo)     \t=\t${pad(this.e_oeminfo.readUInt16LE(), 11, ' ', true)}\t(${this.e_oeminfo.toString("hex")})
reserve2              \t(20b: e_res2)        \t=\t${pad(this.e_res2.toString("hex"), 11, ' ', false)}
pe_addr               \t(4b : e_lfanew)      \t=\t${pad(this.e_lfanew.readUInt32LE(), 11, ' ', true)}\t(${this.e_lfanew.toString("hex")})
pe_sig                \t(4b : sig)           \t=\t${pad(this.e_sig.toString("binary").replace(/\u0000/g, ''), 11, ' ', true)}\t(${this.e_sig.toString("hex")})
${os.EOL}` : "",
		coff = `\t\x1b[4;1m${pad(pad("    COFF    ", 47, '-', false), 82, '-', true)}\x1b[0m ${os.EOL}
machine               \t(2b : machine)       \t=\t${pad((Object.keys(PEC.Hdr.Machine).find(k => PEC.Hdr.Machine[k] == this.machine.readUInt16LE()) || this.machine.readUInt16LE()).toString().replace(/\u0000/g, ''), 11, ' ', true)}\t(${this.machine.toString("hex")})
sector_num            \t(2b : sectnum)       \t=\t${pad(this.sectnum.readUInt16LE(), 11, ' ', true)}\t(${this.sectnum.toString("hex")})
timestamp             \t(4b : timestamp)     \t=\t${pad(this.timestamp.readUInt32LE(), 11, ' ', true)}\t(${this.timestamp.toString("hex")})
symtable_ptr          \t(4b : symtabptr)     \t=\t${pad(this.symtabptr.readUInt32LE(), 11, ' ', true)}\t(${this.symtabptr.toString("hex")})
symbol_num            \t(4b : symbnum)       \t=\t${pad(this.symbnum.readUInt32LE(), 11, ' ', true)}\t(${this.symbnum.toString("hex")})
opt_hdr_size          \t(2b : optionalsize)  \t=\t${pad(this.optionalsize.readUInt16LE(), 11, ' ', true)}\t(${this.optionalsize.toString("hex")})
characteristics       \t(2b : chrctrs)       \t=\t${Object.keys(PEC.Hdr.Characteristics).filter(k => (this.chrctrs.readUInt16LE() & PEC.Hdr.Characteristics[k])).map(c => `${c}[${PEC.Hdr.Characteristics[c]}]`).join('|') || this.chrctrs.readUInt16LE()}\t(${this.chrctrs.toString("hex")})
${os.EOL}`,
		opt = this.isopt ? `\t\x1b[4;1m${pad(pad("    OPT     ", 47, '-', false), 82, '-', true)}\x1b[0m ${os.EOL}
opt_magic             \t(2b : o_magic)       \t=\t${pad(this.isopt == 0x10b ? "PE" : (this.isopt == 0x20b ? "PE+" : (this.isopt == 0x107 ? "ROM" : this.isopt)), 11, ' ', true)}\t\t(${this.o_magic.toString("hex")})
link_major            \t(1b : o_major)       \t=\t${pad(this.o_major.readUInt8(), 11, ' ', true)}\t(${this.o_major.toString("hex")})
link_minor            \t(1b : o_minor)       \t=\t${pad(this.o_minor.readUInt8(), 11, ' ', true)}\t(${this.o_minor.toString("hex")})
code_sz               \t(4b : o_code_sz)     \t=\t${pad(this.o_code_sz.readUInt32LE(), 11, ' ', true)}\t(${this.o_code_sz.toString("hex")})
initdat_sz            \t(4b : o_initdat_sz)  \t=\t${pad(this.o_initdat_sz.readUInt32LE(), 11, ' ', true)}\t(${this.o_initdat_sz.toString("hex")})
uninitdat_sz          \t(4b : o_uninitdat_sz)\t=\t${pad(this.o_uninitdat_sz.readUInt32LE(), 11, ' ', true)}\t(${this.o_uninitdat_sz.toString("hex")})
entry                 \t(4b : o_entry)       \t=\t${pad(this.o_entry.readUInt32LE(), 11, ' ', true)}\t(${this.o_entry.toString("hex")})
base                  \t(4b : o_base)        \t=\t${pad(this.o_base.readUInt32LE(), 11, ' ', true)}\t(${this.o_base.toString("hex")})
section_alignment     \t(4b : o_sectalign)   \t=\t${pad(this.o_sectalign.readUInt32LE(), 11, ' ', true)}\t(${this.o_sectalign.toString("hex")})
file_alignment        \t(4b : o_filealign)   \t=\t${pad(this.o_filealign.readUInt32LE(), 11, ' ', true)}\t(${this.o_filealign.toString("hex")})
major_os_ver          \t(2b : o_majosver)    \t=\t${pad(this.o_majosver.readUInt16LE(), 11, ' ', true)}\t(${this.o_majosver.toString("hex")})
minor_os_ver          \t(2b : o_minosver)    \t=\t${pad(this.o_minosver.readUInt16LE(), 11, ' ', true)}\t(${this.o_minosver.toString("hex")})
major_img_ver         \t(2b : o_majimver)    \t=\t${pad(this.o_majimver.readUInt16LE(), 11, ' ', true)}\t(${this.o_majimver.toString("hex")})
minor_img_ver         \t(2b : o_minimver)    \t=\t${pad(this.o_minimver.readUInt16LE(), 11, ' ', true)}\t(${this.o_minimver.toString("hex")})
major_subs_ver        \t(2b : o_majsubsver)  \t=\t${pad(this.o_majsubsver.readUInt16LE(), 11, ' ', true)}\t(${this.o_majsubsver.toString("hex")})
minor_subs_ver        \t(2b : o_minsubsver)  \t=\t${pad(this.o_minsubsver.readUInt16LE(), 11, ' ', true)}\t(${this.o_minsubsver.toString("hex")})
win_32_res            \t(4b : o_win32res)    \t=\t${pad(this.o_win32res.readUInt32LE(), 11, ' ', true)}\t(${this.o_win32res.toString("hex")})
image_sz              \t(4b : o_imgsz)       \t=\t${pad(this.o_imgsz.readUInt32LE(), 11, ' ', true)}\t(${this.o_imgsz.toString("hex")})
headers_sz            \t(4b : o_hdrsz)       \t=\t${pad(this.o_hdrsz.readUInt32LE(), 11, ' ', true)}\t(${this.o_hdrsz.toString("hex")})
checksum              \t(4b : o_chksum)      \t=\t${pad(this.o_chksum.readUInt32LE(), 11, ' ', true)}\t(${this.o_chksum.toString("hex")})
subsystem             \t(2b : o_subs)        \t=\t${pad((Object.keys(PEC.Hdr.Subsystem).find(k => this.o_subs.readUInt16LE() == PEC.Hdr.Subsystem[k]) || this.o_subs.readUInt16LE()).toString().replace(/\u0000/g, ''), 11, ' ', true)}\t(${this.o_subs.toString("hex")})
dll_characteristics   \t(2b : o_dllchrctrs)  \t=\t${Object.keys(PEC.Hdr.DLLCharacteristics).filter(k => (this.o_dllchrctrs.readUInt16LE() & PEC.Hdr.DLLCharacteristics[k])).map(c => `${c}[${PEC.Hdr.DLLCharacteristics[c]}]`).join('|') || this.o_dllchrctrs.readUInt16LE()}\t(${this.o_dllchrctrs.toString("hex")})
loader_flags          \t(4b : o_ldflag)      \t=\t${pad(this.o_ldflag.readUInt32LE(), 11, ' ', true)}\t(${this.o_ldflag.toString("hex")})
rvas_szs              \t(4b : o_rva_sz)      \t=\t${pad(this.o_rva_sz.readUInt32LE(), 11, ' ', true)}\t(${this.o_rva_sz.toString("hex")})
${os.EOL}` : "",
		pe_ = this.isopt != 0x20b ?`database              \t(4b : o_database)    \t=\t${pad(this.o_database.readUInt32LE(), 11, ' ', true)}\t(${this.o_database.toString("hex")})
imagebase             \t(4b : o_imbase)      \t=\t${pad(this.o_imbase.readUInt32LE(), 11, ' ', true)}\t(${this.o_imbase.toString("hex")})
stack_reserve         \t(4b : o_stackres)    \t=\t${pad(this.o_stackres.readUInt32LE(), 11, ' ', true)}\t(${this.o_stackres.toString("hex")})
stack_commit          \t(4b : o_stackcomm)   \t=\t${pad(this.o_stackcomm.readUInt32LE(), 11, ' ', true)}\t(${this.o_stackcomm.toString("hex")})
heap_reserve          \t(4b : o_heapres)     \t=\t${pad(this.o_heapres.readUInt32LE(), 11, ' ', true)}\t(${this.o_heapres.toString("hex")})
heap_commit           \t(4b : o_heapcomm)    \t=\t${pad(this.o_heapcomm.readUInt32LE(), 11, ' ', true)}\t(${this.o_heapcomm.toString("hex")})
${os.EOL}` : "",
		pe_p = this.isopt == 0x20b ? `imagebase             \t(8b : o_imbase)      \t=\t${pad(this.o_imbase.readBigUInt64LE(), 11, ' ', true)}\t(${this.o_imbase.toString("hex")})
stack_reserve         \t(8b : o_stackres)    \t=\t${pad(this.o_stackres.readBigUInt64LE(), 11, ' ', true)}\t(${this.o_stackres.toString("hex")})
stack_commit          \t(8b : o_stackcomm)   \t=\t${pad(this.o_stackcomm.readBigUInt64LE(), 11, ' ', true)}\t(${this.o_stackcomm.toString("hex")})
heap_reserve          \t(8b : o_heapres)     \t=\t${pad(this.o_heapres.readBigUInt64LE(), 11, ' ', true)}\t(${this.o_heapres.toString("hex")})
heap_commit           \t(8b : o_heapcomm)    \t=\t${pad(this.o_heapcomm.readBigUInt64LE(), 11, ' ', true)}\t(${this.o_heapcomm.toString("hex")})
${os.EOL}` : "",
		rva = this.isopt ? `\t\x1b[4;1m${pad(pad(" RVAs (" + this.o_rva_sz.readUInt32LE() + ") ", 47, '-', false), 82, '-', true)}\x1b[0m ${os.EOL}
\x1b[3mIndex|Sector:\t\tAddress\t\t\t(Size)\x1b[0m ${os.EOL}
${this.o_rvas.cleaned.map(rv => rv.self.str).join(os.EOL)}
${os.EOL}` : "",
		sects = `\t\x1b[4;1m${pad(pad("    SECT    ", 47, '-', false), 82, '-', true)}\x1b[0m ${os.EOL}
${this.sects.map(s => s.str).join(os.EOL)}
${os.EOL}`;
		
		return head + pe + coff + opt + pe_ + pe_p + rva + sects;
	} //toString
	
	[Symbol.toPrimitive](hint) {
		if (hint == "string") return this.str;
		else return this;
	}
	
	static init(...args) {
		return new PEC.Hdr(...args);
	} //init
	
} //Hdr

class RVA {
	
	addr = null;
	size = 0;
	rvaidx = 0;
	
	constructor(addr, sz, idx) {
		this.addr = addr;
		this.size = sz;
		this.rvaidx = idx;
		
		assert(addr.length == 4 && sz.length == 4, "RVA bad size");
	} //ctor
	
	static init(...args) {
		return new PEC.Hdr.RVA(...args);
	} //init
	
	get parsed() {
		return {
			addr: (this.addr || Buffer.from("00000000", "hex")).readUInt32LE(),
			size: (this.size || Buffer.from("00000000", "hex")).readUInt32LE(),
			idx: this.rvaidx,
			self: this
		};
	} //parsed
	
	get str() {
		const par = this.parsed;
		
		return `${par.idx}|${Object.keys(PEC.Hdr.Datadir).find(k => PEC.Hdr.Datadir[k] == par.idx)}:\t${pad(par.addr, 10, ' ', true)}|${this.addr.toString("hex")}\t(${par.size}|${this.size.toString("hex")})`;
	} //str
	
	[Symbol.toPrimitive](hint) {
		if (hint == "string") return this.str;
		else return this;
	}
	
	toString() {
		return this.str;
	} //toString
	
} //RVA
class Sect {
	
	name = null; virtsize = null;
	virtaddr = null; rawdatsz = null;
	rawdatptr = null; relocptr = null;
	linenoptr = null; relocnum = null;
	linenonum = null; chrctrs = null;
	
	constructor(opts) {
		Object.assign(this, opts);
	} //ctor
	
	static init(...args) {
		return new PEC.Hdr.Sect(...args);
	} //init
	
	get parsed() {
		const retobj = { };
		
		for (const k in this) {
			if (k == "name") retobj.name = this.name.toString("binary").replace(/\x00/g, '');
			else if (k.endsWith("num")) retobj[k] = this[k].readUInt16LE();
			else retobj[k] = this[k].readUInt32LE();
		}
		
		return retobj;
	} //parsed
	
	get str() {
		const par = this.parsed;
		
		return `${par.name}:
\taddr:           \t${par.virtaddr}\t\t|\tsz:     ${par.virtsize}
\tdata:           \t${par.rawdatptr}\t\t|\tinitsz: ${par.rawdatsz}
\trelocs:         \t${par.relocptr}\t\t|\tnum:    ${par.relocnum}
\tlines:          \t${par.linenoptr}\t\t|\tnum:    ${par.linenonum}
\tcharacteristics:\t${Object.keys(PEC.Hdr.SectCharacteristics).filter(c => (par.chrctrs & PEC.Hdr.SectCharacteristics[c])).map(k => `${k}[${PEC.Hdr.SectCharacteristics[k]}]`).join('|')}\t\t(${par.chrctrs})${os.EOL}`;
	} //str
	
	[Symbol.toPrimitive](hint) {
		if (hint == "string") return this.str;
		else return this;
	}
	
	toString() {
		return this.str;
	} //toString
	
} //Sect

PEC.Hdr = Hdr;
PEC.Hdr.RVA = RVA;
PEC.Hdr.Sect = Sect;
PEC.Hdr.Machine = {
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
};
PEC.Hdr.Characteristics = {
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
};
PEC.Hdr.Subsystem = {
	UNKNOWN:					0,	// An unknown subsystem
	NATIVE:						1,	// Device drivers and native Windows processes
	WINDOWS_GUI:				2,	// The Windows graphical user interface (GUI) subsystem
	WINDOWS_CUI:				3,	// The Windows character subsystem
	OS2_CUI:					5,	// The OS/2 character subsystem
	POSIX_CUI:					7,	// The Posix character subsystem
	NATIVE_WINDOWS:				8,	// Native Win9x driver
	WINDOWS_CE_GUI:				9,	// Windows CE
	EFI_APPLICATION:			10,	// An Extensible Firmware Interface (EFI) application
	EFI_BOOT_SERVICE_DRIVER:	11,	// An EFI driver with boot services
	EFI_RUNTIME_DRIVER:			12,	// An EFI driver with run-time services
	EFI_ROM:					13,	// An EFI ROM image
	XBOX:						14,	// XBOX
	WINDOWS_BOOT_APPLICATION:	16,	// Windows boot application.
};
PEC.Hdr.DLLCharacteristics = {
	RESERVED1:				0x0001,	// Reserved, must be zero.
	RESERVED2:				0x0002,	// Reserved, must be zero.
	RESERVED3:				0x0004,	// Reserved, must be zero.
	RESERVED4:				0x0008,	// Reserved, must be zero.
	HIGH_ENTROPY_VA:		0x0020,	// Image can handle a high entropy 64-bit virtual address space.
	DYNAMIC_BASE:			0x0040,	// DLL can be relocated at load time.
	FORCE_INTEGRITY:		0x0080,	// Code Integrity checks are enforced.
	NX_COMPAT:				0x0100,	// Image is NX compatible.
	NO_ISOLATION:			0x0200,	// Isolation aware, but do not isolate the image.
	NO_SEH:					0x0400,	// Does not use structured exception (SE) handling. No SE handler may be called in this image.
	NO_BIND:				0x0800,	// Do not bind the image.
	APPCONTAINER:			0x1000,	// Image must execute in an AppContainer.
	WDM_DRIVER:				0x2000,	// A WDM driver.
	GUARD_CF:				0x4000,	// Image supports Control Flow Guard.
	TERMINAL_SERVER_AWARE:	0x8000,	// Terminal Server aware.
};
PEC.Hdr.Datadir = {
	Export:			1,	// The export table
	Import:			2,	// The import table
	Resource:		3,	// The resource table
	Exception:		4,	// The exception table
	Certificate:	5,	// The attribute certificate table
	Base_Reloc:		6,	// The base relocation table
	Debug:			7,	// The debug data
	Architecture:	8,	// Reserved, must be 0
	Global:			9,	// The RVA of the value to be stored in the global pointer register. The size member of this structure must be set to zero.
	Thread_Loc:		10,	// The thread local storage (TLS) table
	Load_Cfg:		11,	// The load configuration table
	Bound_Imp:		12,	// The bound import table
	Address_Imp:	13,	// The import address table
	Delay_Imp:		14,	// The delay import descriptor address
	CLR_Hdr:		15,	// The CLR runtime header
	Reserved:		16,	// Reserved, must be 0
};
PEC.Hdr.SectCharacteristics = {
	RESERVED1:				0x00000000,	// Reserved for future use.
	RESERVED2:				0x00000001,	// Reserved for future use.
	RESERVED3:				0x00000002,	// Reserved for future use.
	RESERVED4:				0x00000004,	// Reserved for future use.
	TYPE_NO_PAD:			0x00000008,	// The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
	RESERVED5:				0x00000010,	// Reserved for future use.
	CNT_CODE:				0x00000020,	// The section contains executable code.
	CNT_INITIALIZED_DATA:	0x00000040,	// The section contains initialized data.
	CNT_UNINITIALIZED_DATA:	0x00000080,	// The section contains uninitialized data.
	LNK_OTHER:				0x00000100,	// Reserved for future use.
	LNK_INFO:				0x00000200,	// The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
	RESERVED7:				0x00000400,	// Reserved for future use.
	LNK_REMOVE:				0x00000800,	// The section will not become part of the image. This is valid only for object files.
	LNK_COMDAT:				0x00001000,	// The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
	GPREL:					0x00008000,	// The section contains data referenced through the global pointer (GP).
	MEM_PURGEABLE:			0x00020000,	// Reserved for future use.
	MEM_16BIT:				0x00020000,	// Reserved for future use.
	MEM_LOCKED:				0x00040000,	// Reserved for future use.
	MEM_PRELOAD:			0x00080000,	// Reserved for future use.
	ALIGN_1BYTES:			0x00100000,	// Align data on a 1-byte boundary. Valid only for object files.
	ALIGN_2BYTES:			0x00200000,	// Align data on a 2-byte boundary. Valid only for object files.
	ALIGN_4BYTES:			0x00300000,	// Align data on a 4-byte boundary. Valid only for object files.
	ALIGN_8BYTES:			0x00400000,	// Align data on an 8-byte boundary. Valid only for object files.
	ALIGN_16BYTES:			0x00500000,	// Align data on a 16-byte boundary. Valid only for object files.
	ALIGN_32BYTES:			0x00600000,	// Align data on a 32-byte boundary. Valid only for object files.
	ALIGN_64BYTES:			0x00700000,	// Align data on a 64-byte boundary. Valid only for object files.
	ALIGN_128BYTES:			0x00800000,	// Align data on a 128-byte boundary. Valid only for object files.
	ALIGN_256BYTES:			0x00900000,	// Align data on a 256-byte boundary. Valid only for object files.
	ALIGN_512BYTES:			0x00A00000,	// Align data on a 512-byte boundary. Valid only for object files.
	ALIGN_1024BYTES:		0x00B00000,	// Align data on a 1024-byte boundary. Valid only for object files.
	ALIGN_2048BYTES:		0x00C00000,	// Align data on a 2048-byte boundary. Valid only for object files.
	ALIGN_4096BYTES:		0x00D00000,	// Align data on a 4096-byte boundary. Valid only for object files.
	ALIGN_8192BYTES:		0x00E00000,	// Align data on an 8192-byte boundary. Valid only for object files.
	LNK_NRELOC_OVFL:		0x01000000,	// The section contains extended relocations.
	MEM_DISCARDABLE:		0x02000000,	// The section can be discarded as needed.
	MEM_NOT_CACHED:			0x04000000,	// The section cannot be cached.
	MEM_NOT_PAGED:			0x08000000,	// The section is not pageable.
	MEM_SHARED:				0x10000000,	// The section can be shared in memory.
	MEM_EXECUTE:			0x20000000,	// The section can be executed as code.
	MEM_READ:				0x40000000,	// The section can be read.
	MEM_WRITE:				0x80000000,	// The section can be written to.
};
global.PEC = exports.PEC = PEC;
global._pec = PEC.init(true);

dbg("Loaded.");
