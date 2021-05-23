#!/usr/bin/env node

const { PEC } = require("../pecomp"),
	os = require("os");

if (os.endianness() != "LE") console.warn("SYSTEM NOT RUNNING ON 'LE' ENDIANESS.");

if (process.argv.length == 3) {
	PEC.read(process.argv[2]).then(p => {
		console.log(p.hdr.str);
		console.error(p.err);
	});
} else console.info(`Usage:${os.EOL}\t${process.argv[1]} file<Path>\t- Read Header of PE file.`);
