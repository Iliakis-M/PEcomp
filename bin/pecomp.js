#!/usr/bin/env node

const PEC = require("../pecomp"),
	os = require("os");

if (process.argv.length == 3) {
	PEC.read(process.argv[2]).then(p => {
		console.info(p.hdr.str);
		console.warn(p.err);
	});
} else console.log(`Usage:${os.EOL}\t${process.argv[1]} file<Path>\t- Read Header of PE file.`);
