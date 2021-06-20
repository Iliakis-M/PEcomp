const { PEC } = require("../");

PEC.read("src/HxD.exe").then(p => {
	console.info(p.hdr.str);
	console.error(p.err);
});
