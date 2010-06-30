// set classpath
var addURL = java.net.URLClassLoader.__javaObject__.getDeclaredMethod("addURL", [java.net.URL]);
addURL.accessible = true;
for each (var file in new java.io.File("lib").listFiles().concat(new java.io.File("target/classes"))) {
    addURL.invoke(java.lang.ClassLoader.getSystemClassLoader(), [file.toURL()]);
}

print("Available Cards:");
var scterms = javax.smartcardio.TerminalFactory.getDefault().terminals().list();
var terms = [];
for (var i = 0; i < scterms.size(); i++) {
    var term = scterms.get(i);
    terms.push(term);
    print("  " + i + ":" + (term.isCardPresent() ? "x:" : " :") + term.getName());
}
function gp(id) {
    return com.joelhockey.smartcard.GP.newSCIO(terms[id].connect("*"));
}
function hex(b) { return com.joelhockey.codec.Hex.b2s(b); }

var ISK = "404142434445464748494a4b4c4d4e4f";
print("Variables:\n  var terms = javax.smartcardio.TerminalFactory.getDefault().terminals.list()");
print("  var ISK = '404142434445464748494a4b4c4d4e4f'");
print("Function:\n  gp(id)\n  hex(buf)");
print("GP methods':\n  getData(p1p2)\n  scp02(keyVersion(0), enc?, mac?, isk)\n  getStatus()\n  getKeyInfo()\n");