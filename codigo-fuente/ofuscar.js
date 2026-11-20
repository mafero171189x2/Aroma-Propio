// Genera publicar/index.html a partir de ../index.html con el JavaScript principal ofuscado.
// Uso:  node herramientas/ofuscar.js
const fs = require('fs'), path = require('path');
const JSO = require('javascript-obfuscator');
const raiz = path.join(__dirname, '..');
const src = fs.readFileSync(path.join(raiz, 'index.html'), 'utf8');
const re = /<script>([\s\S]*?)<\/script>/g;
let mejor = null, m;
while ((m = re.exec(src))) if (!mejor || m[1].length > mejor[1].length) mejor = m;
if (!mejor || mejor[1].length < 5000) throw new Error('No encontré el script principal');
const out = JSO.obfuscate(mejor[1], {
  compact: true, simplify: true,
  stringArray: true, stringArrayThreshold: 0.8, stringArrayEncoding: ['base64'],
  stringArrayWrappersCount: 1, rotateStringArray: true, shuffleStringArray: true,
  identifierNamesGenerator: 'hexadecimal', renameGlobals: false,
  controlFlowFlattening: false, deadCodeInjection: false,
  selfDefending: false, debugProtection: false, disableConsoleOutput: false,
  numbersToExpressions: true, splitStrings: false, transformObjectKeys: false,
  unicodeEscapeSequence: false, target: 'browser'
}).getObfuscatedCode();
const html = src.slice(0, mejor.index) + '<script>' + out + '</script>' + src.slice(mejor.index + mejor[0].length);
const dir = path.join(raiz, 'publicar');
fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(path.join(dir, 'index.html'), html);
console.log('OK', (src.length / 1024).toFixed(0) + ' KB ->', (html.length / 1024).toFixed(0) + ' KB');
