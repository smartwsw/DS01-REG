// 一致性测试：从 index.html 中抽出实际运行的两段脚本，逐项对比 Python 基准结果
const fs = require('fs');
const zlib = require('zlib');
const vm = require('vm');

const html = fs.readFileSync(__dirname + '/index.html', 'utf8');

function grab(id) {
  const m = new RegExp('<script id="' + id + '">([\\s\\S]*?)<\\/script>').exec(html);
  if (!m) throw new Error('找不到脚本: ' + id);
  return m[1];
}

vm.runInThisContext(grab('cryptojs'), { filename: 'crypto-js.min.js' });
vm.runInThisContext(grab('app'), { filename: 'app.js' });

const t = globalThis.__tool;
const EXPECT = {
  lic: '16CC-6630-75C5-AB65-9C08-C3C1-E19F-9367',
  info: '000806ECD2928D43'
};

let failed = 0;
function check(name, actual, expected) {
  const ok = actual === expected;
  if (!ok) failed++;
  console.log((ok ? 'PASS ' : 'FAIL ') + name + (ok ? '' : '\n  got: ' + actual + '\n  exp: ' + expected));
}

// 1. 直接输入序列号
check('serial input', t.genKeyFromHex('000806ECD2928D43').lic, EXPECT.lic);
check('serial input (with dashes)', t.genKeyFromHex('00-08-06-EC-D2-92-8D-43').lic, EXPECT.lic);

// 1.1 后半段为 0 的识别
check('zero tail detect', String(t.isZeroTail('000806EC00000000')), 'true');
check('zero tail detect (dashes)', String(t.isZeroTail('00-08-06-EC-00-00-00-00')), 'true');
check('zero tail detect (normal serial)', String(t.isZeroTail('000806ECD2928D43')), 'false');
check('zero tail key info', t.genKeyFromHex('000806EC00000000').info, '000806EC00000000');

// 2. 从 .lic 文件读取
const licBuf = fs.readFileSync(__dirname + '/../DS01.lic');
const fromFile = t.genKeyFromLic(licBuf.buffer.slice(licBuf.byteOffset, licBuf.byteOffset + licBuf.byteLength));
check('lic file key', fromFile.lic, EXPECT.lic);
check('lic file serial', fromFile.info, EXPECT.info);

// ---------- 构造 zip（deflate + store + 垃圾条目） ----------
function crc32(buf) {
  let c, crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    c = (crc ^ buf[i]) & 0xFF;
    for (let k = 0; k < 8; k++) c = c & 1 ? (c >>> 1) ^ 0xEDB88320 : c >>> 1;
    crc = (crc >>> 8) ^ c;
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function makeZip(files) {
  const parts = [];
  const central = [];
  let offset = 0;
  for (const f of files) {
    const name = Buffer.from(f.name, 'utf8');
    const data = Buffer.from(f.data);
    const comp = f.store ? data : zlib.deflateRawSync(data);
    const method = f.store ? 0 : 8;
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(comp.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    parts.push(local, name, comp);

    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(0x0800, 8);
    cd.writeUInt16LE(method, 10);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(comp.length, 20);
    cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(name.length, 28);
    cd.writeUInt32LE(offset, 42);
    central.push(cd, name);
    offset += local.length + name.length + comp.length;
  }
  const cdBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, cdBuf, eocd]);
}

// 3. ZIP 内多个 .lic
(async () => {
  const zip = makeZip([
    { name: 'sub/DS01.lic', data: licBuf },
    { name: 'stored/DS01.lic', data: licBuf, store: true },
    { name: '__MACOSX/._DS01.lic', data: Buffer.from('resource fork junk') },
    { name: 'readme.txt', data: Buffer.from('hello') }
  ]);
  const items = await t.readZipLicenses(zip.buffer.slice(zip.byteOffset, zip.byteOffset + zip.byteLength));
  check('zip entry count', String(items.length), '2');
  items.forEach((it, i) => {
    check('zip[' + i + '] name', it.name, ['sub/DS01.lic', 'stored/DS01.lic'][i]);
    check('zip[' + i + '] key', t.genKeyFromLic(it.buffer).lic, EXPECT.lic);
  });
  console.log(failed ? '\nFAILED: ' + failed : '\nALL PASS');
  process.exit(failed ? 1 : 0);
})();
