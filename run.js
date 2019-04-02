const fs = require('fs');

let cxxPrologue = fs.readFileSync('prologue.cxx').toString();
let cxxEpilogue = fs.readFileSync('epilogue.cxx').toString();

let logData = fs.readFileSync('nestest.log').toString();
logData = logData.split("\n");
let regsRegExp = /A:(?<a>[0-9A-F]{2})\s*X:(?<x>[0-9A-F]{2})\s*Y:(?<y>[0-9A-F]{2})\s*P:(?<p>[0-9A-F]{2})\s*SP:(?<sp>[0-9A-F]{2})\s*PPU:\s*(?<ppuColumn>\d+)\s*,\s*(?<ppuLine>\d+)\s*CYC:(?<cpuClock>\d+)/;
logData = logData.filter(x => x.trim() != '').map((line) => 
{
  line = line.trim();
  let addr = parseInt (line.slice(0, 4), 16);
  let bytes = line.slice(6, 14).trim().split(' ').map(x => parseInt(x, 16));
  let unofficial = line.slice(15, 16) == '*';
  let disassembly = line.slice(16, 47).trim();
  let annotation;
  let idxofat = disassembly.indexOf('@');
  let idxofeq = disassembly.indexOf('=');
  if (idxofat >= 0 || idxofeq >= 0)
  {
    let splitBy;
    if (idxofat >= 0 && idxofeq >= 0)
      splitBy = Math.min(idxofat, idxofeq);
    else
      splitBy = Math.max(idxofat, idxofeq);

    [disassembly, annotation] = [
      disassembly.slice(0, splitBy).trim(), 
      disassembly.slice(splitBy).trim()
    ];
  }
  let [mnemonic] = disassembly.split(' ');
  let [clock, regs] = [{}, {}];
  for(let [key, value] of Object.entries(regsRegExp.exec(line.slice(48)).groups))
  {
    let isTiming = ['ppuColumn', 'ppuLine', 'cpuClock'].includes(key);
    if (isTiming)
      clock[key] = parseInt(value, 10);
    else
      regs[key] = parseInt(value, 16);
  }
  clock.ppuClock = clock.ppuLine * 341 + clock.ppuColumn;
  return {addr, bytes, text: {line, disassembly, mnemonic, annotation}, regs, clock, unofficial};
});

fs.writeFileSync('nestest.log.json', JSON.stringify(logData, null, 4));

let hex = (value, bits) => `0x${value.toString(16).toUpperCase().padStart(bits/4, '0')}`;
let pad = (value, chrs, wot) => value.toString().padStart(chrs, wot);

let cxxSource = ['LogLine logNestest [] =', '{'];
for(let line of logData)
{  
  cxxSource.push(
    `\t`+
    `{${hex(line.addr, 16)}, `+
    `{`+
      `${hex(line.regs.a , 8)}, `+
      `${hex(line.regs.x , 8)}, `+
      `${hex(line.regs.y , 8)}, `+
      `${hex(line.regs.p , 8)}, `+
      `${hex(line.regs.sp, 8)}}, `+
    `${line.bytes.length}, `+
    `{`+
      `${hex(line.bytes[0] || 0, 8)}, `+
      `${hex(line.bytes[1] || 0, 8)}, `+
      `${hex(line.bytes[2] || 0, 8)}}, `+
    `${pad(line.clock.cpuClock , 6, ' ')}, `+
    `${pad(line.clock.ppuClock , 6, ' ')}, `+
    `${pad(line.clock.ppuColumn, 4, ' ')}, `+ 
    `${pad(line.clock.ppuLine  , 4, ' ')}, `+
    `${line.unofficial ? 'true' : 'false'}, `+
    `"${line.text.disassembly}", `+
    `${line.text.annotation ? ('"' + line.text.annotation + '"') : 'nullptr'}`+    
    `},`);
}
cxxSource.push('};');

let romData = fs.readFileSync('nestest.nes');

romData = [...romData]
header = romData.splice(0, 16)
signature = header.slice(0, 4)

console.assert(JSON.stringify(signature) == JSON.stringify([78,69,83,26]));

prgRomSize = 1024*16*header[4]
chrRomSize = 1024*8*header[5]

console.assert(prgRomSize + chrRomSize == romData.length)
prgRom = romData.splice(0, prgRomSize)
chrRom = romData.splice(0, chrRomSize)

cxxSource.push(`const byte prgrom [${prgRomSize}] =`)
cxxSource.push(`{`)
while (prgRom.length)
{
  line = prgRom.splice(0, 16)
  line = ('\t' + line.map(x => `${hex(x, 8)},`).join (' '))
  cxxSource.push(line)
}
cxxSource.push(`};`)


cxxSource.push(`const byte chrrom [${chrRomSize}] =`)
cxxSource.push(`{`)
while (chrRom.length)
{
  line = chrRom.splice(0, 16)
  line = ('\t' + line.map(x => `${hex(x, 8)},`).join (' '))
  cxxSource.push(line)
}
cxxSource.push(`};`)

cxxSource.push(`const byte header [16] =`)
cxxSource.push(`{`)
while (header.length)
{
  line = header.splice(0, 16)
  line = ('\t' + line.map(x => `${hex(x, 8)},`).join (' '))
  cxxSource.push(line)
}
cxxSource.push(`};`)


cxxSource = [cxxPrologue, cxxSource.join('\n'), cxxEpilogue].join('\n');

fs.writeFileSync('nestest.cxx', cxxSource);

