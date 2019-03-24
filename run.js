const fs = require('fs');

let cxxPrologue = fs.readFileSync('prologue.cxx').toString();
let cxxEpilogue = fs.readFileSync('epilogue.cxx').toString();

let logData = fs.readFileSync('nestest.log').toString();
logData = logData.split("\n");
let regsRegExp = /A:(?<A>[0-9A-F]{2})\s*X:(?<X>[0-9A-F]{2})\s*Y:(?<Y>[0-9A-F]{2})\s*P:(?<P>[0-9A-F]{2})\s*SP:(?<SP>[0-9A-F]{2})\s*PPU:\s*(?<ppuColumn>\d+)\s*,\s*(?<ppuLine>\d+)\s*CYC:(?<cpuClock>\d+)/;
logData = logData.filter(x => x.trim() != '').map((line) => 
{
  line = line.trim();
  let addr = parseInt (line.slice(0, 4), 16);
  let bytes = line.slice(6, 14).trim().split(' ').map(x => parseInt(x, 16));
  let [disassembly, annotation] = line.slice(15, 47).split('@').map(x => x.trim());
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
  return {addr, bytes, text: {line, disassembly, mnemonic, annotation}, regs, clock};
});

fs.writeFileSync('nestest.log.json', JSON.stringify(logData, null, 4));

//console.log(logData.slice(0, 10));
//debugger;