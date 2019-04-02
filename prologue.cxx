#include <cstdint>
#include <cstddef>

using word = std::uint16_t;
using byte = std::uint8_t;
using dword = std::uint32_t;
using qword = std::uint64_t;

struct LogLine
{  
  word addr;
  struct { byte a, x, y, p, sp; } regs;

  byte nbytes;
  byte opbytes[3u];    

  qword column;
  qword scanline;
  qword cpuclock;
  qword ppuclock;

  bool unofficial;
  const char* instruction;
  const char* disassembly;
};
