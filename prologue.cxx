#include <cstdint>
#include <cstddef>

using word = std::uint16_t;
using byte = std::uint8_t;
using dword = std::uint32_t;
using qword = std::uint64_t;

struct LogLine
{  
  byte opbytes[3u];    
  const char* symbolic;
  struct 
  { 
    word pc;
    byte a, x, y, p, sp;
  } regs;

  qword ppuclock;
  qword scanline;
  qword cpuclock;
};


LogLine logNestest [] =
{