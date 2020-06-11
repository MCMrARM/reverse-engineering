// General file layout:
// Actual data (header.fileLengthMinusHeaders bytes)
// Section __TEXT header
// Section __DATA header
// File header


// Main header, located at the last 0x20 bytes of the firmware.
struct rtkit_fw_header {
  char magic[4]; // 'fwsg'
  uint32_t unknown; // seems to always be 1, version? not checked anyways
  uint32_t fileLengthMinusHeaders:
  uint32_t sectionHeaderCount;
  char reserved[0x10];
};

// Section headers, located just before the main header
struct rtkit_fw_section {
  uint64_t memStart;
  uint32_t fileStart;
  uint32_t length;
  uint8_t filler[8];
  char name[8];
};
