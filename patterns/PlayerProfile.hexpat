import std.sys;
import gzip; // Creates a top level GZip pattern at address 0x0

struct ExtraFieldCT {
    char CT[2];
    std::assert(CT == "CT", "CT == \"CT\""); // CT likely means Croteam.
    u16 field_data_length;
    std::assert(field_data_length == 8, "field_data_length == 8");
    u32 compressed_size;
    std::assert(compressed_size == sizeof(gzip.data), "compressed_size == sizeof(gzip.data)");
    u32 decompressed_size;
    std::assert(decompressed_size == gzip.isize, "decompressed_size == gzip.isize");
};

std::assert(gzip.flags.FEXTRA, "gzip.flags.FEXTRA");
ExtraFieldCT extra_field_ct @ addressof(gzip.extraField);
