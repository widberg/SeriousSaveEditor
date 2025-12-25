import std.core;
import std.sys;

struct PascalString {
    u32 size;
    char data[size];
};

enum FileType_ : u64 {
    INFSTRM1 = 0x494E465354524D31,
    WRKSTRM1 = 0x57524B5354524D31,
    SIGSTRM1 = 0x5349475354524D31,
};

using FileType = be FileType_;

enum FileSubType : u32 {
    SIG2 = 0x53494732, // 2GIS in little endian as ASCII
};

enum HashMethod : u32 {
    CRC32 = 1, // IEEE 802.3 Cyclic Redundancy Check
    SHA1 = 4,
    TIGER = 5,
    SHA256 = 6,
};

fn get_hash_size(HashMethod hash_method) {
    match (hash_method) {
        (HashMethod::CRC32): return 4;
        (_): return -1;
    }
};

struct SignatureBlock {
    FileType file_type;
    if (std::core::is_valid_enum(file_type)) {
        FileSubType file_sub_type;
        std::assert(std::core::is_valid_enum(file_sub_type), "std::core::is_valid_enum(file_sub_type)");
    } else {
        $ = addressof(this);
    }
    u32 version;
    u32 block_size; // clamped to [0, 0x80000] when read (Talos)
    HashMethod hash_method;
    if (std::core::is_valid_enum(file_type)) {
        s32 hash_size; // clamped to [0, 0x1000] when read
        std::assert(hash_size == 0, "hash_size == 0");
    } else {
        s32 hash_size = get_hash_size(hash_method);
    }
    u8 hash[hash_size];
    if (std::core::is_valid_enum(file_type)) {
        u32 salt; // rng based on system time
        if (version >= 2) {
            u32 has_memory_stream_name;
        }
        if (version >= 3) {
            u32 has_userid;
        }
        if (version >= 5) {
            PascalString signature_related_string;
        }
        u32 signature_size; // clamped to [0, 0x1000] (Talos)
        if (version >= 3 && signature_size > 0) {
            PascalString sign_key_name;
            u8 signature[signature_size]; // See comments at the end of this file
        }
    }
};

SignatureBlock signature_block @ 0x0;

// Talos
// SIGSTRM1 SIG2

// if version < 2 then has_memory_stream_name = 0 and the field is not read
// if version < 3 then has_userid = 0 and the field is not read
// if version < 3 or signature_size <= 0 then no signature check

// updates are done as bytes with pointers to variables and sizes. not with actual values. so pay attention to endianness.
// The hashes are then signed with rsa to yield a 64 byte signature
// code to verify hash looks like this. data is the actual data as described below not a hash
// public_key.verify(
//     signature,
//     data,
//     padding.PSS(
//         mgf=padding.MGF1(hashes.SHA1()),
//         salt_length=11
//     ),
//     hashes.SHA1()
// )

// Don't include the length prefix when hashing pascal strings

// memory stream name
// <memory stream:PlayerProfile_unrestricted.dat> or <memory stream:PlayerProfile.dat>

// userid
// steamID64 (Hex) lowercase as string: 1100001075d8dea
// idk about other platforms

// neither memory_stream_name or userid are stored in the file. must be gathered elsewhere

// For signature in signature block
// start new hasher
// update with signature_block.version
// update with signature_block.block_size
// update with signature_block.hash_method
// update with signature_block.skip_hash_check
// update with signature_block.salt
// update with has_memory_stream_name
// if memory_stream_name updated with memory_stream_name
// update with has_userid
// if userid update with userid
// update with some_string
// update with signature_block.hash_size
// if signature_block.hash_size > 0 update with signature_block.sign_key_name
// finish

// For mid-file signatures after max 0x10000 sized blocks
// start new hasher
// update hash with signature_block.salt ^ (blocks_read + 0xB1B);
// if memory_stream_name updated with memory_stream_name
// if userid update with userid
// update with block bytes
// finish

// the tail is the same as the mid but only the remaining data since the last mid
// last block can be less than 0x10000 size
// include the metaend bit

// Serious Sam 2
// No magic

// CRC-32 on the bytes as is
// First hash before data is for the bytes of the header from the beginning up to the hash
// Each block size group of bytes has a hash after it
// Last block only hashes whats available. No extra padding.

// Overall very similar to Talos, but no signature so it's simpler
// Not sure if I should split this off into it's own format
