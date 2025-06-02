import std.sys;

struct PascalString {
    u32 size;
    char data[size];
};

enum HashMethod : u32 {
    SHA1 = 4,
    TIGER = 5,
    SHA256 = 6,
};

struct SignatureBlock {
    char SIGSTRM1[8]; // Or INFSTRM1 or WRKSTRM1
    std::assert(SIGSTRM1 == "SIGSTRM1", "SIGSTRM1 == \"SIGSTRM1\"");
    char _2GIS[4];
    std::assert(_2GIS == "2GIS", "_2GIS == \"2GIS\"");
    u32 version;
    std::assert(version == 5, "version == 5");
    u32 block_size; // clamped to [0, 0x80000] when read
    std::assert(block_size == 0x10000, "block_size == 0x10000");
    HashMethod hash_method;
    s32 hash_size; // clamped to [0, 0x1000] when read
    std::assert(hash_size == 0, "hash_size == 0");
    u8 hash[hash_size];
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
    u32 signature_size; // clamped to [0, 0x1000]
    if (version >= 3 && signature_size > 0) {
        PascalString sign_key_name;
        u8 signature[signature_size]; // See comments at the end of this file
    }
};

SignatureBlock signature_block @ 0x0;

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
