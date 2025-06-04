import std.sys;

struct PascalString {
    u32 size;
    char data[size];
};

struct MetadataBlock {
    char CTSE[4]; // Looks like SeriousE is another type of file the game expects to see. CTSE likely means Croteam Serious Engine.
    std::assert(CTSE == "CTSE", "CTSE == \"CTSE\"");
    char META[4];
    std::assert(META == "META", "META == \"META\"");
    u32 endianness_cookie; // 0x1234ABCD
    u32 version;
    if (version >= 2) {
        PascalString version_string;
    }
};

struct MSGSBlock { // Messages
    char block_name[4];
    std::assert(block_name == "MSGS", "block_name == \"MSGS\"");
    u32 size;
    std::assert(size == 0, "size == 0");
};

struct INFOBlock {  // Info
    char block_name[4];
    std::assert(block_name == "INFO", "block_name == \"INFO\"");
    u32 EditDataStripped;
    u32 ResourceFiles;
    u32 Idents;
    u32 Types;
    u32 Objects;
};

struct RFILBlock { // ResourceFiles
    char block_name[4];
    std::assert(block_name == "RFIL", "block_name == \"RFIL\"");
    u32 size;
    std::assert(size == 0, "size == 0");
    std::assert(size == parent.info.ResourceFiles, "size == parent.info.ResourceFiles");
};

struct IDNTBlockEntry {
    u32 Ident;
    PascalString Name;
};

struct IDNTBlock { // Idents
    char block_name[4];
    std::assert(block_name == "IDNT", "block_name == \"IDNT\"");
    u32 size;
    std::assert(size == parent.info.Idents, "size == parent.info.Idents");
    IDNTBlockEntry idents[size];
};

struct EXTYBlockEntry {
    u32 Type;
    PascalString Name;
};

struct EXTYBlock { // ExternalTypes
    char block_name[4];
    std::assert(block_name == "EXTY", "block_name == \"EXTY\"");
    u32 size;
    std::assert(size <= parent.info.Types, "size <= parent.info.Types");
    EXTYBlockEntry types[size];
};

enum TypeKind : u32 {
    Primitive = 0,
    Enum = 1,
    Pointer = 2,
    Array = 4,
    Struct = 5,
    I = 6,
    StaticStackArray = 7,
    DynamicContainer = 8,
    E = 11,
    F = 12,
    TypeDef = 13,
    D = 14,
};

struct TypeKindStructMember {
    if (parent.parent.parent.parent.metadata_block.version >= 11) {
        u32 ID;
    } else {
        if (parent.parent.parent.parent.metadata_block.version < 5) {
            u32 ID;
        }
        PascalString Name;
    }
    u32 Type;
};

struct TypeKindStruct {
    s32 Base;
    char STMB[4]; // StructMembers
    std::assert(STMB == "STMB", "STMB == \"STMB\"");
    u32 number_of_members;
    TypeKindStructMember members[number_of_members];
};

struct TypeKindTypeDef {
    u32 For;
};

struct TypeKindPrimitive {
    u32 Bytes;
    u32 LBE;
};

struct TypeKindEnum {
    u32 Bytes;
};

struct TypeKindPointer {
    u32 To; // Type of Object pointed to. The value read from the file for a pointer is either -1 or the ID of another object in the file.
};

struct TypeKindStaticStackArray {
    u32 Of;
};

struct TypeKindDynamicContainer {
    u32 Of;
};

struct TypeKindArray {
    u32 Of;
    char ADIM[4]; // Dimensions
    std::assert(ADIM == "ADIM", "ADIM == \"ADIM\"");
    u32 rows;
    std::assert(rows == 1, "rows == 1");
    u32 cols;
};

struct DTTY {
    char dtty[4];
    u32 DataType;
    PascalString Name;
    u32 Format;
    TypeKind Type;
    match (Type) {
        (TypeKind::Struct): TypeKindStruct struct_;
        (TypeKind::TypeDef): TypeKindTypeDef primitive2;
        (TypeKind::Primitive): TypeKindPrimitive primitive;
        (TypeKind::Enum): TypeKindEnum enum_;
        (TypeKind::Pointer): TypeKindPointer pointer;
        (TypeKind::StaticStackArray): TypeKindStaticStackArray static_stack_array;
        (TypeKind::DynamicContainer): TypeKindDynamicContainer dynamic_container;
        (TypeKind::Array): TypeKindArray array;
        (_): u8 error[-1];
    }
};

struct INTYBlock { // Internal Types
    char block_name[4];
    std::assert(block_name == "INTY", "block_name == \"INTY\"");
    u32 size;
    std::assert(size + parent.exty.size == parent.info.Types, "size + parent.exty.size == parent.info.Types");
    DTTY data_types[size];
};

struct EXOBBlock { // ExternalObjects
    char block_name[4];
    std::assert(block_name == "EXOB", "block_name == \"EXOB\"");
    u32 size;
    std::assert(size == 0, "size == 0");
    std::assert(size <= parent.info.Objects, "size <= parent.info.Objects");
};

struct ObjectTypeEntry {
    u32 Object;
    u32 Type;
};

struct OBTYBlock { // InternalObjectTypes
    char block_name[4];
    std::assert(block_name == "OBTY", "block_name == \"OBTY\"");
    u32 size;
    ObjectTypeEntry types[size];
};

struct EDTYBlock { // EditObjectTypes
    char block_name[4];
    std::assert(block_name == "EDTY", "block_name == \"EDTY\"");
    u32 size;
    std::assert(size == 0, "size == 0");
    ObjectTypeEntry types[size];
};

struct OBJSBlockEntryARRY { // Array
    u8 error[-1];
};

struct OBJSBlockEntrySTAR { // StaticArray
    u8 error[-1];
};

struct OBJSBlockEntrySSAR { // StaticStackArray
    u32 size;
    PascalString strings[size];
};

struct OBJSBlockEntryDCON { // Container
    u8 error[-1];
};

struct OBJSBlockEntry {
    char type[4];
    match (type) {
        ("ARRY"): OBJSBlockEntryARRY arry;
        ("STAR"): OBJSBlockEntrySTAR star;
        ("SSAR"): OBJSBlockEntrySSAR ssar;
        ("DCON"): OBJSBlockEntryDCON dcon;
        (_): u8 error[-1];
    }
};

struct OBJSBlock { // InternalObjects
    char block_name[4];
    std::assert(block_name == "OBJS", "block_name == \"OBJS\"");
    u32 size;
    std::assert(size == parent.obty.size, "size == parent.obty.size");
    std::assert(size + parent.exob.size == parent.info.Objects, "size + parent.exob.size == parent.info.Objects");
    u8 skip[-1]; // Parsing this is too hard in an ImHex pattern, change the size of this to work
};

struct EDOBBlock { // EditObjects
    char block_name[4];
    std::assert(block_name == "EDOB", "block_name == \"EDOB\"");
    u32 size;
    std::assert(size == parent.edty.size, "size == parent.edty.size");
    std::assert(size == 0, "size == 0");
};

struct MetaendBlock {
    char META[4];
    std::assert(META == "META", "META == \"META\"");
    char END_[4];
    std::assert(END_ == "END ", "END_ == \"END \"");
};

struct TheTalosPrincipleSaveGameData {
    MetadataBlock metadata_block;
    MSGSBlock msgs;
    INFOBlock info;
    RFILBlock rfil;
    IDNTBlock idnt;
    EXTYBlock exty;
    INTYBlock inty;
    EXOBBlock exob;
    OBTYBlock obty;
    EDTYBlock edty;
    OBJSBlock objs;
    EDOBBlock edob;
    MetaendBlock metaend_block;
};

TheTalosPrincipleSaveGameData save_game_data @ 0x0;
