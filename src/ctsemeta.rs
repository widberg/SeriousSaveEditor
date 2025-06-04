#![allow(non_snake_case)] // Keep the original names where possible

use std::collections::HashMap;
use std::io::{Seek, Write};

use binrw::{BinRead, BinResult, BinWrite, Endian, args, binrw, writer};
use log::warn;
use serde::{Deserialize, Serialize};

use crate::helpers::{
    parse_pascal_string,
    parse_pascal_vec,
    write_pascal_string,
    write_pascal_vec,
};

// binrw 0.15.0 doesn't do map and write_with in the right order due to a
// bug so we do this
#[writer(writer, endian)]
fn write_option_pascal_string(value: &Option<String>) -> BinResult<()> {
    let value = value.as_ref().map(String::as_str).unwrap_or_default();
    write_pascal_string(value, writer, endian, ())
}

#[binrw]
#[derive(Serialize, Deserialize)]
#[brw(magic = b"CTSEMETA")]
pub struct Metadata {
    #[brw(magic = 0x1234ABCDu32)] // Endianness cookie
    pub version: u32,
    #[br(if(version >= 2), parse_with = parse_pascal_string, map = |x: String| Some(x))]
    #[bw(if(*version >= 2), write_with = write_option_pascal_string)]
    pub version_string: Option<String>,
}

#[derive(BinRead, BinWrite, Serialize, Deserialize)]
#[brw(magic = b"MSGS")]
pub struct Messages {
    #[br(parse_with = parse_pascal_vec, assert(messages.is_empty()))]
    #[bw(write_with = write_pascal_vec)]
    pub messages: Vec<()>,
}

#[derive(BinRead, BinWrite, Serialize, Deserialize)]
#[brw(magic = b"INFO")]
pub struct Info {
    pub EditDataStripped: u32,
    pub ResourceFiles: u32,
    pub Idents: u32,
    pub Types: u32,
    pub Objects: u32,
}

impl Info {
    fn new(
        resource_file: &ResourceFiles,
        idents: &Idents,
        external_types: &ExternalTypes,
        internal_types: &InternalTypes,
        external_objects: &ExternalObjects,
        internal_objects: &InternalObjects,
    ) -> Self {
        Self {
            EditDataStripped: 1,
            ResourceFiles: resource_file.resource_files.len() as u32,
            Idents: idents.idents.len() as u32,
            Types: (external_types.types.len() + internal_types.types.len()) as u32,
            Objects: (external_objects.external_objects.len()
                + internal_objects.internal_object.len()) as u32,
        }
    }
}

#[derive(BinRead, BinWrite, Serialize, Deserialize)]
#[brw(magic = b"RFIL")]
pub struct ResourceFiles {
    #[br(parse_with = parse_pascal_vec, assert(resource_files.is_empty()))]
    #[bw(write_with = write_pascal_vec)]
    pub resource_files: Vec<()>,
}

#[derive(BinRead, BinWrite, Serialize, Deserialize)]
pub struct Ident {
    pub Ident: u32,
    #[br(parse_with = parse_pascal_string)]
    #[bw(write_with = write_pascal_string)]
    pub Name: String,
}

#[derive(BinRead, BinWrite, Serialize, Deserialize)]
#[brw(magic = b"IDNT")]
pub struct Idents {
    #[br(parse_with = parse_pascal_vec)]
    #[bw(write_with = write_pascal_vec)]
    pub idents: Vec<Ident>,
}

#[derive(BinRead, BinWrite, Serialize, Deserialize)]
pub struct ExternalType {
    pub Type: u32,
    #[br(parse_with = parse_pascal_string)]
    #[bw(write_with = write_pascal_string)]
    pub Name: String,
}

#[derive(BinRead, BinWrite, Serialize, Deserialize)]
#[brw(magic = b"EXTY")]
pub struct ExternalTypes {
    #[br(parse_with = parse_pascal_vec)]
    #[bw(write_with = write_pascal_vec)]
    pub types: Vec<ExternalType>,
}

#[derive(BinRead, BinWrite, Serialize, Deserialize)]
pub struct DataTypeTypeStructMember {
    pub ID: u32,
    pub Type: u32,
}

#[binrw]
#[derive(Serialize, Deserialize)]
pub enum DataTypeType {
    #[brw(magic = 0u32)]
    Primitive { Bytes: u32, LBE: u32 },
    #[brw(magic = 1u32)]
    Enum { Bytes: u32 },
    #[brw(magic = 2u32)]
    Pointer { To: u32 },
    #[brw(magic = 4u32)]
    Array {
        Of: u32,
        #[brw(magic = b"ADIM")]
        #[br(assert(rows == 1))]
        rows: u32,
        cols: u32,
    },
    #[brw(magic = 5u32)]
    Struct {
        Base: i32,
        #[brw(magic = b"STMB")]
        #[br(parse_with = parse_pascal_vec)]
        #[bw(write_with = write_pascal_vec)]
        members: Vec<DataTypeTypeStructMember>,
    },
    #[brw(magic = 7u32)]
    StaticStackArray { Of: u32 },
    #[brw(magic = 8u32)]
    DynamicContainer { Of: u32 },
    #[brw(magic = 13u32)]
    TypeDef { For: u32 },
}

#[derive(BinRead, BinWrite, Serialize, Deserialize)]
#[brw(magic = b"DTTY")]
pub struct DataType {
    pub DataType: u32,
    #[br(parse_with = parse_pascal_string)]
    #[bw(write_with = write_pascal_string)]
    pub Name: String,
    pub Format: u32,
    pub Type: DataTypeType,
}

#[derive(BinRead, BinWrite, Serialize, Deserialize)]
#[brw(magic = b"INTY")]
pub struct InternalTypes {
    #[br(parse_with = parse_pascal_vec)]
    #[bw(write_with = write_pascal_vec)]
    pub types: Vec<DataType>,
}

#[derive(BinRead, BinWrite, Serialize, Deserialize)]
#[brw(magic = b"EXOB")]
pub struct ExternalObjects {
    #[br(parse_with = parse_pascal_vec, assert(external_objects.is_empty()))]
    #[bw(write_with = write_pascal_vec)]
    pub external_objects: Vec<()>,
}

#[derive(BinRead, BinWrite, Serialize, Deserialize)]
pub struct InternalObjectType {
    pub Object: u32,
    pub Type: u32,
}

#[derive(BinRead, BinWrite, Serialize, Deserialize)]
#[brw(magic = b"OBTY")]
pub struct InternalObjectTypes {
    #[br(parse_with = parse_pascal_vec)]
    #[bw(write_with = write_pascal_vec)]
    pub types: Vec<InternalObjectType>,
}

#[derive(BinRead, BinWrite, Serialize, Deserialize)]
#[brw(magic = b"EDTY")]
pub struct EditObjectTypes {
    #[br(parse_with = parse_pascal_vec, assert(edit_object_types.is_empty()))]
    #[bw(write_with = write_pascal_vec)]
    pub edit_object_types: Vec<()>,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Serialize, Deserialize)]
pub enum InternalObjectDataValue {
    Pointer(i32),
    CString(String),
    IDENT(u32),
    UBYTE(u8),
    ULONG(u32),
    SLONG(i32),
    UQUAD(u64),
    SQUAD(i64),
    FLOAT(f32),
    Primitive(Vec<u8>),
    SLONGEnum(i32),
    Enum(Vec<u8>),
    Array(Vec<InternalObjectDataValue>),
    Struct {
        Base: Option<Box<InternalObjectDataValue>>,
        members: Vec<InternalObjectDataValue>,
    },
    CSyncedSLONG(i32),
    StaticStackArray(Vec<InternalObjectDataValue>),
    DynamicContainer(Vec<u32>),
}

#[derive(Serialize, Deserialize)]
pub struct InternalObject {
    Object: u32,
    Type: u32,
    value: InternalObjectDataValue,
}

#[derive(BinRead, BinWrite)]
#[brw(magic = b"DCON")]
struct DCONMagic;

#[derive(BinRead, BinWrite)]
#[brw(magic = b"SSAR")]
struct SSARMagic;

impl BinRead for InternalObject {
    type Args<'a> = (&'a InternalTypes,);

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<Self> {
        let internal_types = args.0;

        fn read_type<R: std::io::Read + std::io::Seek>(
            reader: &mut R,
            endian: Endian,
            data_type: u32,
            internal_types: &HashMap<u32, &DataType>,
        ) -> BinResult<InternalObjectDataValue> {
            let data_type = internal_types.get(&data_type).ok_or_else(|| {
                let pos = match reader.stream_position() {
                    Ok(pos) => pos,
                    Err(e) => return binrw::Error::Io(e),
                };
                binrw::Error::Custom {
                    pos,
                    err: Box::new("Tried to read external type"),
                }
            })?;
            let value = match &data_type.Type {
                DataTypeType::Primitive { Bytes, .. } => match data_type.Name.as_str() {
                    // Special case for primitive named CString, it is a Pascal string
                    "CString" => {
                        InternalObjectDataValue::CString(parse_pascal_string(reader, endian, ())?)
                    }
                    // Special case for primitive named IDENT, it is a ULONG
                    "IDENT" => {
                        InternalObjectDataValue::IDENT(u32::read_options(reader, endian, ())?)
                    }
                    // Special cases for known types so they are easier to edit in the JSON
                    "UBYTE" => {
                        InternalObjectDataValue::UBYTE(u8::read_options(reader, endian, ())?)
                    }
                    "ULONG" => {
                        InternalObjectDataValue::ULONG(u32::read_options(reader, endian, ())?)
                    }
                    "SLONG" => {
                        InternalObjectDataValue::SLONG(i32::read_options(reader, endian, ())?)
                    }
                    "UQUAD" => {
                        InternalObjectDataValue::UQUAD(u64::read_options(reader, endian, ())?)
                    }
                    "SQUAD" => {
                        InternalObjectDataValue::SQUAD(i64::read_options(reader, endian, ())?)
                    }
                    "FLOAT" => {
                        InternalObjectDataValue::FLOAT(f32::read_options(reader, endian, ())?)
                    }
                    _ => {
                        warn!(
                            "Unknown primitive type: ID: {}, name: {}, size: {}, format: {}",
                            data_type.DataType, data_type.Name, Bytes, data_type.Format
                        );
                        InternalObjectDataValue::Primitive(Vec::<u8>::read_options(
                            reader,
                            endian,
                            args! { count: *Bytes as usize, inner: () },
                        )?)
                    }
                },
                DataTypeType::Enum { Bytes } => match Bytes {
                    // Special cases for known enum sizes so they are easier to edit in the
                    // JSON
                    4 => InternalObjectDataValue::SLONGEnum(i32::read_options(reader, endian, ())?),
                    _ => InternalObjectDataValue::Enum(Vec::<u8>::read_options(
                        reader,
                        endian,
                        args! { count: *Bytes as usize, inner: () },
                    )?),
                },
                DataTypeType::Pointer { .. } => {
                    // This is either -1 or the ID of another Object in the file
                    InternalObjectDataValue::Pointer(i32::read_options(reader, endian, ())?)
                }
                DataTypeType::Array { Of, cols, .. } => InternalObjectDataValue::Array(
                    std::iter::repeat_with(|| read_type(reader, endian, *Of, internal_types))
                        .take(*cols as usize)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                DataTypeType::Struct { Base, members } => match data_type.Name.as_str() {
                    // Special case for struct named CSyncedSLONG with 0 members, it is an
                    // SLONG
                    "CSyncedSLONG" if members.is_empty() => InternalObjectDataValue::CSyncedSLONG(
                        i32::read_options(reader, endian, ())?,
                    ),
                    _ => {
                        let Base = if *Base != -1 {
                            Some(Box::new(read_type(
                                reader,
                                endian,
                                *Base as u32,
                                internal_types,
                            )?))
                        } else {
                            None
                        };

                        let members = members
                            .iter()
                            .map(|member| read_type(reader, endian, member.Type, internal_types))
                            .collect::<Result<Vec<_>, _>>()?;
                        InternalObjectDataValue::Struct { Base, members }
                    }
                },
                DataTypeType::StaticStackArray { Of } => {
                    SSARMagic::read_options(reader, endian, ())?;

                    let count = u32::read_options(reader, endian, ())?;
                    InternalObjectDataValue::StaticStackArray(
                        std::iter::repeat_with(|| read_type(reader, endian, *Of, internal_types))
                            .take(count as usize)
                            .collect::<Result<Vec<_>, _>>()?,
                    )
                }
                DataTypeType::DynamicContainer { .. } => {
                    DCONMagic::read_options(reader, endian, ())?;

                    let count = u32::read_options(reader, endian, ())?;
                    InternalObjectDataValue::DynamicContainer(
                        std::iter::repeat_with(|| u32::read_options(reader, endian, ()))
                            .take(count as usize)
                            .collect::<Result<Vec<_>, _>>()?,
                    )
                }
                DataTypeType::TypeDef { For } => read_type(reader, endian, *For, internal_types)?,
            };

            Ok(value)
        }

        // FIXME: Probably shouldn't reconstruct the HashMap for every object, but
        // passing things by reference with binrw is hard
        let internal_types = internal_types
            .types
            .iter()
            .by_ref()
            .map(|t| (t.DataType, t))
            .collect::<HashMap<_, _>>();
        let Object = u32::read_options(reader, endian, ())?;
        let Type = u32::read_options(reader, endian, ())?;
        let value = read_type(reader, endian, Type, &internal_types)?;

        Ok(Self {
            Object,
            Type,
            value,
        })
    }
}

impl BinWrite for InternalObject {
    type Args<'a> = ();

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        _args: Self::Args<'_>,
    ) -> BinResult<()> {
        self.Object.write_options(writer, endian, ())?;
        self.Type.write_options(writer, endian, ())?;

        fn write_value<W: Write + Seek>(
            value: &InternalObjectDataValue,
            writer: &mut W,
            endian: Endian,
        ) -> BinResult<()> {
            match value {
                InternalObjectDataValue::Pointer(pointer) => {
                    pointer.write_options(writer, endian, ())
                }
                InternalObjectDataValue::CString(cstring) => {
                    write_pascal_string(cstring, writer, endian, ())
                }
                InternalObjectDataValue::IDENT(ident) => ident.write_options(writer, endian, ()),
                InternalObjectDataValue::UBYTE(ubyte) => ubyte.write_options(writer, endian, ()),
                InternalObjectDataValue::ULONG(ulong) => ulong.write_options(writer, endian, ()),
                InternalObjectDataValue::SLONG(slong) => slong.write_options(writer, endian, ()),
                InternalObjectDataValue::UQUAD(uquad) => uquad.write_options(writer, endian, ()),
                InternalObjectDataValue::SQUAD(squad) => squad.write_options(writer, endian, ()),
                InternalObjectDataValue::FLOAT(float) => float.write_options(writer, endian, ()),
                InternalObjectDataValue::Primitive(bytes) => {
                    bytes.write_options(writer, endian, ())
                }
                InternalObjectDataValue::SLONGEnum(slong_enum) => {
                    slong_enum.write_options(writer, endian, ())
                }
                InternalObjectDataValue::Enum(bytes) => bytes.write_options(writer, endian, ()),
                InternalObjectDataValue::Array(internal_object_data_values) => {
                    for value in internal_object_data_values {
                        write_value(value, writer, endian)?;
                    }

                    Ok(())
                }
                InternalObjectDataValue::Struct { Base, members } => {
                    if let Some(Base) = Base {
                        write_value(Base, writer, endian)?;
                    }

                    for member in members {
                        write_value(member, writer, endian)?;
                    }

                    Ok(())
                }
                InternalObjectDataValue::CSyncedSLONG(csynced_slong) => {
                    csynced_slong.write_options(writer, endian, ())
                }
                InternalObjectDataValue::StaticStackArray(internal_object_data_values) => {
                    SSARMagic.write_options(writer, endian, ())?;
                    (internal_object_data_values.len() as u32).write_options(writer, endian, ())?;
                    for value in internal_object_data_values {
                        write_value(value, writer, endian)?;
                    }

                    Ok(())
                }
                InternalObjectDataValue::DynamicContainer(pointers) => {
                    DCONMagic.write_options(writer, endian, ())?;
                    (pointers.len() as u32).write_options(writer, endian, ())?;
                    for pointer in pointers {
                        pointer.write_options(writer, endian, ())?;
                    }

                    Ok(())
                }
            }
        }

        write_value(&self.value, writer, endian)?;

        Ok(())
    }
}

#[derive(BinRead, BinWrite, Serialize, Deserialize)]
#[brw(magic = b"OBJS")]
#[br(import(internal_types: &InternalTypes))]
pub struct InternalObjects {
    #[br(parse_with = parse_pascal_vec, args((internal_types,)))]
    #[bw(write_with = write_pascal_vec)]
    pub internal_object: Vec<InternalObject>,
}

#[derive(BinRead, BinWrite, Serialize, Deserialize)]
#[brw(magic = b"EDOB")]
pub struct EditObjects {
    #[br(parse_with = parse_pascal_vec, assert(edit_objects.is_empty()))]
    #[bw(write_with = write_pascal_vec)]
    pub edit_objects: Vec<()>,
}

#[derive(BinRead, BinWrite, Serialize, Deserialize)]
#[brw(magic = b"METAEND ")]
pub struct Metaend;

#[binrw]
#[derive(Serialize, Deserialize)]
pub struct CTSEMeta {
    pub metadata: Metadata,
    pub messages: Messages,
    #[br(temp)]
    #[bw(calc = Info::new(resource_files, idents, external_types, internal_types, external_objects, internal_objects))]
    pub _info: Info,
    pub resource_files: ResourceFiles,
    pub idents: Idents,
    pub external_types: ExternalTypes,
    pub internal_types: InternalTypes,
    pub external_objects: ExternalObjects,
    pub internal_object_types: InternalObjectTypes,
    pub edit_object_types: EditObjectTypes,
    #[br(args(&internal_types))]
    pub internal_objects: InternalObjects,
    pub edit_objects: EditObjects,
    #[br(temp)]
    #[bw(calc = Metaend)]
    _metaend: Metaend,
}
