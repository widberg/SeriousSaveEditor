use binrw::{BinRead, BinWrite, args, parser, writer};

#[parser(reader, endian)]
pub fn parse_pascal_string() -> binrw::BinResult<String> {
    let count = u32::read_options(reader, endian, ())? as usize;
    let pos = reader.stream_position()?;
    let utf8 = Vec::<u8>::read_options(reader, endian, args! { count, inner: () })?;
    let string = String::from_utf8(utf8).map_err(|e| binrw::Error::Custom {
        pos,
        err: Box::new(e),
    })?;
    Ok(string)
}

// Weird signature to work with binrw type_hint functions
#[writer(writer, endian)]
pub fn write_pascal_string(value: &(impl AsRef<str> + ?Sized)) -> binrw::BinResult<()> {
    (value.as_ref().len() as u32).write_options(writer, endian, ())?;
    value.as_ref().as_bytes().write(writer)?;
    Ok(())
}

#[parser(reader, endian)]
pub fn parse_pascal_vec<T>(args: T::Args<'_>) -> binrw::BinResult<Vec<T>>
where
    for<'a> T: BinRead<Args<'a>: Clone> + 'a,
{
    let count = u32::read_options(reader, endian, ())? as usize;
    let vec = Vec::<T>::read_options(reader, endian, args! { count, inner: args })?;
    Ok(vec)
}

#[writer(writer, endian)]
pub fn write_pascal_vec<T>(value: &Vec<T>) -> binrw::BinResult<()>
where
    for<'a> T: BinWrite<Args<'a> = ()> + 'a,
{
    (value.len() as u32).write_options(writer, endian, ())?;
    value.write_options(writer, endian, ())?;
    Ok(())
}
