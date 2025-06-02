use std::collections::HashMap;
use std::io::{BufRead, Cursor, Read, Seek, SeekFrom, Write};
use std::ops::{Deref, DerefMut};

use anyhow::Result;
use binrw::meta::WriteMagic;
use binrw::{BinRead, BinWrite, Endian, args, binwrite};
use flate2::bufread::GzDecoder;
use flate2::{Compression, GzBuilder};
use log::warn;
use rand::RngCore;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::traits::SignatureScheme;
use rsa::{Pss, RsaPrivateKey, RsaPublicKey};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use tiger::Tiger;

use crate::helpers::{parse_pascal_string, write_pascal_string};

const SIGNATURE_STREAM_BLOCK_SIZE: u32 = 0x10000;
const SIGNATURE_STREAM_HASH_METHOD: HashMethod = HashMethod::Sha1;

#[derive(Copy, Clone)]
enum HashMethod {
    Sha1 = 4,
    Tiger = 5,
    Sha256 = 6,
}

impl TryFrom<u32> for HashMethod {
    type Error = ();

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value {
            x if x == Self::Sha1 as u32 => Ok(Self::Sha1),
            x if x == Self::Tiger as u32 => Ok(Self::Tiger),
            x if x == Self::Sha256 as u32 => Ok(Self::Sha256),
            _ => Err(()),
        }
    }
}

impl From<HashMethod> for u32 {
    fn from(value: HashMethod) -> Self {
        value as Self
    }
}

impl HashMethod {
    fn new_hasher(self) -> Box<dyn sha1::digest::DynDigest> {
        match self {
            Self::Sha1 => Box::new(Sha1::new()),
            Self::Tiger => Box::new(Tiger::new()),
            Self::Sha256 => Box::new(Sha256::new()),
        }
    }

    fn new_pss(self) -> Pss {
        const SALT_LEN: usize = 11;
        match self {
            Self::Sha1 => Pss::new_with_salt::<Sha1>(SALT_LEN),
            Self::Tiger => Pss::new_with_salt::<Tiger>(SALT_LEN),
            Self::Sha256 => Pss::new_with_salt::<Sha256>(SALT_LEN),
        }
    }

    fn signature_size(self, private_key: &RsaPrivateKey) -> rsa::Result<usize> {
        let mut rng = rand::thread_rng();
        let hasher = Self::new_hasher(self);
        let pss = Self::new_pss(self);
        pss.sign(Some(&mut rng), private_key, &hasher.finalize())
            .map(|x| x.len())
    }
}

macro_rules! to_endian_bytes {
    ($endian:expr, $value:expr) => {
        match ($endian) {
            Endian::Big => ($value).to_be_bytes(),
            Endian::Little => ($value).to_le_bytes(),
        }
    };
}

#[derive(BinRead, BinWrite)]
#[brw(magic = b"SIGSTRM12GIS")]
struct SignatureStreamMagic;

pub fn parse_gz_signature_stream_data<R: BufRead>(
    reader: &mut R,
    endian: Endian,
    key_ring: &KeyRing,
    memory_stream_name: Option<impl AsRef<str>>,
    userid: Option<impl AsRef<str>>,
) -> Result<Box<[u8]>> {
    let mut reader = GzDecoder::new(reader);
    parse_signature_stream_data(&mut reader, endian, key_ring, memory_stream_name, userid)
}

pub fn parse_signature_stream_data<R: Read>(
    reader: &mut R,
    endian: Endian,
    key_ring: &KeyRing,
    memory_stream_name: Option<impl AsRef<str>>,
    userid: Option<impl AsRef<str>>,
) -> Result<Box<[u8]>> {
    let mut reader = binrw::io::NoSeek::new(reader);
    SignatureStreamMagic::read_options(&mut reader, endian, ())?;
    let version = u32::read_options(&mut reader, endian, ())?;
    let block_size = u32::read_options(&mut reader, endian, ())?.clamp(0, 0x80000);
    let hash_method_id = u32::read_options(&mut reader, endian, ())?;
    let hash_size = i32::read_options(&mut reader, endian, ())?.clamp(0, 0x1000);
    Vec::<u8>::read_options(
        &mut reader,
        endian,
        args! { count: hash_size as usize, inner: () },
    )?;
    let salt = u32::read_options(&mut reader, endian, ())?;
    let has_memory_stream_name = if version >= 2 {
        Some(u32::read_options(&mut reader, endian, ())?)
    } else {
        None
    };
    let has_userid = if version >= 3 {
        Some(u32::read_options(&mut reader, endian, ())?)
    } else {
        None
    };
    let signature_related_string = if version >= 5 {
        Some(parse_pascal_string(&mut reader, endian, ())?)
    } else {
        None
    };
    let signature_size = u32::read_options(&mut reader, endian, ())?.clamp(0, 0x1000);

    let signature_info = if version >= 3 && signature_size > 0 {
        let sign_key_name = parse_pascal_string(&mut reader, endian, ())?;
        let signature = Vec::<u8>::read_options(
            &mut reader,
            endian,
            args! { count: signature_size as usize, inner: () },
        )?;
        Some((sign_key_name, signature))
    } else {
        None
    };

    struct VerifyingInfo<'a> {
        public_key: RsaPublicKey,
        hash_method: HashMethod,
        salt: u32,
        memory_stream_name_bytes: Option<&'a [u8]>,
        userid_bytes: Option<&'a [u8]>,
    }

    let verifying_info = (|| {
        let (sign_key_name, signature) = signature_info?;
        let Some(public_key) = key_ring
            .get(sign_key_name.as_str())
            .map(|keys| keys.public.clone())
        else {
            warn!("no key \"{}\" in key ring", sign_key_name);
            return None;
        };

        let Ok(hash_method) = <u32 as TryInto<HashMethod>>::try_into(hash_method_id) else {
            warn!("unknown hash method {}", hash_method_id);
            return None;
        };

        let mut hasher = hash_method.new_hasher();
        let pss = hash_method.new_pss();
        hasher.update(&to_endian_bytes!(endian, version));
        hasher.update(&to_endian_bytes!(endian, block_size));
        hasher.update(&to_endian_bytes!(endian, hash_method_id));
        hasher.update(&to_endian_bytes!(endian, hash_size));
        hasher.update(&to_endian_bytes!(endian, salt));
        let memory_stream_name_bytes = has_memory_stream_name.and_then(|has_memory_stream_name| {
            hasher.update(&to_endian_bytes!(endian, has_memory_stream_name));
            (has_memory_stream_name != 0).then(|| {
                    let Some(memory_stream_name) = memory_stream_name.as_ref() else {
                        warn!("save requires memory stream name to be verified but one was not provided");
                        return None;
                    };
                    let memory_stream_name_bytes = memory_stream_name.as_ref().as_bytes();
                    hasher.update(memory_stream_name_bytes);
                    Some(memory_stream_name_bytes)
                }).flatten()
        });
        let userid_bytes = has_userid.and_then(|has_userid| {
            hasher.update(&to_endian_bytes!(endian, has_userid));
            (has_userid != 0)
            .then(|| {
                let Some(userid) = userid.as_ref() else {
                    warn!(
                        "save requires memory stream name to be verified but one was not provided"
                    );
                    return None;
                };
                let userid_bytes = userid.as_ref().as_bytes();
                hasher.update(userid_bytes);
                Some(userid_bytes)
            })
            .flatten()
        });
        if let Some(signature_related_string) = signature_related_string {
            hasher.update(signature_related_string.as_bytes());
        }
        hasher.update(&to_endian_bytes!(endian, signature_size));
        hasher.update(sign_key_name.as_bytes());
        if let Err(e) = pss.verify(&public_key, &hasher.finalize(), &signature) {
            warn!("invalid signature in header: {}", e);
        }

        Some(VerifyingInfo {
            public_key,
            hash_method,
            salt,
            memory_stream_name_bytes,
            userid_bytes,
        })
    })();

    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;
    let mut reader = Cursor::new(&data);

    let mut deinterleaved_data = Vec::new();
    let mut signature_data = vec![0; signature_size as usize];

    for block_index in 0.. {
        let remaining = data.len() as u64 - reader.position();

        if remaining == 0 {
            break;
        }

        let block_data = if remaining >= block_size as u64 + signature_size as u64 {
            reader
                .by_ref()
                .take(block_size as u64)
                .read_to_end(&mut deinterleaved_data)?;
            reader.read_exact(&mut signature_data)?;
            &deinterleaved_data[deinterleaved_data.len() - block_size as usize..]
        } else {
            let short_block_size = remaining - signature_size as u64;
            reader
                .by_ref()
                .take(short_block_size)
                .read_to_end(&mut deinterleaved_data)?;
            reader.read_exact(&mut signature_data)?;
            &deinterleaved_data[deinterleaved_data.len() - short_block_size as usize..]
        };

        if let Some(verifying_info) = verifying_info.as_ref() {
            let mut hasher = verifying_info.hash_method.new_hasher();
            let pss = verifying_info.hash_method.new_pss();
            hasher.update(&to_endian_bytes!(
                endian,
                verifying_info.salt ^ (block_index + 0xB1B)
            ));
            if let Some(memory_stream_name_bytes) = verifying_info.memory_stream_name_bytes {
                hasher.update(memory_stream_name_bytes);
            }
            if let Some(userid_bytes) = verifying_info.userid_bytes {
                hasher.update(userid_bytes);
            }
            hasher.update(block_data);
            if let Err(e) = pss.verify(
                &verifying_info.public_key,
                &hasher.finalize(),
                &signature_data,
            ) {
                warn!("invalid signature for block {}: {}", block_index, e);
            }
        }
    }

    Ok(deinterleaved_data.into_boxed_slice())
}

pub struct SignOptions<'a, S: AsRef<str> + ?Sized, T: AsRef<str> + ?Sized, U: AsRef<str> + ?Sized> {
    pub key_ring: &'a KeyRing<'a>,
    pub sign_key_name: &'a S,
    pub memory_stream_name: Option<&'a T>,
    pub userid: Option<&'a U>,
}

pub fn write_gz_signature_stream_data<
    W: Write + Seek,
    S: AsRef<str> + ?Sized,
    T: AsRef<str> + ?Sized,
    U: AsRef<str> + ?Sized,
>(
    writer: &mut W,
    endian: Endian,
    sign_options: Option<&SignOptions<S, T, U>>,
    version: u32,
    data: &[u8],
) -> Result<()> {
    let mut writer = GzBuilder::new()
        .extra([0u8; 0xC])
        .operating_system(0)
        .write(writer, Compression::new(6));

    let decompressed_size =
        write_signature_stream_data(&mut writer, endian, sign_options, version, data)?;

    let mut writer = writer.finish()?;
    let writer_end_pos = writer.stream_position()?;
    const GZIP_HEADER_SIZE: u64 = 0x18;
    const GZIP_FOOTER_SIZE: u64 = 0x8;
    let compressed_size = writer_end_pos - GZIP_HEADER_SIZE - GZIP_FOOTER_SIZE; // flate2 is annoying
    writer.seek(SeekFrom::Start(0xC))?;

    // Croteam sizes prefix extra field
    #[binwrite]
    #[bw(little, magic = b"CT")]
    struct ExtraFieldCT {
        #[bw(calc = 8)]
        field_data_length: u16,
        compressed_size: u32,
        decompressed_size: u32,
    }

    ExtraFieldCT {
        compressed_size: compressed_size as u32,
        decompressed_size: decompressed_size as u32,
    }
    .write(&mut writer)?;

    Ok(())
}

pub fn write_signature_stream_data<
    W: Write,
    S: AsRef<str> + ?Sized,
    T: AsRef<str> + ?Sized,
    U: AsRef<str> + ?Sized,
>(
    writer: &mut W,
    endian: Endian,
    sign_options: Option<&SignOptions<S, T, U>>,
    version: u32,
    data: &[u8],
) -> Result<usize> {
    let mut writer = binrw::io::NoSeek::new(writer);
    let mut rng = rand::thread_rng();
    let signature_stream_block_size = SIGNATURE_STREAM_BLOCK_SIZE;
    let hash_method = SIGNATURE_STREAM_HASH_METHOD;
    let hash_method_id = <HashMethod as Into<u32>>::into(hash_method);
    let hash_size = 0i32;
    let salt = rng.next_u32();
    let (has_memory_stream_name, has_userid) = sign_options
        .map(|sign_options| {
            (
                sign_options.memory_stream_name.is_some() as u32,
                sign_options.userid.is_some() as u32,
            )
        })
        .unwrap_or_default();
    let signature_related_string = "";

    SignatureStreamMagic.write(&mut writer)?;
    let mut decompressed_size = <SignatureStreamMagic as WriteMagic>::MAGIC.len();
    version.write_options(&mut writer, endian, ())?;
    decompressed_size += 4;
    signature_stream_block_size.write_options(&mut writer, endian, ())?;
    decompressed_size += 4;
    hash_method_id.write_options(&mut writer, endian, ())?;
    decompressed_size += 4;
    hash_size.write_options(&mut writer, endian, ())?;
    decompressed_size += 4;
    salt.write_options(&mut writer, endian, ())?;
    decompressed_size += 4;
    if version >= 2 {
        has_memory_stream_name.write_options(&mut writer, endian, ())?;
        decompressed_size += 4;
    }
    if version >= 3 {
        has_userid.write_options(&mut writer, endian, ())?;
        decompressed_size += 4;
    }
    if version >= 5 {
        write_pascal_string(&signature_related_string, &mut writer, endian, ())?;
        decompressed_size += 4 + signature_related_string.len();
    }

    let (header_signature_stuff_size, signing_info) = if version >= 3 {
        struct SigningInfo<'a> {
            private_key: RsaPrivateKey,
            hash_method: HashMethod,
            salt: u32,
            memory_stream_name_bytes: Option<&'a [u8]>,
            userid_bytes: Option<&'a [u8]>,
        }

        if let Some(sign_options) = sign_options.as_ref() {
            if let Some(private_key) = sign_options
                .key_ring
                .get(sign_options.sign_key_name.as_ref())
                .and_then(|keys| keys.private.clone())
            {
                let mut hasher = hash_method.new_hasher();
                let pss = hash_method.new_pss();
                hasher.update(&to_endian_bytes!(endian, version));
                hasher.update(&to_endian_bytes!(endian, signature_stream_block_size));
                hasher.update(&to_endian_bytes!(endian, hash_method_id));
                hasher.update(&to_endian_bytes!(endian, hash_size));
                hasher.update(&to_endian_bytes!(endian, salt));
                if version >= 2 {
                    hasher.update(&to_endian_bytes!(endian, has_memory_stream_name));
                    if version >= 4 {
                        if let Some(memory_stream_name) = sign_options.memory_stream_name.as_ref() {
                            hasher.update(memory_stream_name.as_ref().as_bytes());
                        }
                    }
                }
                if version >= 3 {
                    hasher.update(&to_endian_bytes!(endian, has_userid));
                    if let Some(userid) = sign_options.userid.as_ref() {
                        hasher.update(userid.as_ref().as_bytes());
                    }
                }
                if version >= 5 {
                    hasher.update(signature_related_string.as_bytes());
                }
                match hash_method.signature_size(&private_key) {
                    Err(e) => {
                        warn!("failed to sign header: {}", e);
                        0u32.write_options(&mut writer, endian, ())?;
                        (4, None)
                    }
                    Ok(signature_size) => {
                        hasher.update(&to_endian_bytes!(endian, signature_size as u32));
                        hasher.update(sign_options.sign_key_name.as_ref().as_bytes());
                        match pss.sign(Some(&mut rng), &private_key, &hasher.finalize()) {
                            Err(e) => {
                                warn!("failed to sign header: {}", e);
                                0u32.write_options(&mut writer, endian, ())?;
                                (4, None)
                            }
                            Ok(signature) => {
                                let signature_size = signature.len() as u32;
                                signature_size.write_options(&mut writer, endian, ())?;
                                write_pascal_string(
                                    sign_options.sign_key_name,
                                    &mut writer,
                                    endian,
                                    (),
                                )?;
                                signature.write(&mut writer)?;
                                (
                                    4 + 4
                                        + sign_options.sign_key_name.as_ref().len()
                                        + signature.len(),
                                    Some(SigningInfo {
                                        private_key,
                                        hash_method,
                                        salt,
                                        memory_stream_name_bytes: sign_options
                                            .memory_stream_name
                                            .as_ref()
                                            .map(|x| x.as_ref().as_bytes()),
                                        userid_bytes: sign_options
                                            .userid
                                            .as_ref()
                                            .map(|x| x.as_ref().as_bytes()),
                                    }),
                                )
                            }
                        }
                    }
                }
            } else {
                warn!(
                    "no private key \"{}\" in key ring",
                    sign_options.sign_key_name.as_ref()
                );
                0u32.write_options(&mut writer, endian, ())?;
                (4, None)
            }
        } else {
            0u32.write_options(&mut writer, endian, ())?;
            (4, None)
        }
    } else {
        0u32.write_options(&mut writer, endian, ())?;
        (4, None)
    };

    decompressed_size += header_signature_stuff_size;

    for block_index in 0.. {
        let start = block_index as usize * signature_stream_block_size as usize;
        if start >= data.len() {
            break;
        }
        let end =
            ((block_index as usize + 1) * signature_stream_block_size as usize).min(data.len());
        let block_data = &data[start..end];
        writer.write_all(block_data)?;
        decompressed_size += block_data.len();
        if let Some(signing_info) = signing_info.as_ref() {
            let mut hasher = signing_info.hash_method.new_hasher();
            let pss = signing_info.hash_method.new_pss();
            hasher.update(&to_endian_bytes!(
                endian,
                signing_info.salt ^ (block_index + 0xB1B)
            ));
            if let Some(memory_stream_name_bytes) = signing_info.memory_stream_name_bytes {
                hasher.update(memory_stream_name_bytes);
            }
            if let Some(userid_bytes) = signing_info.userid_bytes {
                hasher.update(userid_bytes);
            }
            hasher.update(block_data);
            let signature = pss.sign(
                Some(&mut rng),
                &signing_info.private_key,
                &hasher.finalize(),
            )?;
            writer.write_all(&signature)?;
            decompressed_size += signature.len();
        }
    }

    Ok(decompressed_size)
}

pub struct RsaKeys {
    private: Option<RsaPrivateKey>,
    public: RsaPublicKey,
}

pub struct KeyRing<'a>(HashMap<&'a str, RsaKeys>);

impl<'a> KeyRing<'a> {
    fn new() -> Self {
        Self(HashMap::new())
    }

    fn insert_from_name_and_private_key_pem(&mut self, name: &'a str, private_key_pem: &str) {
        let private_key = RsaPrivateKey::from_pkcs1_pem(private_key_pem).unwrap();
        let public_key = private_key.to_public_key();
        self.insert(
            name,
            RsaKeys {
                private: Some(private_key),
                public: public_key,
            },
        );
    }

    fn insert_from_name_and_public_key_pem(&mut self, name: &'a str, public_key_pem: &str) {
        let public_key = RsaPublicKey::from_pkcs1_pem(public_key_pem).unwrap();
        self.insert(
            name,
            RsaKeys {
                private: None,
                public: public_key,
            },
        );
    }
}

impl<'a> Deref for KeyRing<'a> {
    type Target = HashMap<&'a str, RsaKeys>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for KeyRing<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// Keys needed to validate signature streams
pub static SIGN_KEY_GAME_LOCAL_NAME: &str = "SignKey.GameLocal";
static SIGN_KEY_GAME_LOCAL_PRIVATE_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANIBJ/mD23F0s2pFxNDq2iJifJ75IKSCaRCWhfxR/0KpbwsQCPp9
yQgCSAb/FRe+Ij2CvXzVR8BNVA9qEhVrtkECAwEAAQJANhiaJYoz0wwO04dZZb+5
pTXdiE4AfKAjVGSR6ydsK81mCqo4PSDgNHOUTVl3jWOjIiRAfR1uHURG8zq66Prd
SQIhAOB+YhT2+MN4Gvf3bj2FBC1WIsFz7ll3evu/hYlzHj53AiEA73o0qDvKshQy
wf1XkZ+ZCuzna6bpu5CxhtAIto4jRwcCIQDTaXHIuISw4CzVlGh2+wth/poggKLY
ElL5PfXt6UF0JQIhAMCGru7RoxOnyWbMFiqs9I0kCKkzd5WjrhWECn05qILhAiAg
RyiY59PrKm80JxhD5WzKpD8CH0V8F6TkZs2/V7fRnQ==
-----END RSA PRIVATE KEY-----";

pub static SIGN_KEY_EDITOR_SIGNATURE: &str = "Signkey.EditorSignature";
static SIGN_KEY_EDITOR_SIGNATURE_PRIVATE_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEArbudiCPeDVNXCr9aNFE9KyIWeqHzw1P4tyDb1UfteuOt9aor
92qoSP9L3cOd27q6Ju/limeFDGbOH1wvrW4bLb3ST0C7WwAEV/o6SdU3uAco4y3U
FB22QU9t0Ll880uXWuvLTCc4m0H0sYCNzvt8xTfp3rwVX7xZ+IJHFeACFV995R2P
Gh+wUA8Zv+ggKbjBKRLlwu+WW4s5OoHdCkpUNC/5AwyCia9N+JPm+vvLt9+x/Tri
IobA8itmzofrUUkYzan/uESSF1X5eZXGz9+T0OdEVr43yZldAe1ghgPpqvVUs1Z5
7ROQ36s+c1FDlf8kXPQxVUui1VbRt3SjA0daYwIDAQABAoIBAATJ1rC0PwriUNQv
Vql50mly72hX4w5vgmZsaxgOJcyCTql7vunQhcI6pHkAoEQ4eahYalzjN4vnoCdw
dLFKB0kTzKJ55/ASfbbTDceP2eZM7uKRa8wAzvouhJoBKCF95DZm/gZ4+kVv5Eep
gb8XuBD+K92uFMS7vfBsiXsKiTl/iao0dlcDYjnfkJQWgaRBWSW7O1nC6Tp8XPpQ
Xm/reub6Qx2U9599CIcqORXTEwbZdVcKjkxu6XhV0I+/1wcnv+oL2uT6D+EYeLUS
q0ty1mM8eXgdENB3pSeq5zvOmQP+2jF/evhdIcCbvuGbpkliNKVR7m8fEvEFpuM7
dZfMPOkCgYEA0PHHHJyZHb+mTd2DZh8I/XSF0/VbfBEET+nvIiXt5KpCI4hgfsGt
NysjYITckoVY2P6u2LIkIULdAWvo2FNy2sgdSfr/esQRWM7tqdfg/hVf0TN5LNN0
tOJpEBO84jDoV4cnmpmxcptJB+6bT24BR8coNioQhoYqErjbrBaGwy8CgYEA1NvL
JnWIqhndFmK8WagATQYtZP7okkZVSiheeCWEtd0Aw7D80L5TP0KV87k6pPcfgRom
j9d7oMiWT8+ArrL9ud6n1bK9w/gvQVnqVyc3iKLjhHBu6KLWzz3ietzgoqyqLk0P
3PBBvdZiAHi7Eho40ILpuw4bBmAxJv0hkEfPXw0CgYEArVUVR4AFaW9WZ9vuKGZw
j8n9RzOQnCCFwkGflmV+ryYqzc1Rt3W120FXDLfLP2WNqh3FMJC/djRAoPBC7kpz
ylkeKwQkslQ6y8CF2lLzG/ThUuvvhyc39uKoI6UsGTxXUl0VlqQPV7LIZ+MiRkdM
mp31ltFYejCMcJGX8m+RhhMCgYEAqtPKcg8ZowomuPR8nKeLtkUi4U8Cb4IqqN1F
E79ohlvbZTIBc7WLMdXKalNZkVMS4ZWPJRmWii7xExRA/fOAVU8v+vz79u6TXis/
OrqqgunXFk71c5ZcNu4/eMMTNPrFiWsnM/VNjYEkHaTG3XxV5GFsG0bywWcpi1TT
PuuirXECgYB0AEVi60oKFpAZ68T/PiGLi+we1QZy0Kipvevt4Jo+1ZJVHWV0Hyda
QXjAj2vusb8h0g67U/0+WqiNbyFdr3hhQSkcCb6vQ6OOVIYcsZ9GfrUwrgAZhfZo
6Q5Qa78rTiDnT7xqTGfjpaeqR3CCu8dxc/74hgsCuIgJhgJDyxmDsA==
-----END RSA PRIVATE KEY-----";

pub static SIGN_KEY_LICENSE_SIGNATURE: &str = "SignKey.LicenseSignature";
static SIGN_KEY_LICENSE_SIGNATURE_PRIVATE_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvkWJEd6agqvybNMBP2WeKycF+7f80LakopP93BLjHeu501og
YkwRLHAdvW6ZZJeiTecXSX5TvIioEBC90DAJmhVEMn9O/8OY517iM0yfiNBPKJU+
rYCOYNvgATwsU6cOKkT8+pobmqLK/ab24eqlZBIxBpCz6zbBnqwk37E7pfX4t33n
D8mXh7sCuGFHQUMMWcYERzNqpbpKXQ1rnyR4umzEf4lGEhxZ6NwAYYTMG+nR8png
AEe3tLs4Mk2+G8y9tLiS7Vu5OakzWmPGQgN8uYzuOFc3rtxZHuilmqG2kKfelEs3
5sgosuJJEux5IoVT6RMldngK4OGkdrRd83zCJQIDAQABAoH/JZGheNOBWUvK+dZm
0Ehq7IgLDgQnpAIjBd6IFs2j5gF6tahAsH1UhTra7ZKBVZ5qW2UnOgx0cAiLoIgP
O7C6ZWLl9dWbBqhJFNPeK1tFAD6bMegtruOtOTXPbLglpvESQo+BMzcV/0fQLmnn
tvDIhpI1iaKCpwEis8oxTO2ffgadWrsQHFKH/3GCkH3t1zJlHC+9A9d20HUM0ZOR
cwaVwc7QrYHDIOmp2WerlVHByWfzudh/J9GkVMJmDrhb5RrhRX8w7TKyAwBR8VeG
p23pH7bb1zIPOO1Ir3O3qWrO+GwFMaFkR34OhkazEbsWntZcJ2xDRg8NmpRvb2pB
eTExAoGBAMwwmkKuUtN/ksg24ipFAl0GmtPtvTuw2L7FrcvUxQ1tederIFw+brAG
p+qtJo/XyBZzURGnCsaIKHDwUJ3sDApWVeIFwpetLAGJN6J/aItj402h//sb0q9z
thT2j4SQHK2l9LOjnwZYZKLphnyKAeorDcI3fFuy0paYhJgIgSsNAoGBAO6M23/N
mxEH7H/sNCSWFUmQnarOoECdvD+NcqWRlaD5r4PAz9WbM/ZVYFxtJ9Eh53ybcK1N
Y9TM97/dbD623mtIOBK5fljMm9Sl6AwleCDQ/YVrQih9pJTXlVVXDzXymELqE+Hu
X77JMG0Qbb/4wQKQ79zibx3GpdPKcfilTs15AoGBAIYeeoTICiFfz2LxIdcP4wCF
gRcpNj3J6GROZdzX0eMDAKAXiDbuzzeR96OevhCHdKbCcgJ9TQegkae1Qc6pKDN2
CA1hKTMFjT0pC0ESHPJJ1xi8Cu6+lMGn6HaWiShSnHO26SdBlwfM8bVMXIjbAWz1
gKEMXwPATrCaV6WhGG7VAoGBAL1Io3rbiGmRIgW3RQCq3iVLTPAVmG7tOkwrToc1
58admLkwqzlRN4AE6rssGeYFwwrKxDOfLtHR+dwSNCvnKsFxwpyI90o6wIORSXkp
2hIgAqp1Gz/JwmggT+wxcm5aGpst5azmWq6mMXi5CnzDQ1Nn8gwQ2B6GW1qcTqb/
dHHxAoGASBaFvphWIH7gyrPJHRg7SCFTpGjehEyJLzkhzwPgCarxSM6KDAg05kVE
QMdaxopbgDkQ0v1y28M26mdby6nKpmELUlAN0h5fv5AvKQjzxMifUbJAHCH1NZX5
qbYE6GQD1jF8E/m78J/hmmseR37FdK18vWMn/pWPjvMeA4+pY2M=
-----END RSA PRIVATE KEY-----";

pub static SIGN_KEY_OFFICIAL_SIGNATURE: &str = "SignKey.OfficialSignature";
static SIGN_KEY_OFFICIAL_SIGNATURE_PUBLIC_PEM: &str = "-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEAoZ3gxls8HipMTo+XGL1qXwrU6POeo+jpwBy5PozQafQA4pp3EN9F
cAILP/LtrYqo0CT1ukK4fMEPwl+/ndj7dEgdDGnt8MUv8ceK0g5R2QyMae4+YDtk
Jown6E7k/AwDKKSGv7TAjR4rLHguh9LBg8JD5sDFRekDj5PFtQHiojkMIgZ+rAX4
n67bzOusnLRHycQRw6cyuGLRs5nLsJKIWZwYVSYa1Z2EGKR7EemSCTgbAAJcen4J
yWneasVNW71ps3xaX5yaAbnQWyWx1arKu1xsNsCO8z3DKIceYXkiXWVcP51CSCJW
l2m79ZRSz7Qo1c2nzFlaXH/dn3CRRz4PmR1/eqm+xjZFfgE5eyf7His3uEggYPX+
qdo91H3jxxB6YusuXC3rup/3HVx1xeNcuyvuA/a6s4OLzVTD11zPOdYQPA8epJuG
z49NYJwjekionQiBUYbQEA9gGTUztkSLGU5055pUy4SjRLynJA87+s+NWNTjbjS8
UvB6VY073sGz2Ov3UeqqebEsj404IawjL0kQthMo+JhWPSP7+j0l1ePKBAybRMoj
b1TrJpPC4vpTJzAYjLnw5WrFlRQrepeDP2SJE3f5sO3bs4PsEHbQVGc3fQpn7HVd
XbtLobQLHj0lk7TUVJ6iknZFp5t47YiVN8P5JAMWRIEJw/VX+CVRZdkCAwEAAQ==
-----END RSA PUBLIC KEY-----";

impl Default for KeyRing<'_> {
    fn default() -> Self {
        let mut key_ring = Self::new();
        key_ring.insert_from_name_and_private_key_pem(
            SIGN_KEY_GAME_LOCAL_NAME,
            SIGN_KEY_GAME_LOCAL_PRIVATE_PEM,
        );
        key_ring.insert_from_name_and_private_key_pem(
            SIGN_KEY_EDITOR_SIGNATURE,
            SIGN_KEY_EDITOR_SIGNATURE_PRIVATE_PEM,
        );
        key_ring.insert_from_name_and_private_key_pem(
            SIGN_KEY_LICENSE_SIGNATURE,
            SIGN_KEY_LICENSE_SIGNATURE_PRIVATE_PEM,
        );
        key_ring.insert_from_name_and_public_key_pem(
            SIGN_KEY_OFFICIAL_SIGNATURE,
            SIGN_KEY_OFFICIAL_SIGNATURE_PUBLIC_PEM,
        );
        key_ring
    }
}
