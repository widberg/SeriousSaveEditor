use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufWriter, Cursor};
use std::path::PathBuf;

use anyhow::Result;
use binrw::io::BufReader;
use binrw::{BinRead, BinWrite, Endian};
use clap::{Parser, Subcommand, ValueEnum};
use ctsemeta::CTSEMeta;
use signature_stream::{
    KeyRing,
    SIGN_KEY_GAME_LOCAL_NAME,
    SignOptions,
    parse_gz_signature_stream_data,
    parse_signature_stream_data,
    write_gz_signature_stream_data,
    write_signature_stream_data,
};

mod ctsemeta;
mod helpers;
mod signature_stream;

#[derive(ValueEnum, Clone)]
enum ClapEndian {
    #[clap(alias = "b")]
    Big,
    #[clap(alias = "l")]
    Little,
}

impl From<ClapEndian> for Endian {
    fn from(value: ClapEndian) -> Self {
        match value {
            ClapEndian::Big => Self::Big,
            ClapEndian::Little => Self::Little,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    #[clap(alias = "x")]
    Extract {
        player_profile: PathBuf,
        player_profile_extracted: PathBuf,
        #[arg(short, long)]
        memory_stream_name: Option<String>,
        #[arg(short, long)]
        userid: Option<String>,
        #[clap(value_enum)]
        #[arg(short, long, default_value_t = ClapEndian::Little)]
        endian: ClapEndian,
        #[arg(short, long)]
        no_guess_memory_stream_name: bool,
        #[arg(short, long)]
        json: bool,
        #[arg(long)]
        no_gz: bool,
    },
    #[clap(alias = "c")]
    Create {
        player_profile_extracted: PathBuf,
        player_profile: PathBuf,
        #[arg(short, long)]
        memory_stream_name: Option<String>,
        #[arg(short, long)]
        userid: Option<String>,
        #[clap(value_enum)]
        #[arg(short, long, default_value_t = ClapEndian::Little)]
        endian: ClapEndian,
        #[arg(short, long)]
        guess_memory_stream_name: bool,
        #[arg(long)]
        no_sign: bool,
        #[arg(short, long, default_value_t = 5)]
        signature_stream_version: u32,
        #[arg(short, long)]
        json: bool,
        #[arg(short, long, default_value_t = SIGN_KEY_GAME_LOCAL_NAME.to_string())]
        key_name: String,
        #[arg(long)]
        no_gz: bool,
    },
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

fn try_guess_memory_stream_name(file_name: Option<&OsStr>) -> Option<String> {
    let file_name = file_name?.to_str()?;

    if file_name.contains("PlayerProfile") {
        if file_name.contains("unrestricted") {
            Some("<memory stream:PlayerProfile_unrestricted.dat>".to_owned())
        } else {
            Some("<memory stream:PlayerProfile.dat>".to_owned())
        }
    } else if file_name.contains("All") {
        Some("Content/Talos/All.dat".to_owned())
    } else if file_name.contains("DLC") {
        Some("Content/Talos/DLC.dat".to_owned())
    } else {
        None
    }
}

fn main() -> Result<()> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "warn"),
    );

    let cli = Args::parse();
    let key_ring = KeyRing::default();

    match cli.command {
        Commands::Extract {
            player_profile,
            player_profile_extracted,
            memory_stream_name,
            userid,
            endian,
            no_guess_memory_stream_name,
            json,
            no_gz,
        } => {
            let endian = endian.into();
            let memory_stream_name = memory_stream_name.or_else(|| {
                (!no_guess_memory_stream_name)
                    .then(|| try_guess_memory_stream_name(player_profile.file_name()))
                    .flatten()
            });

            let mut reader = BufReader::new(File::open(&player_profile)?);
            let signature_stream_data = if no_gz {
                parse_signature_stream_data(
                    &mut reader,
                    endian,
                    &key_ring,
                    memory_stream_name,
                    userid,
                )?
            } else {
                parse_gz_signature_stream_data(
                    &mut reader,
                    endian,
                    &key_ring,
                    memory_stream_name,
                    userid,
                )?
            };

            if json {
                let ctsemeta =
                    CTSEMeta::read_options(&mut Cursor::new(&signature_stream_data), endian, ())?;

                serde_json::to_writer_pretty(
                    BufWriter::new(File::create(&player_profile_extracted)?),
                    &ctsemeta,
                )?;
            } else {
                std::fs::write(&player_profile_extracted, &signature_stream_data)?;
            }
        }
        Commands::Create {
            player_profile_extracted,
            player_profile,
            memory_stream_name,
            userid,
            endian,
            guess_memory_stream_name,
            no_sign,
            signature_stream_version,
            json,
            key_name,
            no_gz,
        } => {
            let endian = endian.into();
            let memory_stream_name = memory_stream_name.or_else(|| {
                (guess_memory_stream_name)
                    .then(|| try_guess_memory_stream_name(player_profile.file_name()))
                    .flatten()
            });

            let signature_stream_data = if json {
                let ctsemeta: CTSEMeta = serde_json::from_reader(BufReader::new(File::open(
                    &player_profile_extracted,
                )?))?;

                let mut signature_stream_data = Cursor::new(Vec::new());
                ctsemeta.write_options(&mut signature_stream_data, endian, ())?;
                signature_stream_data.into_inner()
            } else {
                std::fs::read(&player_profile_extracted)?
            };

            let mut writer = BufWriter::new(File::create(&player_profile)?);
            let sign_options = (!no_sign).then_some(SignOptions {
                key_ring: &key_ring,
                sign_key_name: &key_name,
                memory_stream_name: memory_stream_name.as_ref(),
                userid: userid.as_ref(),
            });
            if no_gz {
                write_signature_stream_data(
                    &mut writer,
                    endian,
                    sign_options.as_ref(),
                    signature_stream_version,
                    &signature_stream_data,
                )?;
            } else {
                write_gz_signature_stream_data(
                    &mut writer,
                    endian,
                    sign_options.as_ref(),
                    signature_stream_version,
                    &signature_stream_data,
                )?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Cursor;
    use std::path::PathBuf;

    use binrw::io::BufReader;
    use binrw::{BinRead, BinWrite, Endian};

    use crate::ctsemeta::CTSEMeta;
    use crate::signature_stream::{
        KeyRing,
        SIGN_KEY_GAME_LOCAL_NAME,
        SignOptions,
        parse_gz_signature_stream_data,
        write_gz_signature_stream_data,
    };
    use crate::try_guess_memory_stream_name;

    #[test]
    fn round_trip() {
        let endian = Endian::Little;
        let key_ring = KeyRing::default();

        let player_profile = PathBuf::from("data/PlayerProfile.dat");
        let memory_stream_name = try_guess_memory_stream_name(player_profile.file_name());
        let userid = Some("1100001075d8dea");

        // Try to read it first
        let mut reader = BufReader::new(File::open(&player_profile).unwrap());
        let signature_stream_data = parse_gz_signature_stream_data(
            &mut reader,
            endian,
            &key_ring,
            memory_stream_name.as_ref(),
            userid,
        )
        .unwrap();

        // Parse the data
        let ctsemeta =
            CTSEMeta::read_options(&mut Cursor::new(&signature_stream_data), endian, ()).unwrap();

        // Write back the data
        let mut writer = Cursor::new(Vec::new());
        CTSEMeta::write_options(&ctsemeta, &mut writer, endian, ()).unwrap();
        let signature_stream_data_again = writer.into_inner().into_boxed_slice();

        // Make sure it survived
        assert_eq!(signature_stream_data, signature_stream_data_again);

        // Write a new signature stream
        let mut writer = Cursor::new(Vec::new());
        write_gz_signature_stream_data(
            &mut writer,
            endian,
            Some(SignOptions {
                key_ring: &key_ring,
                sign_key_name: SIGN_KEY_GAME_LOCAL_NAME,
                memory_stream_name: memory_stream_name.as_ref(),
                userid: userid.as_ref(),
            })
            .as_ref(),
            5,
            &signature_stream_data,
        )
        .unwrap();
        let signature_stream = writer.into_inner().into_boxed_slice();
        let mut reader = Cursor::new(&signature_stream);

        // We cant check that the signature streams are identical so at least check that
        // the new one parses
        parse_gz_signature_stream_data(&mut reader, endian, &key_ring, memory_stream_name, userid)
            .unwrap();
    }
}
