# SeriousSaveEditor

A save editor for Serious Engine games

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/widberg/SeriousSaveEditor/build.yml)](https://github.com/widberg/SeriousSaveEditor/actions)
![GitHub Release](https://img.shields.io/github/v/release/widberg/SeriousSaveEditor)
[![Release Nightly](https://img.shields.io/badge/release-nightly-5e025f?labelColor=301934)](https://nightly.link/widberg/SeriousSaveEditor/workflows/build/master)

## Support

Right now it only works with The Talos Principle since that's the only game I own, if I ever get more Serious Engine games I'll probably add support for them. I also only tested saves from the latest Steam version, but it may work with other versions. This was a weekend project, so manage expectations accordingly. The outer signature stream format used for save files is also used for some engine files like `The Talos Principle\Content\Talos\{All.dat, DLC.dat}`.

| Year | Game                                 | Serious Engine Version | Status |
|------|--------------------------------------|------------------------|--------|
| 2001 | Serious Sam: The First Encounter     | 1                      | ❌      |
| 2002 | Serious Sam: The Second Encounter    | 1                      | ❌      |
| 2002 | Serious Sam: Xbox                    | 1                      | ❌      |
| 2005 | Serious Sam 2                        | 2                      | ❌      |
| 2009 | Serious Sam HD: The First Encounter  | 3                      | ❌      |
| 2009 | Serious Sam HD: The Second Encounter | 3                      | ❌      |
| 2011 | Serious Sam 3: BFE                   | 3.5                    | ❌      |
| 2014 | The Talos Principle                  | 4                      | ✔      |

## Usage

Make sure to back up any save files, and backup save files, before messing with them! It is also probably best to disable cloud saves and go offline to avoid Steam overwriting your files while messing with them.

You can extract a save file to JSON with the following command. The `-j` argument specifies the output format to be JSON instead of the default binary. The `-u` argument is optional and if supplied will check the save file signature using that userid. For Steam save files https://www.steamidfinder.com/ may be helpful in finding your lowercase steamID64 (Hex). I'll admit the user experience isn't great even with the JSON format, it's a complicated format and I only have so much time to spend on fun stuff so you get what you get.

```console
$ SeriousSaveEditor x PlayerProfile.dat PlayerProfile.dat.json -j -u 1100001075d8dea
```

If you're interested in figuring out more about the format and what individual fields are for, I recommend using [difftastic](https://github.com/Wilfred/difftastic) to compare JSON extracted save files at different points in the game, i.e. before and after opening a door. It looks like in older versions of the save format field name strings were used instead of IDs, I might try downpatching my copy to see if I can get anything useful out of that or if it's left over from previous games. Also, since the game is extremely backwards compatible when it comes to loading old saves, it's possible these strings are still in the game if old saves used them.

Once you are done messing with it you can create a new save file from the JSON with the below command, with the options listed it will be as if the game itself created the save. Again the userid is optional. If you supply one the game will check for it and it must match for the save to load. By default this tool will not guess if the save was for the unrestricted version or not, and so the game wont check the executable when loading the save. You can pass `-g` to lock the save to a particular executable. Or pass `-m "<memory stream:PlayerProfile_unrestricted.dat>"` or `-m "<memory stream:PlayerProfile.dat>"` to force a particular stream name.

Note that the backup saves do not include the `.bkp` extension in the memory stream name. Also note that the backup files are just older copies of the non-backup file and not special in any way. You must make sure a backup file exists with the correct name even if it is an empty file.

```console
$ SeriousSaveEditor c PlayerProfile.dat.json PlayerProfile.dat -j -g -u 1100001075d8dea
```

### Save Transfers

If you want to use someone else's save or make a save that any userid and executable can load you can extract and recreate it without specifying a memory stream name or userid. These commands will work even if the JSON parser doesn't work for your save file since they use the unparsed binary format.

```console
$ SeriousSaveEditor x PlayerProfile.dat PlayerProfile.dat.bin
$ SeriousSaveEditor c PlayerProfile.dat.bin PlayerProfile.dat
```

Keep in mind that the next time the game saves it will be signed normally.

### Other Engine Files

The `The Talos Principle\Content\Talos\{All.dat, DLC.dat}` files can be modified using this tool by passing the `--no-gz` option. This works because those files are the same format as save files but not compressed. Also note that the memory stream names for these files are `Content/Talos/All.dat` and `Content/Talos/DLC.dat`.

```console
$ SeriousSaveEditor x All.dat All.dat.json -j --no-gz
$ SeriousSaveEditor c All.dat.json All.dat -j --no-gz
```

## Issues

If you find a save file that fails to parse or yields unexpected results, please open an issue with the offending save file attached so I can add it to my test corpus. I don't have a large sample size of save files to test with, so I'm sure there are edge cases that I haven't encountered yet.

Also, if you have or want any information about Serious Engine internals, please feel free to reach out. If you're in a modding Discord for any Serious Engine games send me an invite.

## Patterns

I've left some [ImHex](https://imhex.werwolv.net/) patterns I made while working on this in the `patterns` directory. They're good for debugging but the Rust code is definitely the source of truth.

## Prior Work

* watto studios
  - [Viewer_ZIP_PK_TEX_SIGSTRM12GIS](https://www.watto.org/specs.html?specs=Viewer_ZIP_PK_TEX_SIGSTRM12GIS)
  - [Viewer_ZIP_PK_TEX_SIGSTRM12GIS.java](https://github.com/wattostudios/GameExtractor/blob/master/src/org/watto/ge/plugin/viewer/Viewer_ZIP_PK_TEX_SIGSTRM12GIS.java)
* bmaupin
  - [talos-principle-save-file.md](https://gist.github.com/bmaupin/a9f55a4fd167aad40857db2a26e1672f#file-talos-principle-save-file-md)

## Getting Started

### Prerequisites

* [Rust](https://www.rust-lang.org/)

### Checkout

```sh
git clone https://github.com/widberg/SeriousSaveEditor.git
cd SeriousSaveEditor
```

### Build

```sh
cargo build --release
```

### Test

```sh
cargo test
```
