#![feature(array_windows, array_chunks)]

use binread::BinReaderExt;
use nxo_parser::NsoFile;
use structopt::StructOpt;

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;

use std::io::BufRead;
use std::path::PathBuf;

use std::convert::TryInto;

use multimap::MultiMap;

fn write_start() {
    println!("flatapi = ghidra.program.flatapi.FlatProgramAPI(currentProgram)");
}

fn output(section: &str, offset: usize, label: &str) {
    println!("flatapi.createLabel(currentProgram.getMemory().getBlock('.{}').getStart().add({:#x?}), 'hash40_{}', False)", section, offset, label);
}

fn crc32(string: &str) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(string.as_ref());
    hasher.finalize()
}

fn hash40(string: &str) -> u64 {
    ((string.len() as u64) << 32) | (crc32(string) as u64)
}

#[derive(StructOpt)]
struct Args {
    nso_file: PathBuf,
    param_labels: PathBuf,
    arc_labels: PathBuf,
}

fn get_labels_crc32(args: &Args) -> Vec<(u32, String)> {
    BufReader::new(File::open(&args.param_labels).unwrap())
        .lines()
        .skip(1)
        .map(|line| {
            let line = line.unwrap();
            let mut line = line.split(',');
            let (hash, label) = (line.next().unwrap(), line.next().unwrap());
            let crc = u64::from_str_radix(&hash[2..], 16).unwrap() as u32;

            (crc, label.to_owned())
        })
        .chain(
            BufReader::new(File::open(&args.arc_labels).unwrap())
                .lines()
                .map(|line| {
                    let line = line.unwrap();
                    let line = line.trim();

                    (crc32(&line), line.to_owned())
                })
        )
        .collect()
}

fn get_labels_hash40(args: &Args) -> Vec<(u64, String)> {
    BufReader::new(File::open(&args.param_labels).unwrap())
        .lines()
        .skip(1)
        .map(|line| {
            let line = line.unwrap();
            let mut line = line.split(',');
            let (hash, label) = (line.next().unwrap(), line.next().unwrap());
            let hash40 = u64::from_str_radix(&hash[2..], 16).unwrap();

            (hash40, label.to_owned())
        })
        .chain(
            BufReader::new(File::open(&args.arc_labels).unwrap())
                .lines()
                .map(|line| {
                    let line = line.unwrap();
                    let line = line.trim();

                    (hash40(&line), line.to_owned())
                })
        )
        .collect()
}

fn main() {
    let args = Args::from_args();
    write_start();
    let mut file = BufReader::new(File::open(&args.nso_file).unwrap());
    let nso: NsoFile = file.read_le().unwrap();

    let rodata = nso.get_rodata(&mut file).unwrap();
    let hash_to_pos: MultiMap<_, _> = rodata
        .array_windows()
        .enumerate()
        .map(|(i, &x)| (u32::from_le_bytes(x), i))
        .collect();

    let param_labels = get_labels_crc32(&args);

    for (hash, label) in param_labels.iter() {
        if let Some(positions) = hash_to_pos.get_vec(&hash) {
            for pos in positions {
                output("rodata", *pos, label);
            }
        }
    }

    let text = nso.get_text(&mut file).unwrap();
    let hash_to_pos: MultiMap<_, _> = text
        .array_windows()
        .enumerate()
        .map(|(i, &x)| (u32::from_le_bytes(x), i))
        .collect();

    for (hash, label) in param_labels.iter() {
        if let Some(positions) = hash_to_pos.get_vec(&hash) {
            for pos in positions {
                output("text", *pos, label);
            }
        }
    }

    let hash_to_pos: MultiMap<_, _> = text.windows(0xc)
        .enumerate()
        .step_by(4)
        .filter_map(|(pos, instrs)| {
            let instrs = [
                u32::from_le_bytes(instrs[..4].try_into().unwrap()),
                u32::from_le_bytes(instrs[4..8].try_into().unwrap()),
                u32::from_le_bytes(instrs[8..].try_into().unwrap()),
            ];

            match (MovImm::decode(instrs[0]), Movk::decode(instrs[1]), Movk::decode(instrs[2])) {
                (Some(mov), Some(movk16), Some(movk32)) => {
                    // all use same register
                    if mov.rd != movk16.rd || mov.rd != movk32.rd {
                        return None
                    }

                    // 0, 16, 32 shift
                    if mov.shift != 0 || movk16.shift != 16 || movk32.shift != 32 {
                        return None
                    }

                    let possible_hash40 = ((movk32.imm16 as u64) << 32)
                        | ((movk16.imm16 as u64) << 16)
                        | (mov.imm16 as u64);

                    Some((possible_hash40, pos))
                }
                _ => None
            }
        })
        .collect();

    let param_labels = get_labels_hash40(&args);

    for (hash, label) in param_labels.iter() {
        if let Some(positions) = hash_to_pos.get_vec(&hash) {
            for pos in positions {
                output("text", *pos, label);
            }
        }
    }
}

struct MovImm {
    imm16: u16,
    rd: u8,
    shift: u8,
    is_64_bit: bool,
}

impl MovImm {
    const MASK: u32 = 0b0_11_111111_00_0000000000000000_00000;
    const MASKED: u32 = 0b0_10_100101_00_0000000000000000_00000;

    fn decode(instr: u32) -> Option<Self> {
        if instr & Self::MASK == Self::MASKED {
            let rd = (instr & 0b11111) as u8;
            let imm16 = (instr >> 5) as u16;
            let hw = ((instr >> 21) & 0b11) as u8;
            let shift = hw * 16;

            let is_64_bit = (instr >> 31) == 1;

            Some(Self { rd, imm16, shift, is_64_bit })
        } else {
            None
        }
    }
}

struct Movk {
    imm16: u16,
    rd: u8,
    shift: u8,
    is_64_bit: bool,
}

impl Movk {
    const MASK: u32 = 0b0_11_111111_00_0000000000000000_00000;
    const MASKED: u32 = 0b0_11_100101_00_0000000000000000_00000;

    fn decode(instr: u32) -> Option<Self> {
        if instr & Self::MASK == Self::MASKED {
            let rd = (instr & 0b11111) as u8;
            let imm16 = (instr >> 5) as u16;
            let hw = ((instr >> 21) & 0b11) as u8;
            let shift = hw * 16;

            let is_64_bit = (instr >> 31) == 1;

            Some(Self { rd, imm16, shift, is_64_bit })
        } else {
            None
        }
    }
}
