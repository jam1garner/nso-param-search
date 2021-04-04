#![feature(array_windows)]

use nxo_parser::NsoFile;
use binread::BinReaderExt;

use std::fs::File;
use std::io::BufReader;
use std::collections::HashMap;

use std::io::BufRead;
use std::io::Read;

use yaxpeax_arch::Decoder;
use yaxpeax_arm::armv8::a64::Operand;

fn main() {
    let mut file = BufReader::new(File::open("/home/jam/re/ult/1101/main").unwrap());
    let nso: NsoFile = file.read_le().unwrap();

    let rodata = nso.get_rodata(&mut file).unwrap();
    let hash_to_pos: HashMap<_, _> = rodata
        .array_windows()
        .enumerate()
        .map(|(i, &x)| (u32::from_le_bytes(x), i))
        .collect();

    let param_labels = BufReader::new(File::open("/home/jam/dev/ult/param-labels/ParamLabels.csv").unwrap());
    let param_labels = param_labels.lines()
        .skip(1)
        .map(|line| {
            let line = line.unwrap();
            let mut line = line.split(',');
            let (hash, label) = (line.next().unwrap(), line.next().unwrap());
            let crc = u64::from_str_radix(&hash[2..], 16).unwrap() as u32;

            (crc, label.to_owned())
        })
        .collect::<Vec<_>>();

    for (hash, label) in param_labels.iter() {
        if let Some(pos) = hash_to_pos.get(&hash) {
            println!("rodata+{:#x?} | {}", pos, label);
        }
    }
        
    let text = nso.get_text(&mut file).unwrap();
    let hash_to_pos: HashMap<_, _> = text
        .array_windows()
        .enumerate()
        .map(|(i, &x)| (u32::from_le_bytes(x), i))
        .collect();

    for (hash, label) in param_labels.iter() {
        if let Some(pos) = hash_to_pos.get(&hash) {
            println!("text+{:#x?} | {}", pos, label);
        }
    }

    let mut all_imms = std::collections::HashSet::new();

    let decoder = yaxpeax_arm::armv8::a64::InstDecoder::default();
    let mut cursor = std::io::Cursor::new(&text[..]).bytes().map(|x| x.unwrap());
    loop {
        match decoder.decode(&mut cursor) {
            Ok(instr) => {
                for op in &instr.operands {
                    match op {
                        Operand::Imm16(imm) => {
                            all_imms.insert(*imm);
                        }
                        _ => {}
                    }
                }
            }
            Err(yaxpeax_arm::armv8::a64::DecodeError::ExhaustedInput) => {
                break
            }
            _ => continue
        }
    }

    for (hash, label) in param_labels.iter() {
        let low = *hash as u16;
        let hi = (*hash >> 16) as u16;

        if all_imms.contains(&low) && all_imms.contains(&hi) {
            println!("imms found - {}", label);
        }
    }
}
