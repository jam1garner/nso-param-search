#![feature(array_windows, array_chunks)]

use nxo_parser::NsoFile;
use binread::BinReaderExt;

use std::fs::File;
use std::io::BufReader;
use std::collections::HashMap;

use std::io::BufRead;
use std::io::Read;

use aarch64_decode::{decode_a32, decode_a64, Instr};

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

    let mut all_imms = HashMap::new();

    let text_iter = text
            .array_chunks()
            .enumerate()
            .step_by(4)
            .filter_map(|(i, &instr)| Some((i, {
                let instr = u32::from_be_bytes(instr);
                decode_a32(instr)
                    .or_else(|| decode_a64(instr))?
            })));

    for (i, instr) in text_iter.take(1000) {
        println!("{:08x} | {:?}", i, instr);
        match instr {
            Instr::Movn64Movewide { imm16, .. } => {
                all_imms.insert(imm16, i);
            }
            _ => ()
        }
    }

    for (hash, label) in param_labels.iter() {
        let low = (*hash & 0xFFFF) as u16;
        let hi = ((*hash >> 16) & 0xFFFF) as u16;

        if let Some(pos) = all_imms.get(&low) {
            //println!("{} low - {:#x?}", label, pos);
        } 

        if let Some(pos) = all_imms.get(&hi) {
            //println!("{} hi - {:#x?}", label, pos);
        } 

        //if all_imms.contains(&low) && all_imms.contains(&hi) {
        //    println!("imms found - {}", label);
        //}
        //else if all_imms.contains(&hash) {
        //    println!("single imm found - {}", label);
        //} else if all_imms.contains(&low) || all_imms.contains(&hi) {
        //    println!("half found - {}", label);
        //}
    }
}
