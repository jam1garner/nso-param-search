#![feature(array_windows, array_chunks)]

use nxo_parser::NsoFile;
use binread::BinReaderExt;

use std::fs::File;
use std::io::BufReader;
use std::collections::HashMap;

use std::io::BufRead;

fn write_start() {
    println!("flatapi = ghidra.program.flatapi.FlatProgramAPI(currentProgram)");
}

fn output(section: &str, offset: usize, label: &str) {
    println!("flatapi.createLabel(currentProgram.getMemory().getBlock('.{}').getStart().add({:#x?}), 'hash40_{}', False)", section, offset, label);
}

fn main() {
    write_start();
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
            output("rodata", *pos, label);
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
            output("text", *pos, label);
        }
    }
}
