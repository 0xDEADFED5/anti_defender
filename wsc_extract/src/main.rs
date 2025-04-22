use std::convert::TryInto;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem;
use std::{env, fs};

const MZ_SIGNATURE: [u8; 2] = [b'M', b'Z'];
const PE_SIGNATURE: [u8; 4] = [b'P', b'E', 0, 0];
const E_LFANEW_OFFSET: usize = 0x3C;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct CoffHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

const COFF_HEADER_SIZE: usize = mem::size_of::<CoffHeader>();
// const UNKNOWN: u16 = 0x0;
const I386: u16 = 0x014c;
// const IA64: u16 = 0x0200;
const AMD64: u16 = 0x8664;
// const ARM: u16 = 0x01c0;
// const ARM64: u16 = 0xaa64;
// const ARMNT: u16 = 0x01c4;

fn parse_coff_header(header_bytes: &[u8]) -> Result<CoffHeader, &'static str> {
    if header_bytes.len() < COFF_HEADER_SIZE {
        return Err("Byte slice too short for COFF header");
    }
    let machine = u16::from_le_bytes(header_bytes[0..2].try_into().unwrap());
    let number_of_sections = u16::from_le_bytes(header_bytes[2..4].try_into().unwrap());
    let time_date_stamp = u32::from_le_bytes(header_bytes[4..8].try_into().unwrap());
    let pointer_to_symbol_table = u32::from_le_bytes(header_bytes[8..12].try_into().unwrap());
    let number_of_symbols = u32::from_le_bytes(header_bytes[12..16].try_into().unwrap());
    let size_of_optional_header = u16::from_le_bytes(header_bytes[16..18].try_into().unwrap());
    let characteristics = u16::from_le_bytes(header_bytes[18..20].try_into().unwrap());

    Ok(CoffHeader {
        machine,
        number_of_sections,
        time_date_stamp,
        pointer_to_symbol_table,
        number_of_symbols,
        size_of_optional_header,
        characteristics,
    })
}

fn find_coff_header_slice<'a>(data: &'a [u8]) -> Result<&'a [u8], &'static str> {
    if data.len() < E_LFANEW_OFFSET + 4 || !data.starts_with(&MZ_SIGNATURE) {
        return Err("Not a valid DOS MZ executable or too short for e_lfanew");
    }
    let e_lfanew_bytes: [u8; 4] = data[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4]
        .try_into()
        .map_err(|_| "Internal error: Failed to slice e_lfanew")?;
    let pe_header_offset = u32::from_le_bytes(e_lfanew_bytes) as usize;
    let pe_sig_start = pe_header_offset;
    let pe_sig_end = pe_sig_start + PE_SIGNATURE.len();
    if data.len() < pe_sig_end || data[pe_sig_start..pe_sig_end] != PE_SIGNATURE {
        return Err("PE signature not found");
    }
    let coff_header_start = pe_sig_end;
    let coff_header_end = coff_header_start + COFF_HEADER_SIZE;
    if data.len() < coff_header_end {
        return Err("File too short to contain the full COFF header");
    }
    Ok(&data[coff_header_start..coff_header_end])
}

fn is_machine_type(buffer: &[u8], machine_type: u16) -> bool {
    match find_coff_header_slice(&buffer) {
        Ok(coff_slice) => match parse_coff_header(coff_slice) {
            Ok(coff_header) => {
                return coff_header.machine == machine_type;
            }
            Err(_) => {
                return false;
            }
        },
        Err(_) => {
            return false;
        }
    }
}

fn get_file(
    filename: &str,
    pattern: &str,
    machine_type: u16,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = File::open(filename)?;
    let mut buffer = [0u8; 4096];
    let p = pattern.as_bytes();
    let mut offset = 0;
    let mut index = 0;
    let mut ape_index = 0;
    let mut found = false;
    loop {
        loop {
            // search down for filename
            file.seek(SeekFrom::Start(offset))?; // this will eventually return on a bad search
            file.read_exact(&mut buffer)?;
            for x in 0..4096 - p.len() {
                for y in 0..p.len() {
                    found = true;
                    if buffer[x + y] != p[y] {
                        found = false;
                        break;
                    }
                }
                if found {
                    index = offset + x as u64;
                    break;
                }
            }
            if found {
                break;
            }
            offset += 4096 - p.len() as u64;
        }
        // search up for .APE header
        let ape = [0x01, 0x41, 0x50, 0x45];
        offset = index - 4096;
        loop {
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut buffer)?;
            for x in 0..4096 - 4 {
                for y in 0..4 {
                    found = true;
                    if buffer[x + y] != ape[y] {
                        found = false;
                        break;
                    }
                }
                if found {
                    ape_index = offset + x as u64;
                    break;
                }
            }
            if found {
                break;
            }
            if offset < 4096 - 4 {
                break;
            }
            offset -= 4096 - 4;
        }
        if found {
            let mut file_len_buffer = [0u8; 4];
            let mut header_len_buffer = [0u8; 4];
            file.seek(SeekFrom::Start(ape_index + 4))?;
            file.read_exact(&mut header_len_buffer)?;
            let header_len = u32::from_le_bytes(header_len_buffer);
            file.seek(SeekFrom::Start(ape_index + 20))?;
            file.read_exact(&mut file_len_buffer)?;
            let file_len = u32::from_le_bytes(file_len_buffer);
            file.seek(SeekFrom::Start(ape_index + header_len as u64))?;
            let mut file_buffer = vec![0u8; file_len as usize];
            file.read_exact(&mut file_buffer)?;
            let mut output: Vec<u8> = Vec::new();
            lzma_rs::lzma_decompress(&mut file_buffer.as_slice(), &mut output).unwrap();
            if is_machine_type(output.as_slice(), machine_type) {
                return Ok(output);
            } else {
                println!("found {:?}, but wrong machine type. Continuing...", pattern);
                offset = index + p.len() as u64;
            }
        } else {
            return Err("APE header not found.".into());
        }
    }
}
fn main() {
    let args: Vec<String> = env::args().collect();
    let mut filename = "avast_free_antivirus_offline_setup.exe";
    if args.len() == 2 {
        filename = args[1].as_str();
    }
    let mut machine_type = AMD64;
    if cfg!(target_pointer_width = "32") {
        machine_type = I386;
    }
    println!("Scanning {:?} for wsc_proxy.exe and wsc.dll ...", filename);
    let wp = get_file(filename, "wsc_proxy.exe", machine_type);
    let mut error = false;
    match wp {
        Ok(output) => {
            fs::write("wsc_proxy.exe", output).expect("Unable to write wsc_proxy.exe!");
            println!("wsc_proxy.exe found and saved.");
        }
        Err(e) => {
            println!("Error finding wsc_proxy.exe: {:?}", e);
            error = true;
        }
    }
    let wd = get_file(filename, "wsc.dll", machine_type);
    match wd {
        Ok(output) => {
            fs::write("wsc.dll", output).expect("Unable to write wsc.dll!");
            println!("wsc.dll found and saved.");
        }
        Err(e) => {
            println!("Error finding wsc.dll: {:?}", e);
            error = true;
        }
    }
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();
    write!(stdout, "Press any key to continue...").unwrap();
    stdout.flush().unwrap();
    let _ = stdin.read(&mut [0u8]).unwrap();
    if error {
        std::process::exit(1);
    } else {
        std::process::exit(0);
    }
}
