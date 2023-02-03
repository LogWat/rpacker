mod encode;
use encode::*;

use std;
use std::io::{Error};
use std::process::{Command};

use exe::pe::{PE, VecPE, Buffer};
use exe::types::*;
use exe::headers::*;

use clap::Parser;

fn align(value: u32, alignment: u32) -> u32 {
    let mut result = value;
    if result % alignment != 0 {
        result += alignment - (result % alignment);
    }
    result
}

fn check_pe(pefile: &VecPE) -> Result<(), Error> {
    let dos_header = pefile.get_valid_dos_header().unwrap();
    if dos_header.e_magic != DOS_SIGNATURE {
        return Err(Error::new(std::io::ErrorKind::InvalidData, "Invalid DOS magic"));
    }

    let nt_header = pefile.get_valid_nt_headers().unwrap();
    let signature = match nt_header {
        NTHeaders::NTHeaders32(x) => x.signature,
        NTHeaders::NTHeaders64(x) => x.signature,
    };
    if signature != NT_SIGNATURE {
        return Err(Error::new(std::io::ErrorKind::InvalidData, "Invalid PE magic"));
    }

    Ok(())
}


fn pack(pefile: &VecPE, unpacker: &VecPE) -> Result<VecPE, Error> {
    let unpacker = unpacker.clone();
    let mut pefile = pefile.clone();


    println!("[*] Allocating virtual space for post-complex data section...");
    let mut base = 0xffffffff;
    let mut last = 0;
    let section_table = pefile.get_section_table().unwrap();
    for i in 0..section_table.len() {
        if base > u32::from(section_table[i].virtual_address) {
            base = u32::from(section_table[i].virtual_address);
        }
        if last < u32::from(section_table[i].virtual_address) + u32::from(section_table[i].virtual_size) {
            last = u32::from(section_table[i].virtual_address) + u32::from(section_table[i].virtual_size);
        }
    }

    // 上記の範囲を確保できる領域をVirtualSizeで確保するセクションを挿入した
    // 新しいPEファイルを作成する
    let mut output_pefile = VecPE::new_disk(0x400);
    output_pefile.write_ref(0, &ImageDOSHeader::default()).unwrap();
    let e_lfanew = output_pefile.e_lfanew().unwrap();
    output_pefile.write_ref(e_lfanew.into(), &ImageNTHeaders32::default()).unwrap();
        
    let section_align= match output_pefile.get_valid_mut_nt_headers().unwrap() {
        NTHeadersMut::NTHeaders32(x) => {
            x.file_header.time_date_stamp = 0;
            x.optional_header.section_alignment
        },
        NTHeadersMut::NTHeaders64(_x) => {
            return Err(Error::new(std::io::ErrorKind::InvalidData, "Not supported 64bit"));
        }
    };
    let mut new_section = ImageSectionHeader::default();
    new_section.set_name(Some("")); // どうせ書き換える
    let new_section = output_pefile.append_section(&mut new_section).unwrap();
    new_section.virtual_size = align(last - base, section_align);
    new_section.virtual_address = RVA(base);
    new_section.characteristics = SectionCharacteristics::MEM_READ // decode後のデータを格納するセクションなので読み書き可能
        | SectionCharacteristics::MEM_WRITE
        | SectionCharacteristics::CNT_UNINITIALIZED_DATA;

    // unpackerのVAが最も小さいセクションのrvaを取得
    let section_table = unpacker.get_section_table().unwrap();
    let mut min_unpack_rva = 0xffffffff;
    for i in 0..section_table.len() {
        if min_unpack_rva > u32::from(section_table[i].virtual_address) {
            min_unpack_rva = u32::from(section_table[i].virtual_address);
        }
    }

    // unpack後のデータが格納されるセクションを確保した状態のunpackerを再コンパイルにより作成
    let mut params = Vec::new();
    // image_baseをpackするPEファイルのimage_baseにあわせる
    let imgbase = pefile.get_image_base().unwrap() as u32;
    params.push(format!("-Wl,--image-base=0x{:x}", &imgbase));
    // データ展開領域に続くセクションのVAを調整
    let shift = (base + u32::from(new_section.virtual_size)) - min_unpack_rva;
    for i in 0..section_table.len() {
        let section_rva = imgbase + u32::from(section_table[i].virtual_address) + shift;
        params.push(format!("-Wl,--section-start={}=0x{:x}", section_table[i].name.as_str().unwrap(), section_rva));
    }
    compile_unpacker("unpacker\\unpacker.c", "unpacker\\unpacker_4nrlc.exe", &params).unwrap();

    let sunpacker = VecPE::from_disk_file("unpacker\\unpacker_4nrlc.exe").unwrap();
    let s_nth = match sunpacker.get_valid_nt_headers().unwrap() {
        NTHeaders::NTHeaders32(x) => x,
        NTHeaders::NTHeaders64(_x) => {
            return Err(Error::new(std::io::ErrorKind::InvalidData, "64bit unpacker is not supported"));
        },
    };

    let nt_header = output_pefile.get_valid_mut_nt_headers().unwrap();
    match nt_header {
        NTHeadersMut::NTHeaders32(x) => {
            x.optional_header.image_base = s_nth.optional_header.image_base;
            x.optional_header.size_of_image = s_nth.optional_header.size_of_image;
            x.optional_header.address_of_entry_point = s_nth.optional_header.address_of_entry_point;
            x.optional_header.section_alignment = s_nth.optional_header.section_alignment;
            x.optional_header.file_alignment = s_nth.optional_header.file_alignment;
            x.optional_header.dll_characteristics.remove(DLLCharacteristics::DYNAMIC_BASE);
        },
        NTHeadersMut::NTHeaders64(_x) => {
            return Err(Error::new(std::io::ErrorKind::InvalidData, "Not supported"));
        },
    }

    // copy data directories
    let data_dir_table = output_pefile.get_mut_data_directory_table().unwrap();
    let s_data_dir_table = sunpacker.get_data_directory_table().unwrap();
    for i in 0..data_dir_table.len() {
        data_dir_table[i].virtual_address = s_data_dir_table[i].virtual_address;
        data_dir_table[i].size = s_data_dir_table[i].size;
    }

    // copy section headers
    let s_section_table = sunpacker.get_section_table().unwrap();
    for i in 0..s_section_table.len() {
        output_pefile.append_section(&s_section_table[i]).unwrap();
            
        let section_offset = s_section_table[i].pointer_to_raw_data;
        let section_size = s_section_table[i].size_of_raw_data;
        let (base, last) = (u32::from(section_offset), u32::from(section_offset) + section_size);
        let section_data: &[u8] = &sunpacker[base as usize..last as usize];
            
        let output_section = output_pefile.get_section_table().unwrap()[i + 1];
        let output_section_offset = output_section.pointer_to_raw_data;
            
        output_pefile.resize(output_pefile.len() + u32::from(output_section_offset) as usize + section_size as usize, 0);
        output_pefile.write(output_section_offset.into(), section_data).unwrap();
    }

    let mut unpacker = output_pefile.clone();

    match unpacker.get_valid_mut_nt_headers().unwrap() {
        NTHeadersMut::NTHeaders32(x) => {
            x.optional_header.size_of_headers += x.optional_header.file_alignment * 2;
            x.file_header.pointer_to_symbol_table = Offset::from(0);
            x.file_header.number_of_symbols = 0;
        },
        NTHeadersMut::NTHeaders64(_x) => return Err(Error::new(std::io::ErrorKind::InvalidData, "Not support 64bit")),
    };

    // add new section (encoded pefile)
    let mut new_section = ImageSectionHeader::default();
    new_section.set_name(Some(".rp0"));
    let new_section = unpacker.append_section(&mut new_section).unwrap();

    // pack pefile
    let mut pefile_data: &mut [u8] = &mut pefile[..];
    println!("[+] Packing...");
    print!("      original size: {} byte ==> ", pefile_data.len());
    let encoded = encode(&mut pefile_data);
    let encoded_data = encoded.as_raw_slice();

    new_section.virtual_size = encoded_data.len() as u32;
    new_section.size_of_raw_data = new_section.virtual_size;
    new_section.characteristics = SectionCharacteristics::MEM_READ | SectionCharacteristics::CNT_INITIALIZED_DATA;

    let new_section_offset = u32::from(new_section.pointer_to_raw_data) as usize;
    let new_section_size = new_section.size_of_raw_data as usize;
    unpacker.append(&encoded_data);
    // なぜかappendで追加されたデータ場所がおかしくなるので、その場合はかき直す
    if unpacker[new_section_offset..new_section_offset+new_section_size] != encoded_data[..] {
        for section in unpacker.get_section_table().unwrap() {
            if section.name.as_str().unwrap() == ".rp0" {
                let offset = u32::from(section.pointer_to_raw_data) as usize;
                let size = section.size_of_raw_data as usize;
                unpacker.resize(offset + size, 0);
                unpacker[offset..offset+size].copy_from_slice(&encoded_data);
                break;
            }
        }
    }
    
    // rename sections
    let section_table = unpacker.get_mut_section_table().unwrap();
    let section_table_size = section_table.len();
    for i in 0..section_table.len() {
        let section = &mut section_table[i];
        let name = section.name.as_str().unwrap();
        if name != ".rp0" {
            section.set_name(Some(&format!(".rp{}", section_table_size - i - 1)));
        }
    }

    unpacker.pad_to_alignment().unwrap();
    unpacker.fix_image_size().unwrap();

    println!("packed size: {} byte ({:.2}%)", unpacker.len(), unpacker.len() as f32 / pefile_data.len() as f32 * 100.0);
    
    Ok(unpacker)
}

fn compile_unpacker(input: &str, output: &str, params: &Vec<String>) -> Result<(), Error> {
    let mut cmd = Command::new("gcc");
    cmd.arg(input).arg("-o").arg(output);
    for param in params {
        cmd.arg(param);
    }
    let default_params = 
    ["-Wl,--entry=__start", "-nostartfiles", "-nostdlib",
    "-fno-ident", "-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
    "-lkernel32", "-Os", "-Wl,-s"];
    for param in default_params.iter() {
        cmd.arg(param);
    }

    println!("\n[*] Compiling unpacker...");
    print!("      cmd: {}", cmd.get_program().to_str().unwrap());
    for arg in cmd.get_args() {
        print!(" {}", arg.to_str().unwrap());
    }
    println!("\n");

    let res = cmd.output().expect("failed to execute process");
    if !res.status.success() {
        println!("Error: {}", String::from_utf8_lossy(&res.stderr));
        return Err(Error::new(std::io::ErrorKind::InvalidData, "Failed to compile unpacker"));
    }

    Ok(())
}

fn packed_check(pefile: &VecPE) -> bool {
    let section_table = pefile.get_section_table().unwrap();
    for i in 0..section_table.len() {
        if section_table[i].name.as_str().unwrap() == ".rp0" {
            return true;
        }
    }
    return false;
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Opts {
    #[clap(short = 'f', long = "file", help = "Input file")]
    file: String,
    #[clap(short = 'o', long = "out", help = "Output file (default is packed.exe)", default_value = "packed.exe")]
    output: String,
}

fn main() {
    let opts = Opts::parse();

    let ifilename = opts.file;
    let ofilename = opts.output;

    let pefile = VecPE::from_disk_file(ifilename).unwrap();
    match check_pe(&pefile) {
        Ok(_) => {},
        Err(e) => println!("Error: {}", e),
    }

    if packed_check(&pefile) {
        println!("Already packed");
        return;
    }

    let arch = pefile.get_arch().unwrap();
    match arch {
        Arch::X86 => println!(""),
        Arch::X64 => {
            println!("64bit is not supported");
            return;
        }
    }

    let unpacker_filename = "unpacker/unpacker.exe";
    let unpacker_source = "unpacker/unpacker.c";
    compile_unpacker(unpacker_source, unpacker_filename, &Vec::new()).unwrap();
    let unpacker = VecPE::from_disk_file("unpacker/unpacker.exe").unwrap();
    let packed = pack(&pefile, &unpacker).unwrap();

    packed.save(&ofilename).unwrap();
}
