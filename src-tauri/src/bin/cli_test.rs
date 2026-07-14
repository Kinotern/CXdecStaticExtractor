use hxv4_xp3_extractor_rust::extractor::{extract_all, ExtractOptions};

fn main() {
    let xp3_path = r"D:\Github\krkrzHXV4XP3Extractor\testfile\data.xp3";
    let drip_program_path = r"D:\Github\krkrzHXV4XP3Extractor\testfile\drip_program.json";
    let lst_path = r"D:\Github\krkrzHXV4XP3Extractor\rustsrc_release\scheme\YuzuSoft\TenshiSouzouRE-BOOT!\TenshiSouzouRE-BOOT.lst";
    let out_dir = r"D:\Github\krkrzHXV4XP3Extractor\rustsrc_release\output\data";
    
    let opt = ExtractOptions {
        xp3_path: xp3_path.into(),
        out_dir: out_dir.into(),
        drip_program_path: drip_program_path.into(),
        lst_path: Some(lst_path.into()),
    };
    
    // OVERRIDE DRIP PROGRAM IN EXTRACTOR?
    // Wait, extract_all parses drip_program inside.
    let (info, entries, index_blob) = hxv4_xp3_extractor_rust::xp3::Xp3Parser::read_archive(xp3_path).unwrap();
    println!("Total entries: {}", entries.len());
    for (i, entry) in entries.iter().take(5).enumerate() {
        println!("Entry {}: name = {}, offset = {}, size = {}", i, entry.name, entry.segments[0].offset, entry.original_size);
    }
    let hxv4_key = [
        0xe4, 0xdc, 0x1d, 0x99, 0xd9, 0xd9, 0xfb, 0x1a, 
        0xe5, 0xf7, 0x52, 0x9e, 0xe7, 0x0f, 0x84, 0x1b, 
        0xfa, 0xdb, 0x13, 0xd1, 0x2f, 0x4d, 0x22, 0xb9, 
        0x91, 0x70, 0xd6, 0xcc, 0x6a, 0x62, 0xbc, 0x54 
    ];
    let hxv4_nonce0 = [
        0xd9, 0x92, 0x30, 0xe0, 0x26, 0x23, 0xf4, 0xa0, 0xc4, 0xf2, 0x85, 0x76, 0x82, 0xb4, 0xde, 0x6d, 0xfe, 0xfe, 0x82, 0x0b, 0x57, 0x06, 0x0e, 0x50
    ];
    let hxv4_nonce1 = [
        0xb9, 0x6f, 0x89, 0x63, 0x08, 0x50, 0xdd, 0x23, 0xa1, 0x38, 0x10, 0xc7, 0x71, 0x8a, 0xd0, 0x03, 0x93, 0x6d, 0x1d, 0x4a, 0x3a, 0xe0, 0x08, 0x90
    ];

    let mut file = std::fs::File::open(xp3_path).unwrap();
    let mut blob = vec![0u8; info.size as usize];
    use std::io::Read;
    file.read_exact(&mut blob).unwrap();

    let records = hxv4_xp3_extractor_rust::crypto::parse_hxv4_table(
        &blob, &index_blob, &entries, &hxv4_key, &hxv4_nonce0, &hxv4_nonce1
    );
    println!("Records with default key: {:?}", records.is_ok());

    match extract_all(opt, |_, _| {}) {
        Ok(_) => println!("Done"),
        Err(e) => println!("Error: {}", e),
    }
}
