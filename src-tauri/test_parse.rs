use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::convert::TryInto;

fn main() {
    let mut f = File::open(r"D:\Github\krkrzHXV4XP3Extractor\testfile\data.xp3").unwrap();
    let mut magic = [0u8; 11];
    f.read_exact(&mut magic).unwrap();
    let mut base_offset = 0;
    if &magic != b"XP3\r\n \n\x1A\x8B\x67\x01" {
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = vec![0u8; 1024 * 1024];
        let n = f.read(&mut buf).unwrap();
        for i in 0..(n - 11) {
            if &buf[i..i+11] == b"XP3\r\n \n\x1A\x8B\x67\x01" {
                base_offset = i as u64;
                break;
            }
        }
    }
    f.seek(SeekFrom::Start(base_offset + 0x0B)).unwrap();
    let mut off_buf = [0u8; 8];
    f.read_exact(&mut off_buf).unwrap();
    let index_offset = base_offset + u64::from_le_bytes(off_buf);
    
    f.seek(SeekFrom::Start(index_offset)).unwrap();
    let mut flag = [0u8; 1];
    f.read_exact(&mut flag).unwrap();
    
    let mut index_data = Vec::new();
    if flag[0] == 0 {
        f.read_exact(&mut off_buf).unwrap();
        let size = u64::from_le_bytes(off_buf) as usize;
        index_data.resize(size, 0);
        f.read_exact(&mut index_data).unwrap();
    } else if flag[0] == 1 {
        f.read_exact(&mut off_buf).unwrap();
        let comp_size = u64::from_le_bytes(off_buf) as usize;
        f.read_exact(&mut off_buf).unwrap();
        let orig_size = u64::from_le_bytes(off_buf) as usize;
        let mut comp = vec![0u8; comp_size];
        f.read_exact(&mut comp).unwrap();
        
        // Use an external command or just uncompress manually
        std::fs::write("index_comp.bin", &comp).unwrap();
        println!("wrote index_comp.bin, orig_size: {}", orig_size);
    }
}
