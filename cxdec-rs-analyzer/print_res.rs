use pelite::pe32::{Pe, PeFile};
fn main() {
    let data = std::fs::read(r"D:\Github\krkrzHXV4XP3Extractor\rustsrc_release\scheme\YuzuSoft\tenshi\tenshi[hf]\tenshi_sz.exe").unwrap();
    let pe = PeFile::from_bytes(&data).unwrap();
    let root = pe.resources().unwrap().root().unwrap();
    for (name1, dir1) in root.entries().filter_map(|e| e.name().ok().zip(e.entry().ok()?.dir())) {
        for (name2, _dir2) in dir1.entries().filter_map(|e| e.name().ok().zip(e.entry().ok()?.dir())) {
            println!("{:?} {:?}", name1, name2);
        }
    }
}
