use byteorder::{LittleEndian, ReadBytesExt};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use flate2::read::ZlibDecoder;

const XP3_MAGIC: &[u8] = b"XP3\r\n \n\x1A\x8b\x67\x01";

#[derive(Debug, Clone)]
pub struct Xp3Segment {
    pub flags: u32,
    pub offset: u64,
    pub original_size: u64,
    pub archived_size: u64,
}

impl Xp3Segment {
    pub fn is_compressed(&self) -> bool {
        (self.flags & 1) != 0
    }
}

#[derive(Debug, Clone)]
pub struct Xp3Entry {
    pub name: String, // Kept as String for simplicity; UTF-16 to UTF-8
    pub flags: u32,
    pub original_size: u64,
    pub archived_size: u64,
    pub adler32: u32,
    pub segments: Vec<Xp3Segment>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Xp3ArchiveInfo {
    pub path: PathBuf,
    pub size: u64,
    pub entry_count: usize,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum Xp3Error {
    Io(std::io::Error),
    InvalidMagic,
    InvalidIndex,
    CompressionError,
    Utf16Error,
}

impl From<std::io::Error> for Xp3Error {
    fn from(e: std::io::Error) -> Self {
        Xp3Error::Io(e)
    }
}

pub struct Xp3Parser;

impl Xp3Parser {
    pub fn read_archive<P: AsRef<Path>>(path: P) -> Result<(Xp3ArchiveInfo, Vec<Xp3Entry>, Vec<u8>), Xp3Error> {
        let mut file = File::open(&path)?;
        let file_size = file.metadata()?.len();

        let mut magic = [0u8; 11];
        file.read_exact(&mut magic)?;
        if magic != XP3_MAGIC {
            return Err(Xp3Error::InvalidMagic);
        }

        let mut header_offset = file.read_u64::<LittleEndian>()?;
        
        // Minor correction logic for specific XP3 files
        if header_offset == 0x17 && file_size >= 0x28 {
            file.seek(SeekFrom::Start(0x20))?;
            let candidate = file.read_u64::<LittleEndian>()?;
            if candidate > 0 && candidate < file_size {
                header_offset = candidate;
            }
        }

        if header_offset >= file_size {
            return Err(Xp3Error::InvalidIndex);
        }

        file.seek(SeekFrom::Start(header_offset))?;
        let flag = file.read_u8()?;

        let mut index_data = Vec::new();
        if flag == 0 {
            let index_size = file.read_u64::<LittleEndian>()?;
            let mut chunk = vec![0u8; index_size as usize];
            file.read_exact(&mut chunk)?;
            index_data = chunk;
        } else if flag == 1 {
            let comp_size = file.read_u64::<LittleEndian>()?;
            let orig_size = file.read_u64::<LittleEndian>()?;
            let mut chunk = vec![0u8; comp_size as usize];
            file.read_exact(&mut chunk)?;
            
            let mut decoder = ZlibDecoder::new(&chunk[..]);
            decoder.read_to_end(&mut index_data)?;
            if index_data.len() as u64 != orig_size {
                return Err(Xp3Error::CompressionError);
            }
        } else {
            return Err(Xp3Error::InvalidIndex);
        }

        let entries = Self::parse_entries(&index_data)?;
        
        let info = Xp3ArchiveInfo {
            path: path.as_ref().to_path_buf(),
            size: file_size,
            entry_count: entries.len(),
        };

        Ok((info, entries, index_data))
    }

    fn parse_entries(index: &[u8]) -> Result<Vec<Xp3Entry>, Xp3Error> {
        let mut entries = Vec::new();
        let mut cursor = 0;

        while cursor + 12 <= index.len() {
            let tag = &index[cursor..cursor + 4];
            let chunk_size = u64::from_le_bytes(index[cursor + 4..cursor + 12].try_into().unwrap()) as usize;
            cursor += 12;

            if cursor + chunk_size > index.len() {
                break;
            }

            if tag == b"File" {
                let mut entry = Xp3Entry {
                    name: String::new(),
                    flags: 0,
                    original_size: 0,
                    archived_size: 0,
                    adler32: 0,
                    segments: Vec::new(),
                };

                let mut sub_cursor = cursor;
                let end_sub = cursor + chunk_size;

                while sub_cursor + 12 <= end_sub {
                    let sub_tag = &index[sub_cursor..sub_cursor + 4];
                    let sub_size = u64::from_le_bytes(index[sub_cursor + 4..sub_cursor + 12].try_into().unwrap()) as usize;
                    sub_cursor += 12;

                    if sub_cursor + sub_size > end_sub {
                        break;
                    }

                    let body = &index[sub_cursor..sub_cursor + sub_size];
                    if sub_tag == b"info" && sub_size >= 22 {
                        entry.flags = u32::from_le_bytes(body[0..4].try_into().unwrap());
                        entry.original_size = u64::from_le_bytes(body[4..12].try_into().unwrap());
                        entry.archived_size = u64::from_le_bytes(body[12..20].try_into().unwrap());
                        
                        let name_len = u16::from_le_bytes(body[20..22].try_into().unwrap()) as usize;
                        if 22 + name_len * 2 <= sub_size {
                            let name_bytes = &body[22..22 + name_len * 2];
                            let utf16_chars: Vec<u16> = name_bytes
                                .chunks_exact(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .collect();
                            
                            entry.name = String::from_utf16(&utf16_chars)
                                .map_err(|_| Xp3Error::Utf16Error)?;
                        }
                    } else if sub_tag == b"segm" {
                        let mut seg_off = 0;
                        while seg_off + 28 <= sub_size {
                            let seg = Xp3Segment {
                                flags: u32::from_le_bytes(body[seg_off..seg_off + 4].try_into().unwrap()),
                                offset: u64::from_le_bytes(body[seg_off + 4..seg_off + 12].try_into().unwrap()),
                                original_size: u64::from_le_bytes(body[seg_off + 12..seg_off + 20].try_into().unwrap()),
                                archived_size: u64::from_le_bytes(body[seg_off + 20..seg_off + 28].try_into().unwrap()),
                            };
                            entry.segments.push(seg);
                            seg_off += 28;
                        }
                    } else if sub_tag == b"adlr" && sub_size >= 4 {
                        entry.adler32 = u32::from_le_bytes(body[0..4].try_into().unwrap());
                    }

                    sub_cursor += sub_size;
                }
                entries.push(entry);
            }

            cursor += chunk_size;
        }

        Ok(entries)
    }
}
