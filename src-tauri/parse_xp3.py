import sys, struct, zlib

f = open(r"D:\Github\krkrzHXV4XP3Extractor\testfile\data.xp3", "rb")
magic = f.read(11)
base = 0
if magic != b"XP3\r\n \n\x1A\x8B\x67\x01":
    f.seek(0)
    data = f.read(1024*1024)
    idx = data.find(b"XP3\r\n \n\x1A\x8B\x67\x01")
    if idx != -1:
        base = idx
f.seek(base + 0x0B)
idx_offset = struct.unpack("<Q", f.read(8))[0] + base
f.seek(idx_offset)
flag = f.read(1)[0]
if flag == 0:
    size = struct.unpack("<Q", f.read(8))[0]
    index_data = f.read(size)
else:
    csize = struct.unpack("<Q", f.read(8))[0]
    osize = struct.unpack("<Q", f.read(8))[0]
    index_data = zlib.decompress(f.read(csize))

print("Index length:", len(index_data))
print("Has Hxv4?", b"Hxv4" in index_data)
if b"Hxv4" in index_data:
    idx = index_data.find(b"Hxv4")
    print("Hxv4 chunk offset in index:", idx)
    chunk_size = struct.unpack("<Q", index_data[idx+4:idx+12])[0]
    print("Hxv4 chunk size:", chunk_size)

    # Let's see if there is any other string that could trip up from_utf8
    tags = []
    cursor = 0
    while cursor + 12 <= len(index_data):
        tag = index_data[cursor:cursor+4]
        csize = struct.unpack("<Q", index_data[cursor+4:cursor+12])[0]
        tags.append(tag)
        try:
            tag.decode('utf-8')
        except:
            print("INVALID UTF-8 TAG:", tag)
        cursor += 12 + csize
    print("Tags:", tags)
