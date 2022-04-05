use clap::{App, Arg};
use easy_fs::layout::{DiskInodeType, FATDirEnt};
use easy_fs::{BlockDevice, EasyFileSystem, Inode};
use std::fs::{read_dir, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::uninitialized;
use std::string;
use std::sync::Arc;
use std::sync::Mutex;
const BLOCK_SZ: usize = 512;

struct BlockFile(Mutex<File>);

impl BlockDevice for BlockFile {
    fn read_block(&self, block_id: usize, buf: &mut [u8]) {
        assert_eq!(buf.len() % BLOCK_SZ, 0);
        let mut file = self.0.lock().unwrap();
        file.seek(SeekFrom::Start((block_id * BLOCK_SZ) as u64))
            .expect("Error when seeking!");
        assert_eq!(file.read(buf).unwrap(), BLOCK_SZ, "Not a complete block!");
    }

    fn write_block(&self, block_id: usize, buf: &[u8]) {
        assert_eq!(buf.len() % BLOCK_SZ, 0);
        let mut file = self.0.lock().unwrap();
        file.seek(SeekFrom::Start((block_id * BLOCK_SZ) as u64))
            .expect("Error when seeking!");
        assert_eq!(file.write(buf).unwrap(), BLOCK_SZ, "Not a complete block!");
    }
}

fn main() {
    easy_fs_pack().expect("Error when packing easy-fs!");
}

fn easy_fs_pack() -> std::io::Result<()> {
    let matches = App::new("EasyFileSystem packer")
        .arg(
            Arg::with_name("image")
                .short("i")
                .long("image")
                .takes_value(true)
                .help("Executable source dir(with backslash)"),
        )
        .get_matches();
    let image_path = if let Some(i) = matches.value_of("image") {
        i
    } else {
        "/home/dragon/Documents/EduDept/Computer/MyCode/rCore/fat32/easy-fs-fuse/fat32.img"
    };

    println!("image_path = {}", image_path);
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(image_path)
        .unwrap();
    let block_file = Arc::new(BlockFile(Mutex::new(f)));
    let i = EasyFileSystem::open(block_file);
    println!(
        "data_area_start_block: {}, \nsec_per_clus: {}, \nbyts_per_clus: {}, \nroot_clus:{}",
        i.data_area_start_block, i.sec_per_clus, i.byts_per_clus, i.root_clus
    );
    let rt = Inode::new(
        i.root_clus as usize,
        DiskInodeType::File,
        None,
        None,
        i.clone(),
    );
    println!("size:{:?}", rt.size);

    let mut ent = FATDirEnt::empty();
    println!(
        "{},name: {}, size:{}",
        rt.read_at_block_cache(0, ent.as_bytes_mut()),
        ent.get_name(),
        rt.file_size()
    );

    /*
    // 4MiB, at most 4095 files
    let root_inode = Arc::new(EasyFileSystem::root_inode(&efs));
    let apps: Vec<_> = read_dir(src_path)
        .unwrap()
        .into_iter()
        .map(|dir_entry| {
            let mut name_with_ext = dir_entry.unwrap().file_name().into_string().unwrap();
            name_with_ext.drain(name_with_ext.find('.').unwrap()..name_with_ext.len());
            name_with_ext
        })
        .collect();*/
    /* for app in apps {
     *     // load app data from host file system
     *     let mut host_file = File::open(format!("{}{}", target_path, app)).unwrap();
     *     let mut all_data: Vec<u8> = Vec::new();
     *     host_file.read_to_end(&mut all_data).unwrap();
     *     // create a file in easy-fs
     *     let inode = root_inode.create(app.as_str()).unwrap();
     *     // write data to easy-fs
     *     inode.write_at(0, all_data.as_slice());
     * } */
    // list apps
    /* for app in root_inode.ls() {
     *     println!("{}", app);
     * } */
    Ok(())
}

/*#[test]
fn efs_test() -> std::io::Result<()> {
    let block_file = Arc::new(BlockFile(Mutex::new({
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open("target/fs.img")?;
        f.set_len(8192 * 512).unwrap();
        f
    })));
    EasyFileSystem::create(block_file.clone(), 4096, 1);
    let efs = EasyFileSystem::open(block_file.clone());
    let root_inode = EasyFileSystem::root_inode(&efs);
    root_inode.create("filea");
    root_inode.create("fileb");
    for name in root_inode.ls() {
        println!("{}", name);
    }
    let filea = root_inode.find("filea").unwrap();
    let greet_str = "Hello, world!";
    filea.write_at(0, greet_str.as_bytes());
    //let mut buffer = [0u8; 512];
    let mut buffer = [0u8; 233];
    let len = filea.read_at(0, &mut buffer);
    assert_eq!(greet_str, core::str::from_utf8(&buffer[..len]).unwrap(),);

    let mut random_str_test = |len: usize| {
        filea.clear();
        assert_eq!(filea.read_at(0, &mut buffer), 0,);
        let mut str = String::new();
        use rand;
        // random digit
        for _ in 0..len {
            str.push(char::from('0' as u8 + rand::random::<u8>() % 10));
        }
        filea.write_at(0, str.as_bytes());
        let mut read_buffer = [0u8; 127];
        let mut offset = 0usize;
        let mut read_str = String::new();
        loop {
            let len = filea.read_at(offset, &mut read_buffer);
            if len == 0 {
                break;
            }
            offset += len;
            read_str.push_str(core::str::from_utf8(&read_buffer[..len]).unwrap());
        }
        assert_eq!(str, read_str);
    };

    random_str_test(4 * BLOCK_SZ);
    random_str_test(8 * BLOCK_SZ + BLOCK_SZ / 2);
    random_str_test(100 * BLOCK_SZ);
    random_str_test(70 * BLOCK_SZ + BLOCK_SZ / 7);
    random_str_test((12 + 128) * BLOCK_SZ);
    random_str_test(400 * BLOCK_SZ);
    random_str_test(1000 * BLOCK_SZ);
    random_str_test(2000 * BLOCK_SZ);

    Ok(())
}
*/
