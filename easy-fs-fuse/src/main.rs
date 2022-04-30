extern crate alloc;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use clap::{App, Arg};
use easy_fs::block_cache::{Cache, CacheManager};
use easy_fs::layout::{DiskInodeType, FATDirEnt};
use easy_fs::{find_local, BlockDevice, EasyFileSystem, Inode};
use lazy_static::*;
use spin::{Mutex, RwLock};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

//use std::sync::Mutex;
const BLOCK_SZ: usize = 512;

struct BlockFile(Mutex<File>);

impl BlockDevice for BlockFile {
    fn read_block(&self, block_id: usize, buf: &mut [u8]) {
        assert_eq!(buf.len() % BLOCK_SZ, 0);
        let mut file = self.0.lock();
        file.seek(SeekFrom::Start((block_id * BLOCK_SZ) as u64))
            .expect("Error when seeking!");
        assert_eq!(file.read(buf).unwrap(), BLOCK_SZ, "Not a complete block!");
    }

    fn write_block(&self, block_id: usize, buf: &[u8]) {
        assert_eq!(buf.len() % BLOCK_SZ, 0);

        let mut file = self.0.lock();
        file.seek(SeekFrom::Start((block_id * BLOCK_SZ) as u64))
            .expect("Error when seeking!");
        assert_eq!(file.write(buf).unwrap(), BLOCK_SZ, "Not a complete block!");
    }
}

pub struct BlockCache {
    cache: [u8; BLOCK_SZ],
    block_id: usize,
    block_device: Arc<dyn BlockDevice>,
    modified: bool,
}

impl Drop for BlockCache {
    fn drop(&mut self) {
        self.sync()
    }
}

impl BlockCache {
    /// Private function.
    /// Get the address at the `offset` in the cache to the cache for later access.
    /// # Argument
    /// * `offset`: The offset from the beginning of the block
    fn addr_of_offset(&self, offset: usize) -> usize {
        &self.cache[offset] as *const _ as usize
    }

    /// Get a reference to the block at required `offset`, casting the in the coming area as an instance of type `&T`
    /// # Argument
    /// * `offset`: The offset from the beginning of the block
    fn get_ref<T>(&self, offset: usize) -> &T
    where
        T: Sized,
    {
        let type_size = core::mem::size_of::<T>();
        assert!(offset + type_size <= BLOCK_SZ);
        let addr = self.addr_of_offset(offset);
        unsafe { &*(addr as *const T) }
    }

    /// The mutable version of `get_ref()`
    fn get_mut<T>(&mut self, offset: usize) -> &mut T
    where
        T: Sized,
    {
        let type_size = core::mem::size_of::<T>();
        assert!(offset + type_size <= BLOCK_SZ);
        self.modified = true;
        let addr = self.addr_of_offset(offset);
        unsafe { &mut *(addr as *mut T) }
    }
    /// Load a new BlockCache from disk.
    fn new(block_id: usize, block_device: Arc<dyn BlockDevice>) -> Self {
        let mut cache = [0u8; BLOCK_SZ];
        block_device.read_block(block_id, &mut cache);
        Self {
            cache,
            block_id,
            block_device,
            modified: false,
        }
    }
}
impl Cache for BlockCache {
    /// The read-only mapper to the block cache
    fn read<T, V>(&self, offset: usize, f: impl FnOnce(&T) -> V) -> V {
        f(self.get_ref(offset))
    }

    /// The mutable mapper to the block cache    
    fn modify<T, V>(&mut self, offset: usize, f: impl FnOnce(&mut T) -> V) -> V {
        let ret = f(self.get_mut(offset));
        return ret;
    }
}
impl BlockCache {
    /// Synchronize the cache with the external storage, i.e. write it back to the disk.
    fn sync(&mut self) {
        if self.modified {
            self.modified = false;
            self.block_device.write_block(self.block_id, &self.cache);
        }
    }
}
const BLOCK_CACHE_SIZE: usize = 16;

pub struct BlockCacheManager {
    /// # Fields
    /// * `0`: `usize`, the Corresponding `block_id`
    /// * `1`: `Arc<Mutex<BlockCache>>`, the Pointer to BlockCache
    /// # Impl. Info
    /// Using RwLock for concurrent access.
    queue: RwLock<VecDeque<(usize, Arc<Mutex<BlockCache>>)>>,
}

impl BlockCacheManager {
    fn new() -> Self {
        Self {
            queue: RwLock::new(VecDeque::with_capacity(BLOCK_CACHE_SIZE)),
        }
    }
}
impl CacheManager for BlockCacheManager {
    type CacheType = BlockCache;
    const CACHE_SZ: usize = 512;
    fn try_get_block_cache(
        &mut self,
        block_id: usize,
        inner_blk_id: usize,
    ) -> Option<Arc<Mutex<BlockCache>>> {
        if let Some(pair) = self.queue.read().iter().find(|pair| pair.0 == block_id) {
            Some(Arc::clone(&pair.1))
        } else {
            None
        }
    }

    fn get_block_cache<FUNC>(
        &mut self,
        block_id: usize,
        inner_blk_id: usize,
        neighbor: FUNC,
        block_device: Arc<dyn BlockDevice>,
    ) -> Arc<Mutex<BlockCache>>
    where
        FUNC: Fn() -> Vec<usize>,
    {
        if let Some(i) = self.try_get_block_cache(block_id, inner_blk_id) {
            i
        } else {
            // substitute
            let rd = self.queue.read();
            let size = self.queue.read().len();
            drop(rd);
            if size == BLOCK_CACHE_SIZE {
                // from front to tail
                let rd = self.queue.read();
                if let Some((idx, _)) = rd
                    .iter()
                    .enumerate()
                    .find(|(_, pair)| Arc::strong_count(&pair.1) == 1)
                {
                    drop(rd);
                    self.queue.write().drain(idx..=idx);
                } else {
                    panic!("Run out of BlockCache!");
                }
            }
            // load block into mem and push back
            let block_cache = Arc::new(Mutex::new(BlockCache::new(
                block_id,
                Arc::clone(&block_device),
            )));
            self.queue
                .write()
                .push_back((block_id, Arc::clone(&block_cache)));
            block_cache
        }
    }

    fn new(fst_block_id: usize) -> Mutex<Self>
    where
        Self: Sized,
    {
        Mutex::new(Self::new())
    }
}

lazy_static! {
    pub static ref BLOCK_CACHE_MANAGER: Arc<Mutex<BlockCacheManager>> =
        Arc::new(Mutex::new(BlockCacheManager::new()));
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
        "../fat32-fuse/fat32.img"
    };

    println!("image_path = {}", image_path);
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(image_path)
        .unwrap();
    let block_file = Arc::new(BlockFile(Mutex::new(f)));
    let i: Arc<EasyFileSystem<BlockCacheManager, BlockCacheManager>> =
        EasyFileSystem::open(block_file, BLOCK_CACHE_MANAGER.clone());
    println!(
        "data_area_start_block: {}, \nsec_per_clus: {}, \nbyts_per_clus: {}, \nroot_clus:{}",
        i.data_area_start_block, i.sec_per_clus, i.byts_per_clus, i.root_clus
    );
    //    println!("fat ent no:{:?}", i.fat.tot_ent);
    let rt = Arc::new(Inode::new(
        i.root_clus as usize,
        DiskInodeType::Directory,
        None,
        None,
        i.clone(),
    ));
    println!("size:{:?}", rt.size);
    println!("clus:{:?}", rt.direct.lock());

    let mut ent = FATDirEnt::empty();

    let print_iter = || {
        let mut iter = rt.iter().enumerate();
        for i in rt.iter().enumerate() {
            println!(
                "{}, ord: {}, last_ent: {}",
                if !i.unused_not_last() && !i.last_and_unused() {
                    i.get_name()
                } else {
                    if i.last_and_unused() {
                        "last unused".to_string()
                    } else {
                        "unused not last".to_string()
                    }
                },
                i.get_ord(),
                i.is_last_long_dir_ent()
            );
        }
        iter.set_offset(4608);
        println!("last: {:?}", iter.current_clone());
        println!("rt_sz: {}", *rt.size.read());
    };

    let rm = || {
        println!("fat_num:{}", rt.fs.fat.cnt_all_fat(&rt.fs.block_device));
        let v = rt.ls();
        let (_, ent, offset) = v.iter().find(|&i| i.0 == "cat").unwrap();
        println!("{:?}", ent);
        let cat = Arc::new(Inode::from_ent(rt.clone(), ent, *offset));

        println!("direct:{:?}", cat.direct);
        assert!(Inode::delete_from_disk(cat).is_ok());
        println!("fat_num:{}", rt.fs.fat.cnt_all_fat(&rt.fs.block_device));
    };

    print_iter();

    rm();

    print_iter();
    let mut text: [u8; 4096] = [0; 4096];
    /*let i = easy_fs::find_local(rt.clone(), "lua_testcode.sh".to_string())
        .unwrap()
        .read_at_block_cache(0, &mut text);
    println!("{}", String::from_utf8_lossy(&text[0..i]));
    println!(
        "{:?},{:?},{:?}",
        easy_fs::find_local(rt.clone(), "lua_testcode.sh".to_string()).is_none(),
        easy_fs::find_local(rt.clone(), "etc".to_string())
            .unwrap()
            .get_inode_num(),
        rt.get_neighboring_sec(0)
    );*/

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
