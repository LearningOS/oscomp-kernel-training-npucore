initSidebarItems({"constant":[["BLOCK_SZ",""],["CACHE_SZ",""]],"mod":[["bitmap",""],["block_cache",""],["block_dev",""],["dir_iter",""],["efs",""],["layout",""],["vfs",""]],"struct":[["EasyFileSystem",""],["Inode","The functionality of ClusLi & Inode can be merged. The struct for file information"]],"trait":[["BlockDevice","We should regulate the behavior of this trait on FAILURE e.g. What if buf.len()>BLOCK_SZ for read_block? e.g. Does read_block clean the rest part of the block to be zero for buf.len()!=BLOCK_SZ in write_block() & read_block() e.g. What if buf.len()<BLOCK_SZ for write_block?"]]});