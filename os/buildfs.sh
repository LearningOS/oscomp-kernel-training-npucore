U_FAT32_DIR="../fat32-fuse"
U_FAT32=$1

sudo dd if=/dev/zero of=${U_FAT32} bs=1M count=100
sudo mkfs.vfat -F 32 ${U_FAT32}
sudo fdisk -l ${U_FAT32}

if test -e ${U_FAT32_DIR}/fs
then 
    sudo rm -r ${U_FAT32_DIR}/fs
fi
sudo mkdir ${U_FAT32_DIR}/fs

sudo mount -f ${U_FAT32} ${U_FAT32_DIR}/fs
if [ $? ]
then
    sudo umount ${U_FAT32}
fi
sudo mount ${U_FAT32} ${U_FAT32_DIR}/fs

for programname in $(ls ../user/src/bin)
do
    sudo cp -r ../user/target/riscv64gc-unknown-none-elf/release/${programname%.rs} ${U_FAT32_DIR}/fs/${programname%.rs}
done

for programname in $(ls ../user/riscv64)
do
    sudo cp -r ../user/riscv64/$programname ${U_FAT32_DIR}/fs/"$programname"
done

for programname in $(ls ../user/busybox_lua_testsuites)
do 
    sudo cp -r ../user/busybox_lua_testsuites/$programname ${U_FAT32_DIR}/fs/"$programname"
done

# build root
sudo mkdir -p ${U_FAT32_DIR}/fs/etc
sudo sh -c "echo "root:x:0:0:root:/root:/bin/bash" > ${U_FAT32_DIR}/fs/etc/passwd"

sudo umount ${U_FAT32_DIR}/fs
