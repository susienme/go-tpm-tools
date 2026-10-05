package launchermount

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

/*
Integrity FS on Local SSD Configuration Constants and Operational Constraints:

1. Hardware/Device: Designed for GCP Local NVMe SSDs (/dev/disk/by-id/google-local-nvme-ssd-*).
   These devices use native 4096-byte (4K) sector size, bypassing ChromeOS cgpt partition table
   resizing (which fails on 4K NVMe drives due to cgpt's hardcoded 512-byte limit).

2. RAM Overhead & Safety Margin: dm-integrity tags are stored in a memory-backed tmpfs at /run/integrity_fs_lssd.
   The memory overhead is ~0.73% of total disk capacity. The host VM must have at least 2x the required
   metadata overhead in Total System RAM before allocating tmpfs:

   +-----------------------+-----------------------+-----------------+---------------------+
   | Local SSD Count       | Total Capacity        | RAM Overhead    | Required System RAM |
   +-----------------------+-----------------------+-----------------+---------------------+
   |  1 x 375 GiB          |    375 GiB            |   ~2.75 GiB     |   >=  ~5.50 GiB     |
   |  2 x 375 GiB          |    750 GiB            |   ~5.50 GiB     |   >= ~11.00 GiB     |
   |  4 x 375 GiB          |  1,500 GiB ( 1.5 TiB) |  ~11.00 GiB     |   >= ~22.00 GiB     |
   |  8 x 375 GiB          |  3,000 GiB ( 3.0 TiB) |  ~22.00 GiB     |   >= ~44.00 GiB     |
   | 16 x 375 GiB          |  6,000 GiB ( 6.0 TiB) |  ~43.80 GiB     |   >= ~87.60 GiB     |
   | 24 x 375 GiB          |  9,000 GiB ( 9.0 TiB) |  ~65.70 GiB     |   >=~131.40 GiB     |
   | 32 x 375 GiB          | 12,000 GiB (12.0 TiB) |  ~87.60 GiB     |   >=~175.20 GiB     |
   | 48 x 375 GiB (6x3TiB) | 18,000 GiB (18.0 TiB) | ~131.40 GiB     |   >=~262.80 GiB     |
   +-----------------------+-----------------------+-----------------+---------------------+

3. Ephemerality: Encryption keys (AES-256-GCM) and integrity metadata tags are generated in RAM.
   On reboot or shutdown, the key and tags are destroyed, rendering disk data unrecoverable.
4. Kernel Drivers: Requires kernel support for dm-stripe, dm-integrity, dm-crypt (capi:gcm(aes)-random),
   dm-zero, and dm-clone.
*/

const (
	// TypeLSSD = "lssd"

	blockSize             = 4096 // The block size used for dm-integrity, dm-crypt, and ext4 formatting (4096 bytes).
	sectorSize            = 512  // The Linux block device sector size.
	sectorsPerBlock       = blockSize / sectorSize
	integrityTagSize      = 28  // Integrity tag size in bytes (16-byte AES-GCM auth tag + 12-byte random IV).
	journalSectionSectors = 264 // 32 journal sections * 8 sectors/section + 8 buffer sectors
	log2BufferSectors     = 3
	sectorShift           = 9
	cloneRegionSize       = 128
	twoMB                 = 2 << 20
	maxAttempts           = 5

	localSSDGlob      = "/dev/disk/by-id/google-local-nvme-ssd-*"
	dmDir             = "/dev/mapper"
	dmsetup           = "/sbin/dmsetup"
	mkfsExt4          = "/sbin/mkfs.ext4"
	metadataMount     = "/run/integrity_fs_lssd"
	stripeName        = "lssd_stripe"
	protectedLSSDName = "protected_lssd"
)

// LocalSSDMount represents a launcher mount backed by Local SSDs with Integrity FS protection.
type LocalSSDMount struct {
	// Source is the host mount path (e.g., "/mnt/disks/local-ssd").
	Source string
	// Destination is the target mount point inside the workload container.
	Destination string
	// TotalSize is total capacity of all Local SSDs in bytes.
	TotalSize uint64
}

// Compile-time interface check.
var _ Mount = LocalSSDMount{}

// SpecsMount returns the OCI runtime spec Mount for LocalSSDMount.
func (l LocalSSDMount) SpecsMount() specs.Mount {
	return specs.Mount{
		Type:        "bind",
		Source:      l.Source,
		Destination: l.Destination,
		Options:     []string{"rbind", "rw"},
	}
}

// Mountpoint gives the destination mount point inside the workload container.
func (l LocalSSDMount) Mountpoint() string {
	return l.Destination
}

// SetupLocalSSD discovers attached Local SSDs, sets up the Integrity FS stack,
// mounts the filesystem to hostPath, and returns a *LocalSSDMount.
// If no Local SSDs are attached, it returns nil, nil.
func SetupLocalSSD(hostPath string, containerDest string) (*LocalSSDMount, error) {
	// 1. Discover local SSDs
	ssds, err := filepath.Glob(localSSDGlob)
	if err != nil {
		return nil, fmt.Errorf("failed to discover Google Local SSDs: %v", err)
	}
	if len(ssds) == 0 { // This is not an error, but no Local SSDs are attached.
		return nil, nil
	}

	// Validate system RAM before creating any DM devices
	var totalSectors uint64
	for _, dev := range ssds {
		sec, err := getBlockDevSectors(dev)
		if err != nil {
			return nil, fmt.Errorf("failed to get sector count for %s: %v", dev, err)
		}
		totalSectors += sec
	}

	sizes := calculateMetadataSizes(totalSectors)

	if err := validateSystemRAM(sizes.totalMetadataSize); err != nil {
		return nil, err
	}

	underlyingDevice := ssds[0]
	if len(ssds) > 1 {
		// Combine multiple local SSDs into a striped DM device (/dev/mapper/lssd_stripe)
		underlyingDevice, err = createDMStripe(ssds, totalSectors)
		if err != nil {
			return nil, fmt.Errorf("failed to create striped DM device for local SSDs: %v", err)
		}
		defer func() {
			// Remove the striped device if setup fails.
			if err != nil {
				_ = runDmsetupRemove(stripeName)
			}
		}()
	}

	// 2. Setup Integrity FS in memory
	cloneDev, err := integrityFSMemory(underlyingDevice, sizes)
	if err != nil {
		return nil, fmt.Errorf("failed to setup integrity FS on local SSD: %v", err)
	}

	// 3. Create host mount directory and mount filesystem
	if err := os.MkdirAll(hostPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create host mount directory %s: %v", hostPath, err)
	}
	if err := unix.Mount(cloneDev, hostPath, "ext4", unix.MS_NODEV|unix.MS_NOSUID|unix.MS_NOEXEC, ""); err != nil {
		return nil, fmt.Errorf("failed to mount %s to %s: %v", cloneDev, hostPath, err)
	}

	if !filepath.IsAbs(containerDest) {
		containerDest = filepath.Join("/", containerDest)
	}

	return &LocalSSDMount{
		Source:      hostPath,
		Destination: containerDest,
		TotalSize:   sizes.usableDevSectors * sectorSize,
	}, nil
}

// createDMStripe creates a dm-stripe device combining multiple block devices into a RAID 0 stripe.
func createDMStripe(devices []string, totalSectors uint64) (string, error) {
	table := fmt.Sprintf("0 %d striped %d 512", totalSectors, len(devices))
	for _, dev := range devices {
		table += fmt.Sprintf(" %s 0", dev)
	}

	if err := runDmsetupCreate(stripeName, table); err != nil {
		return "", err
	}
	return filepath.Join(dmDir, stripeName), nil
}

// integrityFSMemory sets up in-memory integrity tags, dm-crypt, dm-zero, dm-clone, and formats ext4.
func integrityFSMemory(underlyingDev string, sizes lssdMetadataSizes) (string, error) {
	dmIntegrityName := protectedLSSDName + "_integrity"
	dmCryptName := protectedLSSDName + "_crypt"
	dmZeroName := protectedLSSDName + "_zero"
	dmCloneName := protectedLSSDName

	underlyingDevBase := filepath.Base(underlyingDev)

	if err := os.MkdirAll(metadataMount, 0700); err != nil {
		return "", fmt.Errorf("failed to create metadata mount dir: %v", err)
	}
	mountOpts := fmt.Sprintf("size=%d,noexec,mode=0700", sizes.totalMetadataSize)
	_ = unix.Mount("metadata_device_tmpfs", metadataMount, "tmpfs", unix.MS_NOEXEC, mountOpts)

	integFile, err := os.CreateTemp(metadataMount, underlyingDevBase+"_*_integrity.bin")
	if err != nil {
		return "", fmt.Errorf("failed to create integrity metadata file: %v", err)
	}
	defer integFile.Close()

	if err := unix.Fallocate(int(integFile.Fd()), 0, 0, int64(sizes.integMetadataDeviceSize)); err != nil {
		return "", fmt.Errorf("failed to fallocate integrity file: %v", err)
	}

	integLoopDev, err := attachLoopDevice(integFile)
	if err != nil {
		return "", fmt.Errorf("failed to attach integrity loop device: %v", err)
	}

	integrityTable := fmt.Sprintf("0 %d integrity %s 0 %d D 3 block_size:%d meta_device:%s buffer_sectors:8",
		sizes.usableDevSectors, underlyingDev, integrityTagSize, blockSize, integLoopDev)
	if err := runDmsetupCreate(dmIntegrityName, integrityTable); err != nil {
		return "", fmt.Errorf("failed to create dm-integrity device: %v", err)
	}

	dmIntegrityDev := filepath.Join(dmDir, dmIntegrityName)
	cryptSectors, err := getBlockDevSectors(dmIntegrityDev)
	if err != nil {
		return "", fmt.Errorf("failed to get crypt sectors: %v", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate random key: %v", err)
	}
	hexKey := hex.EncodeToString(key)

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		cryptTable := fmt.Sprintf("0 %d crypt capi:gcm(aes)-random %s 0 %s 0 3 submit_from_crypt_cpus sector_size:%d integrity:%d:aead",
			cryptSectors, hexKey, dmIntegrityDev, blockSize, integrityTagSize)
		lastErr = runDmsetupCreate(dmCryptName, cryptTable)
		if lastErr == nil {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if lastErr != nil {
		return "", fmt.Errorf("failed to create dm-crypt device after retries: %v", lastErr)
	}

	dmCryptDev := filepath.Join(dmDir, dmCryptName)
	cryptDevSectors, err := getBlockDevSectors(dmCryptDev)
	if err != nil {
		return "", fmt.Errorf("failed to get dm-crypt dev sectors: %v", err)
	}

	zeroTable := fmt.Sprintf("0 %d zero", cryptDevSectors)
	if err := runDmsetupCreate(dmZeroName, zeroTable); err != nil {
		return "", fmt.Errorf("failed to create dm-zero device: %v", err)
	}
	dmZeroDev := filepath.Join(dmDir, dmZeroName)

	cloneFile, err := os.CreateTemp(metadataMount, underlyingDevBase+"_*_clone.bin")
	if err != nil {
		return "", fmt.Errorf("failed to create clone metadata file: %v", err)
	}
	defer cloneFile.Close()

	if err := unix.Fallocate(int(cloneFile.Fd()), 0, 0, int64(sizes.cloneMetadataDeviceSize)); err != nil {
		return "", fmt.Errorf("failed to fallocate clone file: %v", err)
	}

	cloneLoopDev, err := attachLoopDevice(cloneFile)
	if err != nil {
		return "", fmt.Errorf("failed to attach clone loop device: %v", err)
	}

	cloneTable := fmt.Sprintf("0 %d clone %s %s %s %d 1 no_discard_passdown 2 hydration_threshold 2 hydration_batch_size 2",
		cryptDevSectors, cloneLoopDev, dmCryptDev, dmZeroDev, cloneRegionSize)
	if err := runDmsetupCreate(dmCloneName, cloneTable); err != nil {
		return "", fmt.Errorf("failed to create dm-clone device: %v", err)
	}
	dmCloneDev := filepath.Join(dmDir, dmCloneName)

	if err := initializeProbeLocations(dmCloneDev); err != nil {
		return "", fmt.Errorf("failed to initialize probe locations: %v", err)
	}

	cmd := exec.Command(mkfsExt4, "-E", "lazy_journal_init", "-E", "nodiscard", dmCloneDev, "-b", fmt.Sprintf("%d", blockSize))
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("mkfs.ext4 failed on %s: %v, output: %s", dmCloneDev, err, string(out))
	}

	return dmCloneDev, nil
}

func getBlockDevSectors(devicePath string) (uint64, error) {
	f, err := os.Open(devicePath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var sizeInBytes uint64
	_, _, sysErr := unix.Syscall(unix.SYS_IOCTL, f.Fd(), uintptr(unix.BLKGETSIZE64), uintptr(unsafe.Pointer(&sizeInBytes)))
	if sysErr != 0 {
		return 0, sysErr
	}
	return sizeInBytes / sectorSize, nil
}

func attachLoopDevice(f *os.File) (string, error) {
	controlFd, err := unix.Open("/dev/loop-control", unix.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("failed to open /dev/loop-control: %v", err)
	}
	defer unix.Close(controlFd)

	devNum, err := unix.IoctlGetInt(controlFd, unix.LOOP_CTL_GET_FREE)
	if err != nil {
		return "", fmt.Errorf("failed to get free loop device: %v", err)
	}

	loopPath := fmt.Sprintf("/dev/loop%d", devNum)
	loopFd, err := unix.Open(loopPath, unix.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("failed to open %s: %v", loopPath, err)
	}
	defer unix.Close(loopFd)

	if err := unix.IoctlSetInt(loopFd, unix.LOOP_SET_FD, int(f.Fd())); err != nil {
		return "", fmt.Errorf("failed to attach %s to %s: %v", f.Name(), loopPath, err)
	}
	return loopPath, nil
}

func initializeProbeLocations(dmCloneDev string) error {
	f, err := os.OpenFile(dmCloneDev, os.O_WRONLY|unix.O_DIRECT, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	sectors, err := getBlockDevSectors(dmCloneDev)
	if err != nil {
		return err
	}

	zeroBlock := make([]byte, blockSize)
	probedBlocks := []int64{1, 2, 3, 4, 512, 1024, 2048}
	for _, blk := range probedBlocks {
		_, _ = f.WriteAt(zeroBlock, blk*blockSize)
	}

	maxBlock := int64(sectors / sectorsPerBlock)
	startBlock := maxBlock - 32768 - 1
	if startBlock > 0 {
		journalZeros := make([]byte, 32768*blockSize)
		_, _ = f.WriteAt(journalZeros, startBlock*blockSize)
	}
	return nil
}

func runDmsetup(args ...string) error {
	cmd := exec.Command(dmsetup, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("dmsetup %v failed: %v, output: %s", args, err, string(out))
	}
	return nil
}

// runDmsetupCreate issues a dmsetup create command to instantiate a Device Mapper target in the kernel.
// It serves as the unified helper for all Device Mapper layers (striped, integrity, crypt, zero, clone)
// by passing target-specific mapping tables (0 <sectors> <target_type> <args...>) directly to dmsetup.
func runDmsetupCreate(name string, table string) error {
	return runDmsetup("create", name, "--table", table)
}

// runDmsetupRemove issues a dmsetup remove command to tear down a Device Mapper target in the kernel.
func runDmsetupRemove(name string) error {
	return runDmsetup("remove", name)
}

func totalRAMBytes() (uint64, error) {
	var si unix.Sysinfo_t
	if err := unix.Sysinfo(&si); err != nil {
		return 0, err
	}
	unit := uint64(si.Unit)
	if unit == 0 {
		unit = 1
	}
	return uint64(si.Totalram) * unit, nil
}

type lssdMetadataSizes struct {
	usableDevBlocks         uint64
	usableDevSectors        uint64
	integMetadataDeviceSize uint64
	cloneMetadataDeviceSize uint64
	totalMetadataSize       uint64
}

// calculateMetadataSizes calculates the required metadata device sizes for dm-integrity and dm-clone
// based on the total number of sectors on the Local SSDs.
// This function reflects integrity_fs_memory() in https://cos.googlesource.com/cos/overlays/board-overlays/+/refs/heads/master/project-lakitu/chromeos-base/chromeos-init-systemd/files/setup-integrity-fs.sh
func calculateMetadataSizes(totalSectors uint64) lssdMetadataSizes {
	// Ensure 4K block alignment. `dm-integrity` requires the device size to be a multiple of 4KB.
	usableDevBlocks := totalSectors / sectorsPerBlock
	usableDevSectors := usableDevBlocks * sectorsPerBlock

	// Required sectors for the superblock and journal section.
	initialSectors := uint64(sectorsPerBlock + journalSectionSectors)
	integTagBlocks := usableDevBlocks * uint64(integrityTagSize)
	// Align to default buffer sector size.
	metadataSectors := ((integTagBlocks + ((1 << (log2BufferSectors + sectorShift)) - 1)) >> (log2BufferSectors + sectorShift)) << log2BufferSectors
	metadataDeviceSectors := initialSectors + metadataSectors
	integMetadataDeviceSize := metadataDeviceSectors * sectorSize

	// Calculate metadata device size for dm-clone (minimum 2MB).
	cloneMetadataDeviceSize := ((usableDevBlocks + (sectorSize - 1)) / sectorSize) * sectorSize
	if cloneMetadataDeviceSize < twoMB {
		cloneMetadataDeviceSize = twoMB
	}

	return lssdMetadataSizes{
		usableDevBlocks:         usableDevBlocks,
		usableDevSectors:        usableDevSectors,
		integMetadataDeviceSize: integMetadataDeviceSize,
		cloneMetadataDeviceSize: cloneMetadataDeviceSize,
		totalMetadataSize:       integMetadataDeviceSize + cloneMetadataDeviceSize,
	}
}

func validateSystemRAM(totalMetadataSize uint64) error {
	totalRAMBytes, err := totalRAMBytes()
	if err != nil {
		return fmt.Errorf("failed to check system RAM: %v", err)
	}
	requiredRAM := 2 * totalMetadataSize
	if totalRAMBytes < requiredRAM {
		return fmt.Errorf("insufficient system RAM for Local SSD integrity FS: required at least %d bytes total RAM (2x overhead), found %d bytes", requiredRAM, totalRAMBytes)
	}
	return nil
}
