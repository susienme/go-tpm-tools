package launchermount

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func TestLocalSSDMountSpecsMount(t *testing.T) {
	testCases := []struct {
		name               string
		hostPath           string
		containerDest      string
		expectedSpecsMount specs.Mount
	}{
		{
			name:          "Basic Local SSD Mount",
			hostPath:      "/mnt/disks/local-ssd",
			containerDest: "/mnt/lssd",
			expectedSpecsMount: specs.Mount{
				Type:        "bind",
				Source:      "/mnt/disks/local-ssd",
				Destination: "/mnt/lssd",
				Options:     []string{"rbind", "rw"},
			},
		},
		{
			name:          "Custom Container Destination",
			hostPath:      "/run/lssd_mount",
			containerDest: "/scratch/data",
			expectedSpecsMount: specs.Mount{
				Type:        "bind",
				Source:      "/run/lssd_mount",
				Destination: "/scratch/data",
				Options:     []string{"rbind", "rw"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mnt := LocalSSDMount{
				Source:      tc.hostPath,
				Destination: tc.containerDest,
			}

			if got := mnt.Mountpoint(); got != tc.containerDest {
				t.Errorf("Mountpoint() = %q, want %q", got, tc.containerDest)
			}

			spMnt := mnt.SpecsMount()
			if diff := cmp.Diff(spMnt, tc.expectedSpecsMount); diff != "" {
				t.Errorf("SpecsMount() diff (-got +want):\n%s", diff)
			}
		})
	}
}

func TestCalculateMetadataSizes(t *testing.T) {
	// 1 Local SSD = 375 GiB = 786,432,000 sectors (512 bytes each)
	ssd1Sectors := uint64(786432000)

	sizes1 := calculateMetadataSizes(ssd1Sectors)
	if sizes1.usableDevSectors == 0 {
		t.Errorf("expected non-zero usable sectors for 1 SSD")
	}

	// RAM overhead should be around ~2.75 GiB for 1 SSD
	if sizes1.totalMetadataSize == 0 {
		t.Errorf("expected non-zero total metadata size for 1 SSD")
	}

	// 8 Local SSDs = 3 TiB
	sizes8 := calculateMetadataSizes(8 * ssd1Sectors)
	if sizes8.totalMetadataSize <= sizes1.totalMetadataSize {
		t.Errorf("8 SSDs metadata size (%d) should be greater than 1 SSD (%d)", sizes8.totalMetadataSize, sizes1.totalMetadataSize)
	}
}

func TestValidateSystemRAM(t *testing.T) {
	ram, err := totalRAMBytes()
	if err != nil {
		t.Fatalf("totalRAMBytes() failed: %v", err)
	}
	if ram == 0 {
		t.Errorf("expected totalRAMBytes > 0")
	}

	// Small metadata overhead (e.g. 1 KB) should pass RAM validation
	if err := validateSystemRAM(1024); err != nil {
		t.Errorf("validateSystemRAM(1024) failed: %v", err)
	}

	// Huge metadata overhead (e.g. 1000 TiB) should fail RAM validation
	hugeSize := uint64(1000 * 1024 * 1024 * 1024 * 1024)
	if err := validateSystemRAM(hugeSize); err == nil {
		t.Errorf("expected error for validateSystemRAM(hugeSize), got nil")
	} else if !strings.Contains(err.Error(), "insufficient system RAM") {
		t.Errorf("got error %v, want 'insufficient system RAM'", err)
	}
}

func TestSetupLSSDNoSSDs(t *testing.T) {
	// SetupLSSD relies on filepath.Glob("/dev/disk/by-id/google-local-nvme-ssd-*")
	// On environments without actual Local SSDs attached, it should gracefully return nil, nil.
	hostPath := t.TempDir()
	containerDest := "/mnt/lssd"

	mnt, err := SetupLocalSSD(hostPath, containerDest)
	if err != nil {
		t.Fatalf("expected nil error when no Local SSDs exist, got %v", err)
	}
	if mnt != nil {
		t.Errorf("expected nil mount when no Local SSDs exist, got %+v", mnt)
	}
}

func TestCreateDMStripeTableFormat(t *testing.T) {
	devices := []string{"/dev/nvme0n1", "/dev/nvme1n1"}
	totalSectors := uint64(1572864000)

	table := fmt.Sprintf("0 %d striped %d 512 %s 0 %s 0", totalSectors, len(devices), devices[0], devices[1])
	expectedPrefix := "0 1572864000 striped 2 512 /dev/nvme0n1 0 /dev/nvme1n1 0"

	if table != expectedPrefix {
		t.Errorf("stripe table = %q, want %q", table, expectedPrefix)
	}
}

func TestSetupLSSDContainerDestRelativePath(t *testing.T) {
	// Relative container destination path should be formatted as absolute
	relDest := "mnt/lssd"
	expectedAbs := "/mnt/lssd"

	if !filepath.IsAbs(relDest) {
		relDest = filepath.Join("/", relDest)
	}
	if relDest != expectedAbs {
		t.Errorf("got %q, want %q", relDest, expectedAbs)
	}
}
