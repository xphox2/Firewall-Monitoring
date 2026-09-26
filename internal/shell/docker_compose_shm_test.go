package shell

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// PostgreSQL runs inside the firewall-mon container and allocates parallel
// query state in /dev/shm (dynamic_shared_memory_type = posix). Docker's
// default 64 MB is smaller than one parallel hash join at the work_mem the
// production box runs (16 MB x hash_mem_multiplier 2 x 3 participants = 96 MB),
// and such a query fails outright rather than spilling. This pins an explicit
// shm_size of at least 512 MB on the service.
func TestDockerCompose_ShmSizeCoversParallelQueries(t *testing.T) {
	data, err := os.ReadFile("../../docker-compose.yml")
	if err != nil {
		t.Skipf("docker-compose.yml not found: %v", err)
	}
	var found string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "shm_size:") {
			found = strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "shm_size:")), `"'`)
		}
	}
	if found == "" {
		t.Fatal("docker-compose.yml sets no shm_size; Docker's 64 MB /dev/shm is smaller than one parallel hash join at production work_mem")
	}
	m := regexp.MustCompile(`^(\d+)([kKmMgG])?[bB]?$`).FindStringSubmatch(found)
	if m == nil {
		t.Fatalf("shm_size %q is not a size this test understands", found)
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	switch strings.ToLower(m[2]) {
	case "k":
		n <<= 10
	case "m":
		n <<= 20
	case "g":
		n <<= 30
	}
	if n < 512<<20 {
		t.Fatalf("shm_size %q is under 512 MB; parallel hash joins need work_mem x 2 x 3 each", found)
	}
}
