package netwatch

import (
	"fmt"
	"net/netip"
	"slices"
)

// routeRow is one routing table row reduced to what default route tracking
// compares. Windows reads its table into rows; the filtering stays portable
// so it is tested on every platform.
type routeRow struct {
	ipv6    bool
	bits    int
	index   int
	nextHop netip.Addr
}

// defaultRouteTokensFromRows keeps the default routes (prefix length 0) of
// interfaces that are not excluded and returns them as sorted tokens, with
// the indexes of the interfaces that carry them.
func defaultRouteTokensFromRows(
	rows []routeRow,
	excludedIndexes map[int]struct{},
) ([]string, map[int]struct{}) {
	tokens := make([]string, 0, 2)
	indexes := make(map[int]struct{}, 2)
	for _, row := range rows {
		if row.bits != 0 {
			continue
		}
		if _, excluded := excludedIndexes[row.index]; excluded {
			continue
		}
		family := 4
		if row.ipv6 {
			family = 6
		}
		gateway := ""
		if row.nextHop.IsValid() && !row.nextHop.IsUnspecified() {
			gateway = row.nextHop.Unmap().String()
		}
		indexes[row.index] = struct{}{}
		tokens = append(tokens, fmt.Sprintf("default|family=%d|link=%d|gateway=%s", family, row.index, gateway))
	}
	slices.Sort(tokens)

	return slices.Compact(tokens), indexes
}
