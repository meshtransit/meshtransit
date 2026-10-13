package main

import (
	"strings"
	"testing"
)

const sample = `2026-10-13 00:30:44.173 UTC [66] LOG:  QUERY STATISTICS
2026-10-13 00:30:44.173 UTC [66] DETAIL:  ! system usage stats:
	!	17164 kB max resident size
2026-10-13 00:30:44.173 UTC [66] STATEMENT:  show transaction_read_only
2026-10-13 00:30:54.954 UTC [66] LOG:  EXECUTE MESSAGE STATISTICS
2026-10-13 00:30:54.954 UTC [66] DETAIL:  ! system usage stats:
	!	230000 kB max resident size
2026-10-13 00:30:54.954 UTC [66] STATEMENT:  SELECT network_revision
	FROM mesh_ops.publish_compiled_policy_v2(
	    $1::UUID)
2026-10-13 00:30:55.000 UTC [70] LOG:  QUERY STATISTICS
2026-10-13 00:30:55.000 UTC [70] DETAIL:  ! system usage stats:
	!	400000 kB max resident size
2026-10-13 00:30:55.000 UTC [70] STATEMENT:  CREATE FUNCTION mesh_ops.x() RETURNS int
2026-10-13 00:30:56.000 UTC [66] LOG:  EXECUTE MESSAGE STATISTICS
2026-10-13 00:30:56.000 UTC [66] DETAIL:  ! system usage stats:
	!	231000 kB max resident size
2026-10-13 00:30:56.000 UTC [66] STATEMENT:  SELECT mesh_ops.publish_compiled_policy_v2($1)
`

func TestScanAttributesGrowthToTheStatement(t *testing.T) {
	t.Parallel()
	worst, err := scan(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(worst) != 2 || worst[0].statement != "publish_compiled_policy_v2" || worst[0].kb != 230000-17164 {
		t.Fatalf("worst = %+v", worst)
	}
	if worst[1].statement != "show transaction_read_only" || worst[1].kb != 17164 {
		t.Fatalf("baseline = %+v", worst[1])
	}
}
