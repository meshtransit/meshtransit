package server

// Metrics receives aggregate relay events. Labels are outcome names only;
// implementations never see keys, addresses, zones or route numbers
// (mtrp-v1 §7).
type Metrics interface {
	Handshake(result string)
	Control(result string)
	Data(result string, payloadBytes int)
	Sessions(active int)
	Routes(delta int)
}

type nopMetrics struct{}

func (nopMetrics) Handshake(string) {}
func (nopMetrics) Control(string)   {}
func (nopMetrics) Data(string, int) {}
func (nopMetrics) Sessions(int)     {}
func (nopMetrics) Routes(int)       {}
