package flowreport

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/client/internal/flowcount"
	"meshtransit.net/client/internal/privatefile"
	"meshtransit.net/shared/flowlog"
)

const (
	stateFile    = "state.json"
	batchSuffix  = ".batch"
	tempInfix    = ".tmp-"
	batchMagic   = "MTFB2\x00"
	headerSize   = len(batchMagic) + 8 + 8 + 8 + sha256.Size
	maxStateSize = 4096
	fileMode     = 0o600
)

// ErrSpoolFailed reports a spool that could not keep its state consistent
// on disk; it serves nothing until meshd restarts and reloads it.
var ErrSpoolFailed = errors.New("flowreport: spool failed")

// Limits bound what a spool keeps: the oldest batches go first, and become a
// lost range (flowlog-v1 §5).
type Limits struct {
	MaxBytes int64
	MaxAge   time.Duration
}

// DiskLimits are a desktop's or server's (design §7).
func DiskLimits() Limits { return Limits{MaxBytes: 256 << 20, MaxAge: 24 * time.Hour} }

// lostRange is batches dropped and not yet committed past.
type lostRange struct {
	First   uint64 `json:"first"`
	Last    uint64 `json:"last"`
	Records uint64 `json:"records"`
	FromMS  int64  `json:"from_ms"`
	ToMS    int64  `json:"to_ms"`
}

type spoolState struct {
	BootID string     `json:"boot_id"`
	Next   uint64     `json:"next"`
	Lost   *lostRange `json:"lost,omitempty"`
}

type entry struct {
	sequence     uint64
	size         int64
	records      uint64
	fromMS, toMS int64
	digest       [sha256.Size]byte
}

// Spool keeps one Network's batches in a private directory until the
// receiver commits them. Its batches are always the contiguous sequences
// held_from..next-1, and its lost range ends below held_from. It is safe
// for concurrent use.
type Spool struct {
	mu      sync.Mutex
	root    *os.Root
	limits  Limits
	write   func(root *os.Root, name string, content []byte) error
	boot    [16]byte
	next    uint64
	lost    *lostRange
	entries []entry // by sequence, contiguous
	bytes   int64
	failed  bool
}

// Pending is a batch to send, with the request values of this send.
type Pending struct {
	Compressed []byte
	Request    *flowlogv1.FlowRequest
}

// OpenSpool opens dir, which must be private to the service, and goes on with
// the batches already there. A missing or damaged state starts a new boot,
// leaving the receiver to start again at held_from.
func OpenSpool(dir string, limits Limits, now time.Time) (*Spool, error) {
	return openSpool(dir, limits, now, writeAtomic)
}

func openSpool(dir string, limits Limits, now time.Time,
	write func(*os.Root, string, []byte) error,
) (*Spool, error) {
	if err := privatefile.PrepareDir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("flowreport: spool directory: %w", err)
	}
	if err := privatefile.RestrictDir(dir); err != nil {
		return nil, fmt.Errorf("flowreport: spool directory: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("flowreport: spool directory: %w", err)
	}
	spool := &Spool{root: root, limits: limits, write: write}
	if err := spool.load(now); err != nil {
		_ = root.Close()
		return nil, err
	}
	return spool, nil
}

// Close releases the directory.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.root.Close()
}

// load reads the state and the batches. Batches the state does not cover
// (at or past next, at or below the lost range) are removed; damaged ones,
// and every older one, become lost, so the batches left are contiguous.
func (s *Spool) load(now time.Time) error {
	state, boot, err := s.readState()
	if err != nil {
		return s.resetLocked()
	}
	s.boot, s.next, s.lost = boot, state.Next, state.Lost
	sequences, err := s.listBatches()
	if err != nil {
		return err
	}
	for _, sequence := range sequences {
		if sequence >= s.next || s.lost != nil && sequence <= s.lost.Last {
			_ = s.root.Remove(batchName(sequence))
			continue
		}
		item, err := s.readEntry(sequence)
		if err != nil {
			_ = s.root.Remove(batchName(sequence))
			s.loseThroughLocked(sequence, entry{sequence: sequence})
			continue
		}
		if len(s.entries) > 0 && s.entries[len(s.entries)-1].sequence+1 != sequence {
			// A hole: what is older cannot be sent in order.
			s.loseThroughLocked(sequence-1, entry{sequence: sequence - 1})
		}
		s.entries = append(s.entries, item)
		s.bytes += item.size
	}
	s.closeTailLocked()
	s.dropPastLimitsLocked(now)
	return s.saveStateLocked()
}

// closeTailLocked keeps the batches ending at next-1: when the last one is
// older (a sequence counted but its file missing), it and every older
// batch become lost, since they could not be followed in order.
func (s *Spool) closeTailLocked() {
	if len(s.entries) > 0 && s.entries[len(s.entries)-1].sequence+1 != s.next {
		s.loseThroughLocked(s.next-1, entry{sequence: s.next - 1})
	}
}

func (s *Spool) readState() (spoolState, [16]byte, error) {
	var boot [16]byte
	raw, err := readBounded(s.root, stateFile, maxStateSize)
	if err != nil {
		return spoolState{}, boot, err
	}
	var state spoolState
	if err := json.Unmarshal(raw, &state); err != nil {
		return spoolState{}, boot, err
	}
	decoded, err := hex.DecodeString(state.BootID)
	if err != nil || len(decoded) != 16 || state.Next == 0 {
		return spoolState{}, boot, errors.New("flowreport: damaged spool state")
	}
	if lost := state.Lost; lost != nil && (lost.First == 0 || lost.First > lost.Last || lost.Last >= state.Next) {
		state.Lost = nil
	}
	copy(boot[:], decoded)
	return state, boot, nil
}

// listBatches returns the batch files' sequences, sorted; stray temporary
// files are removed.
func (s *Spool) listBatches() ([]uint64, error) {
	directory, err := s.root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("flowreport: list spool: %w", err)
	}
	names, err := directory.Readdirnames(-1)
	_ = directory.Close()
	if err != nil {
		return nil, fmt.Errorf("flowreport: list spool: %w", err)
	}
	var sequences []uint64
	for _, name := range names {
		if strings.Contains(name, tempInfix) {
			_ = s.root.Remove(name)
			continue
		}
		digits, ok := strings.CutSuffix(name, batchSuffix)
		if !ok || len(digits) != 20 {
			continue
		}
		sequence, err := strconv.ParseUint(digits, 10, 64)
		if err == nil && sequence > 0 {
			sequences = append(sequences, sequence)
		}
	}
	slices.Sort(sequences)
	return sequences, nil
}

// readEntry reads a whole batch file and checks it against its digest.
func (s *Spool) readEntry(sequence uint64) (entry, error) {
	raw, err := readBounded(s.root, batchName(sequence), int64(headerSize)+flowlog.MaxBatchLength)
	if err != nil {
		return entry{}, err
	}
	item, _, err := parseBatchFile(sequence, raw)
	return item, err
}

func parseBatchFile(sequence uint64, raw []byte) (entry, []byte, error) {
	if len(raw) <= headerSize || string(raw[:len(batchMagic)]) != batchMagic {
		return entry{}, nil, errors.New("flowreport: damaged batch")
	}
	fields := raw[len(batchMagic):]
	item := entry{
		sequence: sequence, size: int64(len(raw)), records: binary.BigEndian.Uint64(fields),
		fromMS: int64(binary.BigEndian.Uint64(fields[8:])), toMS: int64(binary.BigEndian.Uint64(fields[16:])), //nolint:gosec // written by Add
	}
	copy(item.digest[:], fields[24:])
	payload := raw[headerSize:]
	if sha256.Sum256(payload) != item.digest {
		return entry{}, nil, errors.New("flowreport: damaged batch")
	}
	return item, payload, nil
}

// resetLocked starts a new boot and drops every batch. Memory changes only
// once the new state is on disk.
func (s *Spool) resetLocked() error {
	var boot [16]byte
	if _, err := rand.Read(boot[:]); err != nil {
		return fmt.Errorf("flowreport: boot id: %w", err)
	}
	raw, err := json.Marshal(spoolState{BootID: hex.EncodeToString(boot[:]), Next: 1})
	if err != nil {
		return fmt.Errorf("flowreport: encode spool state: %w", err)
	}
	if err := s.write(s.root, stateFile, raw); err != nil {
		return err
	}
	if sequences, err := s.listBatches(); err == nil {
		for _, sequence := range sequences {
			_ = s.root.Remove(batchName(sequence))
		}
	}
	s.boot, s.next, s.lost, s.entries, s.bytes, s.failed = boot, 1, nil, nil, 0, false
	return nil
}

func (s *Spool) saveStateLocked() error {
	raw, err := json.Marshal(spoolState{BootID: hex.EncodeToString(s.boot[:]), Next: s.next, Lost: s.lost})
	if err != nil {
		return fmt.Errorf("flowreport: encode spool state: %w", err)
	}
	return s.write(s.root, stateFile, raw)
}

// Add encodes window as the next batch and keeps it, dropping the oldest
// batches past the limits into the lost range. It takes window's records.
//
// The batch file goes to disk first, then the state that counts it, and
// only then is the batch offered. When the state cannot be saved the file
// is removed again and the sequence is not used; if even that fails the
// spool stops serving until a restart. On that restart the file is removed
// when the saved next does not count it, and kept and sent when it does (a
// save that failed after its rename): it was never offered before, so a
// sequence is never sent with two contents.
func (s *Spool) Add(window flowcount.Window, policy Policy, windowS uint32, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return ErrSpoolFailed
	}
	s.closeTailLocked()
	// A window that cannot be encoded uses no sequence: the caller reports
	// it, the receiver sees no gap.
	batch, err := buildBatch(window, s.boot, s.next, policy, windowS)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(batch.compressed)
	header := make([]byte, headerSize, headerSize+len(batch.compressed))
	copy(header, batchMagic)
	fields := header[len(batchMagic):]
	binary.BigEndian.PutUint64(fields, batch.records)
	binary.BigEndian.PutUint64(fields[8:], uint64(batch.fromMS)) //nolint:gosec // read back as int64
	binary.BigEndian.PutUint64(fields[16:], uint64(batch.toMS))  //nolint:gosec // read back as int64
	copy(fields[24:], digest[:])
	sequence := s.next
	if err := s.write(s.root, batchName(sequence), append(header, batch.compressed...)); err != nil {
		return err
	}
	s.next++
	if err := s.saveStateLocked(); err != nil {
		s.next--
		if removeErr := s.root.Remove(batchName(sequence)); removeErr != nil {
			s.failed = true
		}
		return err
	}
	s.entries = append(s.entries, entry{
		sequence: sequence, size: int64(len(header) + len(batch.compressed)), records: batch.records,
		fromMS: batch.fromMS, toMS: batch.toMS, digest: digest,
	})
	s.bytes += s.entries[len(s.entries)-1].size
	if s.dropPastLimitsLocked(now) {
		// Best effort: a head gap the receiver sees is written as lost
		// anyway (flowlog-v1 §5, rule 1).
		_ = s.saveStateLocked()
	}
	return nil
}

// dropPastLimitsLocked drops the oldest batches while the spool is past its
// size or holds a window older than MaxAge; the newest batch always stays.
func (s *Spool) dropPastLimitsLocked(now time.Time) bool {
	oldest := now.Add(-s.limits.MaxAge).UnixMilli()
	dropped := false
	for len(s.entries) > 1 && (s.limits.MaxBytes > 0 && s.bytes > s.limits.MaxBytes ||
		s.limits.MaxAge > 0 && s.entries[0].toMS < oldest) {
		s.loseThroughLocked(s.entries[0].sequence, s.entries[0])
		dropped = true
	}
	return dropped
}

// loseThroughLocked drops every batch at or below sequence into the lost
// range; dropped describes the last of them when it is not held.
func (s *Spool) loseThroughLocked(sequence uint64, dropped entry) {
	for len(s.entries) > 0 && s.entries[0].sequence <= sequence {
		item := s.entries[0]
		s.entries, s.bytes = s.entries[1:], s.bytes-item.size
		_ = s.root.Remove(batchName(item.sequence))
		s.addLost(item)
	}
	if dropped.records == 0 && dropped.sequence == sequence && (s.lost == nil || s.lost.Last < sequence) {
		s.addLost(dropped)
	}
}

func (s *Spool) addLost(item entry) {
	if s.lost == nil {
		s.lost = &lostRange{First: item.sequence, FromMS: item.fromMS, ToMS: item.toMS}
	}
	s.lost.First, s.lost.Last = min(s.lost.First, item.sequence), max(s.lost.Last, item.sequence)
	s.lost.Records += item.records
	switch {
	case item.toMS == 0:
		// A batch whose window is unknown (damaged, missing).
	case s.lost.ToMS == 0:
		s.lost.FromMS, s.lost.ToMS = item.fromMS, item.toMS
	default:
		s.lost.FromMS, s.lost.ToMS = min(s.lost.FromMS, item.fromMS), max(s.lost.ToMS, item.toMS)
	}
}

// Oldest is the batch to send first, or false when the spool is empty.
func (s *Spool) Oldest() (Pending, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingLocked(0)
}

// Get is batch sequence while the spool holds it (OUT_OF_ORDER); a batch
// below held_from is not held, and the caller sends Oldest instead. When
// that batch is damaged the next good one is offered: callers go by the
// returned Request.Sequence, never by the one they asked for.
func (s *Spool) Get(sequence uint64) (Pending, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) == 0 || sequence < s.entries[0].sequence {
		return Pending{}, false, nil
	}
	return s.pendingLocked(int(min(sequence-s.entries[0].sequence, uint64(len(s.entries))))) //nolint:gosec // bounded
}

// pendingLocked reads batch index. A batch whose file no longer matches its
// digest becomes lost with every older batch, and the next one is offered.
func (s *Spool) pendingLocked(index int) (Pending, bool, error) {
	if s.failed {
		return Pending{}, false, ErrSpoolFailed
	}
	for index < len(s.entries) {
		item := s.entries[index]
		raw, err := readBounded(s.root, batchName(item.sequence), item.size)
		if err == nil {
			if checked, payload, parseErr := parseBatchFile(item.sequence, raw); parseErr == nil &&
				checked.digest == item.digest {
				return Pending{Compressed: payload, Request: s.requestLocked(item.sequence)}, true, nil
			}
		}
		s.loseThroughLocked(item.sequence, item)
		_ = s.saveStateLocked()
		index = 0
	}
	return Pending{}, false, nil
}

func (s *Spool) requestLocked(sequence uint64) *flowlogv1.FlowRequest {
	request := &flowlogv1.FlowRequest{
		BootId: bytes.Clone(s.boot[:]), Sequence: sequence, HeldFrom: s.entries[0].sequence,
	}
	if lost := s.lost; lost != nil {
		request.Lost = &flowlogv1.Lost{
			FirstSequence: lost.First, LastSequence: lost.Last, Records: lost.Records, FromMs: lost.FromMS, ToMs: lost.ToMS,
		}
	}
	return request
}

// Commit drops every batch of boot at or below committed, and the lost
// range once committed reaches past it. An answer for another boot, or a
// committed sequence above the highest batch made, drops nothing: no
// answer may drop what was never sent.
func (s *Spool) Commit(boot []byte, committed uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !bytes.Equal(boot, s.boot[:]) {
		return errors.New("flowreport: commit for another boot")
	}
	if committed >= s.next {
		return fmt.Errorf("flowreport: committed %d past the last batch %d", committed, s.next-1)
	}
	for len(s.entries) > 0 && s.entries[0].sequence <= committed {
		item := s.entries[0]
		s.entries, s.bytes = s.entries[1:], s.bytes-item.size
		_ = s.root.Remove(batchName(item.sequence))
	}
	if s.lost != nil && s.lost.Last <= committed {
		s.lost = nil
		return s.saveStateLocked()
	}
	return nil
}

// Reset drops everything and starts a new boot: logging was turned off for
// the Network (DISABLED).
func (s *Spool) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resetLocked()
}

// Highest is the last batch made, 0 for none.
func (s *Spool) Highest() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.next - 1
}

func batchName(sequence uint64) string { return fmt.Sprintf("%020d%s", sequence, batchSuffix) }

func readBounded(root *os.Root, name string, limit int64) ([]byte, error) {
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("flowreport: file too large")
	}
	return raw, nil
}

func writeAtomic(root *os.Root, name string, content []byte) (resultErr error) {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Errorf("flowreport: temporary name: %w", err)
	}
	temp := name + tempInfix + hex.EncodeToString(suffix[:])
	file, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return fmt.Errorf("flowreport: write %s: %w", name, err)
	}
	defer func() {
		if resultErr != nil {
			_ = root.Remove(temp)
		}
	}()
	_, writeErr := file.Write(content)
	syncErr := file.Sync()
	if err := errors.Join(writeErr, syncErr, file.Close()); err != nil {
		return fmt.Errorf("flowreport: write %s: %w", name, err)
	}
	if err := root.Rename(temp, name); err != nil {
		return fmt.Errorf("flowreport: write %s: %w", name, err)
	}
	if err := privatefile.SyncDir(root); err != nil {
		return fmt.Errorf("flowreport: sync spool: %w", err)
	}
	return nil
}
