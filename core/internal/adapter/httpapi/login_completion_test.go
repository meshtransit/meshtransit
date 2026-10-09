package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
	"go.uber.org/goleak"
)

type completionTestPort struct {
	calls int
	hook  func(context.Context)
	err   error
}

func (port *completionTestPort) CompleteBrowser(ctx context.Context, _ oidcauth.CallbackCommand) (oidcauth.CallbackResult, error) {
	port.calls++
	if port.hook != nil {
		port.hook(ctx)
	}
	return oidcauth.CallbackResult{}, port.err
}

func TestLoginCompletionDoesNotTurnSyntaxOrErrorsIntoSession(t *testing.T) {
	t.Parallel()
	for _, cause := range []struct {
		name string
		err  error
	}{
		{name: "zero success"},
		{name: "unknown commit", err: errors.Join(oidcauth.ErrCallbackUnavailable, oidcauth.ErrCommitOutcomeUnknown)},
		{name: "private dependency", err: errors.New("private-token-code-cookie")},
	} {
		t.Run(cause.name, func(t *testing.T) {
			t.Parallel()
			fixture := newContinuationGateFixture(t)
			gate := mustContinuationGate(t, fixture.options)
			port := &completionTestPort{err: cause.err}
			completion, err := NewLoginCompletion(LoginCompletionOptions{
				Admission: gate, Callback: port, ReturnRouteID: fixture.input.Route().ReturnRouteID(), ReturnPath: "/console",
				Observer: NewLoginCompletionTelemetry(), RequestTimeout: 2 * time.Second, MaxConcurrent: 1,
			})
			if err != nil {
				t.Fatal(err)
			}
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			err = completion.Complete(response, preparedContinuationRequest(t, fixture, gate))
			if err == nil || port.calls != 1 || response.statusWrites != 0 || response.Body.Len() != 0 ||
				response.Header().Get("Set-Cookie") != "" || response.Header().Get("Location") != "" ||
				strings.Contains(err.Error(), "private-token-code-cookie") {
				t.Fatal("unconfirmed syntax/error released response or private data")
			}
			if cause.name == "unknown commit" && !errors.Is(err, oidcauth.ErrCommitOutcomeUnknown) {
				t.Fatal("lost unknown commit category")
			}
		})
	}
}

var _ BrowserLoginCompleter = (*completionTestPort)(nil)
var _ http.ResponseWriter = (*continuationStatusRecorder)(nil)

func completionTestOptions(t *testing.T) (LoginCompletionOptions, *continuationGateFixture, *completionTestPort) {
	t.Helper()
	fixture := newContinuationGateFixture(t)
	port := &completionTestPort{}
	options := LoginCompletionOptions{Admission: mustContinuationGate(t, fixture.options), Callback: port,
		ReturnRouteID: fixture.input.Route().ReturnRouteID(), ReturnPath: "/console",
		Observer: NewLoginCompletionTelemetry(), RequestTimeout: 2 * time.Second, MaxConcurrent: 1}
	return options, fixture, port
}

func TestLoginCompletionRejectsConstructionAndUnsafeReturnMapping(t *testing.T) {
	t.Parallel()
	var missing *completionTestPort
	var missingTelemetry *LoginCompletionTelemetry
	for _, test := range []struct {
		name   string
		change func(*LoginCompletionOptions)
	}{
		{name: "no admission", change: func(o *LoginCompletionOptions) { o.Admission = nil }},
		{name: "zero admission", change: func(o *LoginCompletionOptions) { o.Admission = &LoginContinuationGate{} }},
		{name: "no callback", change: func(o *LoginCompletionOptions) { o.Callback = nil }},
		{name: "typed nil callback", change: func(o *LoginCompletionOptions) { o.Callback = missing }},
		{name: "typed nil observer", change: func(o *LoginCompletionOptions) { o.Observer = missingTelemetry }},
		{name: "timeout", change: func(o *LoginCompletionOptions) { o.RequestTimeout = 0 }},
		{name: "long timeout", change: func(o *LoginCompletionOptions) { o.RequestTimeout = 31 * time.Second }},
		{name: "capacity", change: func(o *LoginCompletionOptions) { o.MaxConcurrent = 0 }},
		{name: "large capacity", change: func(o *LoginCompletionOptions) { o.MaxConcurrent = 129 }},
		{name: "different return id", change: func(o *LoginCompletionOptions) { o.ReturnRouteID = "other" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options, _, _ := completionTestOptions(t)
			test.change(&options)
			if completion, err := NewLoginCompletion(options); completion != nil || !errors.Is(err, ErrInvalidLoginCompletion) {
				t.Fatal("invalid completion constructed")
			}
		})
	}
	for _, value := range []string{"", "https://evil.example.test/", "//evil.example.test", "/x?code=a", "/x#state", "/x%2f", "/x\\y",
		"/x/../y", "/x//y", "/x/", "/auth", "/auth/v1/login/continue", "/é", "/" + strings.Repeat("x", 256)} {
		t.Run("unsafe path "+value, func(t *testing.T) {
			t.Parallel()
			options, _, _ := completionTestOptions(t)
			options.ReturnPath = value
			if completion, err := NewLoginCompletion(options); completion != nil || !errors.Is(err, ErrInvalidLoginCompletion) {
				t.Fatal("unsafe return path accepted")
			}
		})
	}
	for _, value := range []string{"/", "/console", "/" + strings.Repeat("x", 255)} {
		options, _, _ := completionTestOptions(t)
		options.ReturnPath = value
		if _, err := NewLoginCompletion(options); err != nil {
			t.Fatal("canonical local path rejected", err)
		}
	}
}

func TestLoginCompletionRequiresPristineWriterAndProtectedAdmission(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"Set-Cookie", "Location", "Content-Length", "Transfer-Encoding", "Authorization", "set-cookie", "missing csrf", "get"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			options, fixture, port := completionTestOptions(t)
			completion, err := NewLoginCompletion(options)
			if err != nil {
				t.Fatal(err)
			}
			request := preparedContinuationRequest(t, fixture, options.Admission)
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			switch name {
			case "missing csrf":
				request.Header.Del("X-Meshtransit-Csrf")
			case "get":
				request.Method = http.MethodGet
			default:
				response.Header()[name] = []string{"untrusted"}
			}
			if err := completion.Complete(response, request); err == nil || port.calls != 0 || response.statusWrites != 0 || response.Body.Len() != 0 {
				t.Fatal("dirty writer/unprotected request reached authority or wrote response")
			}
		})
	}
}

type completionDeadlineRecorder struct {
	*continuationStatusRecorder
	read, write      []time.Time
	failRestore      bool
	failWriteRestore bool
}

func (recorder *completionDeadlineRecorder) SetReadDeadline(at time.Time) error {
	recorder.read = append(recorder.read, at)
	if recorder.failRestore && len(recorder.read) == 2 {
		return errors.New("private transport")
	}
	return nil
}

func (recorder *completionDeadlineRecorder) SetWriteDeadline(at time.Time) error {
	recorder.write = append(recorder.write, at)
	if recorder.failWriteRestore && len(recorder.write) == 2 {
		return errors.New("private transport")
	}
	return nil
}

func TestLoginCompletionOwnsLiveWholeContextAfterAdmission(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"restored", "read restore failure", "write restore failure"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			options, fixture, port := completionTestOptions(t)
			recorder := &completionDeadlineRecorder{continuationStatusRecorder: &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()},
				read: []time.Time{}, write: []time.Time{}, failRestore: mode == "read restore failure",
				failWriteRestore: mode == "write restore failure"}
			port.hook = func(ctx context.Context) {
				deadline, ok := ctx.Deadline()
				if ctx.Err() != nil || !ok || !deadline.Equal(recorder.read[1]) || !deadline.Equal(recorder.write[1]) ||
					!recorder.read[0].Before(deadline) {
					t.Error("gate child deadline/context became whole pipeline lifetime")
				}
			}
			completion, err := NewLoginCompletion(options)
			if err != nil {
				t.Fatal(err)
			}
			if err := completion.Complete(recorder, preparedContinuationRequest(t, fixture, options.Admission)); err == nil {
				t.Fatal("zero result emitted Session")
			}
			want := 1
			if mode != "restored" {
				want = 0
			}
			if port.calls != want || recorder.statusWrites != 0 {
				t.Fatal("transport restore failure reached effects")
			}
		})
	}
}

func TestLoginCompletionDoesNotExtendParentDeadline(t *testing.T) {
	t.Parallel()
	options, fixture, port := completionTestOptions(t)
	ctx, cancel := context.WithTimeout(t.Context(), 750*time.Millisecond)
	defer cancel()
	want, _ := ctx.Deadline()
	port.hook = func(ctx context.Context) {
		deadline, ok := ctx.Deadline()
		if !ok || !deadline.Equal(want) {
			t.Error("parent deadline extended")
		}
	}
	completion, err := NewLoginCompletion(options)
	if err != nil {
		t.Fatal(err)
	}
	request := preparedContinuationRequest(t, fixture, options.Admission).WithContext(ctx)
	if err := completion.Complete(newLoginHTTPRecorder(), request); err == nil || port.calls != 1 {
		t.Fatal("parent deadline check did not traverse admission/application")
	}
}

func TestLoginCompletionRejectsAbsentReceiverWriterAndRequest(t *testing.T) {
	t.Parallel()
	var absent *LoginCompletion
	for _, completion := range []*LoginCompletion{absent, {}} {
		if err := completion.Complete(newLoginHTTPRecorder(), nil); !errors.Is(err, ErrLoginCompletionUnavailable) {
			t.Fatal("absent completion accepted")
		}
	}
	options, fixture, _ := completionTestOptions(t)
	completion, err := NewLoginCompletion(options)
	if err != nil {
		t.Fatal(err)
	}
	var missingWriter *loginHTTPRecorder
	request := preparedContinuationRequest(t, fixture, options.Admission)
	if err := completion.Complete(missingWriter, request); !errors.Is(err, ErrLoginCompletionUnavailable) {
		t.Fatal("typed nil writer accepted")
	}
}

func TestLoginCompletionCapacityRetainsOwnershipUntilWholeDeadlineJoins(t *testing.T) {
	// Process-global leak inventory runs outside fake-clock work and before parallel tests.
	defer goleak.VerifyNone(t)
	synctest.Test(t, func(t *testing.T) {
		options, fixture, port := completionTestOptions(t)
		completion, err := NewLoginCompletion(options)
		if err != nil {
			t.Fatal(err)
		}
		request := preparedContinuationRequest(t, fixture, options.Admission)
		entered := make(chan struct{})
		port.hook = func(ctx context.Context) { close(entered); <-ctx.Done() }
		var joined sync.WaitGroup
		done := make(chan error, 1)
		joined.Go(func() { done <- completion.Complete(newLoginHTTPRecorder(), request) })
		<-entered
		second := preparedContinuationRequest(t, fixture, options.Admission)
		if err := completion.Complete(newLoginHTTPRecorder(), second); !errors.Is(err, ErrLoginCompletionSaturated) {
			t.Fatal("slot released after admission or second request queued")
		}
		synctest.Wait()
		time.Sleep(options.RequestTimeout)
		synctest.Wait()
		if err := <-done; err == nil || port.calls != 1 {
			t.Fatal("whole deadline did not suppress release")
		}
		joined.Wait()
	})
}

func FuzzLoginReturnPath(f *testing.F) {
	f.Add("/console")
	f.Add("//evil.example.test")
	f.Fuzz(func(t *testing.T, value string) {
		if !validLoginReturnPath(value) {
			return
		}
		if value == "" || len(value) > 256 || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") ||
			strings.ContainsAny(value, "?%#\\\r\n") || value == "/auth" || strings.HasPrefix(value, "/auth/") {
			t.Fatal("accepted path crossed local/no-secret destination boundary")
		}
	})
}
