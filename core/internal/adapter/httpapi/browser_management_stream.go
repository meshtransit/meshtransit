package httpapi

import "net/http"

// browserStreamingResponse lets an operations export through a browser
// session (K1d d1d-b): its file runs to 64 MiB, past the 256 KiB a buffered
// answer holds. Its 200 is admitted the moment the handler writes it, before
// any record: the same header and session checks as a buffered answer, then
// the records go straight to the client. Every page's read checks the session
// again in the database. Any other status stays buffered as for every request.
// The stream holds one browser slot up to the export's deadline; exports per
// replica and per Workspace stay capped by the export handler.
type browserStreamingResponse struct {
	*browserManagementResponse
	target  http.ResponseWriter
	admit   func(http.Header) error
	started bool
}

func (response *browserStreamingResponse) WriteHeader(status int) {
	if response.started || status != http.StatusOK || response.statusWrites != 0 || response.err != nil {
		response.browserManagementResponse.WriteHeader(status)
		return
	}
	response.statusWrites, response.status = 1, status
	if err := response.admit(response.header); err != nil {
		response.err = err
		return
	}
	response.started = true
}

func (response *browserStreamingResponse) Write(body []byte) (int, error) {
	if !response.started {
		return response.browserManagementResponse.Write(body)
	}
	return response.target.Write(body)
}

// Unwrap keeps the export's write deadlines reaching the transport once its
// 200 is admitted; before, no flush or hijack passes the check (review M2).
func (response *browserStreamingResponse) Unwrap() http.ResponseWriter {
	if !response.started {
		return nil
	}
	return response.target
}
