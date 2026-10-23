package localapi

import (
	"errors"
	"net/http"

	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/dnsconfig"
)

// dnsQueryRequest is a diagnostic DNS question (meshctl dns query).
type dnsQueryRequest struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

type dnsQueryResolver struct {
	Address string `json:"address"`
	ViaExit bool   `json:"via_exit,omitempty"`
	Skipped bool   `json:"skipped,omitempty"`
}

type dnsQueryResponse struct {
	APIVersion    string             `json:"api_version"`
	Name          string             `json:"name"`
	Type          string             `json:"type"`
	Path          string             `json:"path"`
	Zone          string             `json:"zone,omitempty"`
	FailOpen      bool               `json:"fail_open,omitempty"`
	Resolvers     []dnsQueryResolver `json:"resolvers,omitempty"`
	RCode         string             `json:"rcode,omitempty"`
	Answers       []string           `json:"answers,omitempty"`
	ElapsedMillis int64              `json:"elapsed_ms"`
	// Error says why no answer came back, when none did.
	Error string `json:"error,omitempty"`
}

func (s *Server) handleDNSQuery(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		s.writeMethodNotAllowed(writer, http.MethodPost)

		return
	}
	input := dnsQueryRequest{}
	if !s.decodeJSONRequest(writer, request, &input) {
		return
	}
	report, err := s.service.QueryDNS(request.Context(), input.Name, input.Type)
	switch {
	case errors.Is(err, dnsconfig.ErrQueryName):
		s.writeError(writer, http.StatusBadRequest, "invalid_dns_query", "the name or record type is not valid")
		return
	case errors.Is(err, daemon.ErrDNSInactive):
		s.writeError(writer, http.StatusConflict, "dns_inactive", "MeshTransit DNS is not running on this node")
		return
	case err != nil && report.Path == "":
		s.writeServiceError(writer, err)
		return
	}
	response := dnsQueryResponse{
		APIVersion: apiVersion, Name: report.Name, Type: report.Type, Path: string(report.Path),
		Zone: report.Zone, FailOpen: report.FailOpen, RCode: report.RCode, Answers: report.Answers,
		ElapsedMillis: report.Elapsed.Milliseconds(),
	}
	if err != nil {
		response.Error = "no answer: " + err.Error()
	}
	for _, resolver := range report.Resolvers {
		response.Resolvers = append(response.Resolvers, dnsQueryResolver{
			Address: resolver.Address.String(), ViaExit: resolver.ViaExit, Skipped: resolver.Skipped,
		})
	}
	s.writeJSON(writer, http.StatusOK, response)
}
