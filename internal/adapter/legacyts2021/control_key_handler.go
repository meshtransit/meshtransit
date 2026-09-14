package legacyts2021

import (
	"encoding/json"
	"net/http"
	"strconv"
)

type controlKeyResponseWire struct {
	PublicKey string `json:"publicKey"`
}

func (server *ControlServer) serveControlKey(
	response http.ResponseWriter,
	request *http.Request,
) {
	setResponseHeaders(response)
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		http.Error(response, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if request.URL.RawQuery != "v="+strconv.Itoa(supportedCapabilityVersion) {
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(controlKeyResponseWire{PublicKey: server.publicKey}); err != nil {
		server.logger.DebugContext(request.Context(), "control key response write failed")
	}
}
