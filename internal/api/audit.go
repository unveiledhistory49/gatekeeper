package api

import (
	"net/http"
	"strconv"
)

func (d Deps) handleListAudit(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgOf(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var since int64
	if v := r.URL.Query().Get("since_seq"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			errJSON(w, http.StatusBadRequest, "invalid since_seq")
			return
		}
		since = n
	}
	limit, _ := paginate(r)
	entries, err := d.Store.ListAudit(r.Context(), orgID, since, limit)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot list audit log")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

func (d Deps) handleVerifyAudit(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgOf(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := d.Store.VerifyAuditChain(r.Context(), orgID); err != nil {
		errJSON(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
