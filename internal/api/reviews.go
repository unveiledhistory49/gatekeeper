package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/unveiledhistory49/gatekeeper/internal/store"
)

func (d Deps) handleCreateCampaign(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgOf(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &body); err != nil {
		errJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Name == "" {
		errJSON(w, http.StatusBadRequest, "name is required")
		return
	}
	now := time.Now().Unix()
	c := store.Campaign{
		ID: newID(), OrgID: orgID, Name: body.Name, Status: "open",
		CreatedBy: actorOf(r.Context()), CreatedAt: now,
	}
	if err := d.Store.CreateCampaign(r.Context(), c); err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot create campaign")
		return
	}
	// Auto-populate pending items from ALL current user_roles in the org.
	users, err := d.Store.ListUsers(r.Context(), orgID, 0, 0)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot seed review items")
		return
	}
	for _, u := range users {
		roles, err := d.Store.UserRoles(r.Context(), u.ID)
		if err != nil {
			continue
		}
		for _, role := range roles {
			_ = d.Store.AddReviewItem(r.Context(), store.ReviewItem{
				ID: newID(), CampaignID: c.ID, UserID: u.ID, RoleID: role.ID,
				Decision: "pending",
			})
		}
	}
	d.audit(r.Context(), "reviews.campaign.create", c.ID, body.Name)
	items, _ := d.Store.ListReviewItems(r.Context(), c.ID)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": c.ID, "org_id": c.OrgID, "name": c.Name, "status": c.Status,
		"created_by": c.CreatedBy, "created_at": c.CreatedAt, "closed_at": c.ClosedAt,
		"items": items,
	})
}

func (d Deps) handleListCampaigns(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgOf(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	cs, err := d.Store.ListCampaigns(r.Context(), orgID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot list campaigns")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"campaigns": cs})
}

func (d Deps) handleListItems(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgOf(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := chi.URLParam(r, "id")
	if _, err := d.Store.GetCampaign(r.Context(), orgID, id); err != nil {
		errJSON(w, http.StatusNotFound, "campaign not found")
		return
	}
	items, err := d.Store.ListReviewItems(r.Context(), id)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot list items")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// findItem locates a review item by ID within the caller's org. The store has
// no direct item lookup, so scan the org's campaigns.
func (d Deps) findItem(r *http.Request, orgID, itemID string) (store.ReviewItem, error) {
	cs, err := d.Store.ListCampaigns(r.Context(), orgID)
	if err != nil {
		return store.ReviewItem{}, err
	}
	for _, c := range cs {
		items, err := d.Store.ListReviewItems(r.Context(), c.ID)
		if err != nil {
			continue
		}
		for _, it := range items {
			if it.ID == itemID {
				return it, nil
			}
		}
	}
	return store.ReviewItem{}, store.ErrNotFound
}

func (d Deps) handleDecideItem(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgOf(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	itemID := chi.URLParam(r, "itemID")
	var body struct {
		Decision string `json:"decision"`
	}
	if err := decodeJSON(r, &body); err != nil {
		errJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Decision != "certified" && body.Decision != "revoked" {
		errJSON(w, http.StatusBadRequest, "decision must be certified or revoked")
		return
	}
	it, err := d.findItem(r, orgID, itemID)
	if err != nil {
		errJSON(w, http.StatusNotFound, "review item not found")
		return
	}
	now := time.Now().Unix()
	reviewer := actorOf(r.Context())
	// Revoke BEFORE recording the decision: if role removal fails the item
	// stays pending and the reviewer can retry. Recording first would wedge
	// the item in a decided-but-not-enforced state (DecideReviewItem rejects
	// re-decision).
	if body.Decision == "revoked" {
		roles, err := d.Store.UserRoles(r.Context(), it.UserID)
		if err != nil {
			errJSON(w, http.StatusInternalServerError, "cannot load entitlements")
			return
		}
		kept := make([]string, 0, len(roles))
		for _, role := range roles {
			if role.ID != it.RoleID {
				kept = append(kept, role.ID)
			}
		}
		if err := d.Store.SetUserRoles(r.Context(), orgID, it.UserID, kept); err != nil {
			errJSON(w, http.StatusInternalServerError, "cannot revoke role")
			return
		}
		d.audit(r.Context(), "reviews.revoke_role", it.UserID, it.RoleID)
	}
	if err := d.Store.DecideReviewItem(r.Context(), it.CampaignID, itemID, reviewer, body.Decision, now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			errJSON(w, http.StatusNotFound, "review item not found")
			return
		}
		errJSON(w, http.StatusConflict, err.Error())
		return
	}
	d.audit(r.Context(), "reviews.decide", itemID, body.Decision)
	it.Decision = body.Decision
	it.ReviewerID = reviewer
	it.DecidedAt = now
	writeJSON(w, http.StatusOK, it)
}

func (d Deps) handleCloseCampaign(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgOf(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := chi.URLParam(r, "id")
	if err := d.Store.CloseCampaign(r.Context(), orgID, id, time.Now().Unix()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			errJSON(w, http.StatusNotFound, "campaign not found")
			return
		}
		errJSON(w, http.StatusConflict, err.Error())
		return
	}
	d.audit(r.Context(), "reviews.campaign.close", id, "")
	c, _ := d.Store.GetCampaign(r.Context(), orgID, id)
	writeJSON(w, http.StatusOK, c)
}
