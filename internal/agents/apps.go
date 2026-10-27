package agents

import (
	"context"
	"errors"

	"github.com/azuresong-afk/ai_railway/internal/apps"
)

// appsPage — приложений за один запрос при выборке своих.
const appsPage = 500

// AppsOf — приложения организации из internal/apps.
func AppsOf(s *apps.Service) Apps { return appsSource{s} }

type appsSource struct{ s *apps.Service }

// App — см. Apps.
func (a appsSource) App(ctx context.Context, id string) (AppInfo, error) {
	x, err := a.s.Application(ctx, id, "")
	if errors.Is(err, apps.ErrNotFound) {
		return AppInfo{}, ErrNoApp
	}
	if err != nil {
		return AppInfo{}, err
	}
	return AppInfo{ID: x.ID, Slug: x.Slug, OwnerID: x.OwnerID, Archived: x.Archived()}, nil
}

// Owned — см. Apps.
func (a appsSource) Owned(ctx context.Context, ownerID string) ([]string, error) {
	out := []string{}
	var after *apps.Cursor
	for {
		page, err := a.s.Applications(ctx, ownerID, after, appsPage)
		if err != nil {
			return nil, err
		}
		for _, x := range page {
			out = append(out, x.ID)
		}
		if len(page) < appsPage {
			return out, nil
		}
		last := page[len(page)-1]
		after = &apps.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
}
