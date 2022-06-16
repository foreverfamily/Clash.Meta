package provider

import "time"

var (
	suspended bool
)

type UpdatableProvider interface {
	UpdatedAt() time.Time
}

func (f *fetcher) UpdatedAt() time.Time {
	return f.updatedAt
}

func (rp *ruleSetProvider) Close() error {
	rp.fetcher.Destroy()

	return nil
}

func Suspend(s bool) {
	suspended = s
}
