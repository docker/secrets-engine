package telemetry

type Tracker interface {
	TrackEvent(event any)

	Notify(err error, rawData ...interface{})
}

func NoopTracker() Tracker {
	return &noopTracker{}
}

type noopTracker struct{}

func (n noopTracker) Notify(error, ...interface{}) {
}

func (n noopTracker) TrackEvent(any) {
}

func AsyncWrapper(tracker Tracker) Tracker {
	return &asyncTracker{tracker: tracker}
}

type asyncTracker struct {
	tracker Tracker
}

func (a asyncTracker) Notify(err error, rawData ...interface{}) {
	go a.tracker.Notify(err, rawData...)
}

func (a asyncTracker) TrackEvent(event any) {
	go a.tracker.TrackEvent(event)
}
