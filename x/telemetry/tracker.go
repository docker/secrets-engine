// Copyright 2025-2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
