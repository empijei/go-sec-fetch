// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package secfetch

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var checkTests = []struct {
	name, site, mode, method string
	want                     bool
}{
	{
		name:   "no headers",
		site:   "",
		mode:   "",
		method: "POST",
		want:   true,
	},
	{
		name:   "ua initiated",
		site:   "none",
		mode:   "",
		method: "GET",
		want:   true,
	},
	{
		name:   "cors bug missing mode",
		site:   "cross-site",
		mode:   "",
		method: "OPTIONS",
		want:   true,
	},
	{
		name:   "same site",
		site:   "same-site",
		mode:   "websocket",
		method: "HEAD",
		want:   true,
	},
	{
		name:   "same origin",
		site:   "same-origin",
		mode:   "unrecognized",
		method: "POST",
		want:   true,
	},
	{
		name:   "cross origin nested navigate",
		site:   "cross-site",
		mode:   "nested-navigate",
		method: "GET",
		want:   true,
	},
	{
		name:   "cross origin head navigate",
		site:   "cross-site",
		mode:   "navigate",
		method: "HEAD",
		want:   true,
	},
	{
		name:   "cross origin navigate",
		site:   "cross-site",
		mode:   "navigate",
		method: "GET",
		want:   true,
	},
	{
		name:   "cross origin form submission",
		site:   "cross-site",
		mode:   "navigate",
		method: "POST",
		want:   false,
	},
	{
		name:   "cross origin no cors",
		site:   "cross-site",
		mode:   "no-cors",
		method: "GET",
		want:   false,
	},
	{
		name:   "cross origin cors",
		site:   "cross-site",
		mode:   "cors",
		method: "POST",
		want:   false,
	},
}

func TestProtectHandler(t *testing.T) {
	const data = "User Data"
	hf := ProtectHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, data)
	}))
	for _, tt := range checkTests {
		t.Run(tt.name, func(t *testing.T) {
			var r *http.Request
			if tt.method == "POST" {
				r = httptest.NewRequest(tt.method, "/", strings.NewReader("body"))
			} else {
				r = httptest.NewRequest(tt.method, "/", nil)
			}
			r.Header.Set("sec-fetch-site", tt.site)
			r.Header.Set("sec-fetch-mode", tt.mode)
			w := httptest.NewRecorder()
			hf.ServeHTTP(w, r)
			if w.Code != 200 && bytes.Contains(w.Body.Bytes(), []byte(data)) {
				t.Errorf("Status was set but user data leaked anyways")
			}
			if got := w.Code == 200; got != tt.want {
				t.Errorf("(%q,%q,%q): got %v, want %v", tt.method, tt.site, tt.mode, got, tt.want)
			}
		})
	}
}

type testRequestLogger struct {
	rs []*http.Request
}

func (t *testRequestLogger) LogRequest(r *http.Request) {
	t.rs = append(t.rs, r)
}

func (t *testRequestLogger) reset() {
	var rs []*http.Request
	t.rs = rs
}

func TestProtectHandlerLogOnly(t *testing.T) {
	const data = "User Data"
	var tl testRequestLogger
	hf := ProtectHandlerLogOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, data)
	}), &tl)
	for _, tt := range checkTests {
		t.Run(tt.name, func(t *testing.T) {
			var r *http.Request
			defer tl.reset()
			if tt.method == "POST" {
				r = httptest.NewRequest(tt.method, "/", strings.NewReader("body"))
			} else {
				r = httptest.NewRequest(tt.method, "/", nil)
			}
			r.Header.Set("sec-fetch-site", tt.site)
			r.Header.Set("sec-fetch-mode", tt.mode)
			w := httptest.NewRecorder()
			hf.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Errorf("Status was set in log only mode")
			}
			if !bytes.Contains(w.Body.Bytes(), []byte(data)) {
				t.Errorf("Response body was changed in log only mode")
			}
			if got := len(tl.rs) == 0; got != tt.want {
				t.Errorf("(%q,%q,%q): got %v, want %v", tt.method, tt.site, tt.mode, got, tt.want)
			}
		})
	}
}

func TestExempt(t *testing.T) {
	const private = "User Data"
	const public = "Public Data"
	var pmux http.ServeMux
	pmux.Handle("/protected", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, private)
	}))
	var mux http.ServeMux
	mux.Handle("/", ProtectHandler(&pmux))
	mux.Handle("/unprotected", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, public)
	}))

	type pathTest struct {
		name, site, mode, method, path string
		want                           bool
	}
	var tests []pathTest
	for _, tt := range checkTests {
		tests = append(tests, pathTest{
			name:   "protected " + tt.name,
			site:   tt.site,
			mode:   tt.mode,
			method: tt.method,
			path:   "/protected",
			want:   tt.want,
		})
	}
	for _, tt := range checkTests {
		tests = append(tests, pathTest{
			name:   "unprotected " + tt.name,
			site:   tt.site,
			mode:   tt.mode,
			method: tt.method,
			path:   "/unprotected",
			want:   true,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r *http.Request
			if tt.method == "POST" {
				r = httptest.NewRequest(tt.method, tt.path, strings.NewReader("body"))
			} else {
				r = httptest.NewRequest(tt.method, tt.path, nil)
			}
			r.Header.Set("sec-fetch-site", tt.site)
			r.Header.Set("sec-fetch-mode", tt.mode)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != 200 && bytes.Contains(w.Body.Bytes(), []byte(private)) {
				t.Errorf("Status was set but user data leaked anyways")
			}
			if got := w.Code == 200; got != tt.want {
				t.Errorf("(%q,%q,%q,%q): got %v, want %v", tt.method, tt.path, tt.site, tt.mode, got, tt.want)
			}
		})
	}
}
