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

// Package secfetch implements a simple middleware to protect HTTP handlers from cross-origin
// requests by leveraging Fetch Metadata.
//
// Suggested usage is to protect the entire http.Server.Handler and not single handlers.
// Example usage:
// 	srv := http.Server{
// 		Handler: secfetch.ProtectHandler(myServeMux),
// 		// Rest of configuration here.
// 	}
//
// This package supports a log-only mode to ease deployment and test the configuration before enforcing it.
//
// It is possible to exempt some handlers by registering them on a http.ServeMux after a previous
// one has been protected. A use case for this is CORS APIs that need to reply to cross-site
// requests.
// Example:
// 	var pmux http.ServeMux
// 	pmux.Handle("/protected1", protHandler1)
// 	pmux.Handle("/protected2", protHandler2)
// 	var mux http.ServeMux
// 	mux.Handle("/", secfetch.ProtectHandler(&pmux))
// 	mux.Handle("/unprotected", publicHandler)
package secfetch

import (
	"fmt"
	"net/http"
)

func allowed(r *http.Request) bool {
	site := r.Header.Get("sec-fetch-site")
	mode := r.Header.Get("sec-fetch-mode")

	if site == "" || // Browser did not send Sec-Fetch-Site, bail out.
		site == "none" || // The action was started by the user agent, not by a site.
		site == "same-site" ||
		site == "same-origin" {
		return true
	}

	// Here site is "cross-site", so let's just allow "GET" navigations
	if mode == "navigate" && r.Method == "GET" {
		return true
	}

	// Cross-site potentially dangerous request, reject.
	return false
}

// ProtectHandler isolates h from potentially malicious requests.
func ProtectHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed(r) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, "Invalid resource access")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// RequestLogger is a type that can log http requests.
type RequestLogger interface {
	// LogRequest is called with every request that needs to be logged.
	LogRequest(*http.Request)
}

// ProtectHandlerLogOnly behaves like ProtectHandler, but only logs requests that would have been
// blocked.
func ProtectHandlerLogOnly(h http.Handler, rl RequestLogger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed(r) {
			rl.LogRequest(r)
		}
		h.ServeHTTP(w, r)
	})
}
