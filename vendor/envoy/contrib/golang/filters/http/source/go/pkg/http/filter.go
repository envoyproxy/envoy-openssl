/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package http

/*
// ref https://github.com/golang/go/issues/25832

#cgo CFLAGS: -I../api
#cgo linux LDFLAGS: -Wl,-unresolved-symbols=ignore-all
#cgo darwin LDFLAGS: -Wl,-undefined,dynamic_lookup

#include <stdlib.h>
#include <string.h>

#include "api.h"

*/
import "C"
import (
	"fmt"
	"unsafe"

	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/api"
)

const (
	HTTP10 = "HTTP/1.0"
	HTTP11 = "HTTP/1.1"
	HTTP20 = "HTTP/2.0"
	HTTP30 = "HTTP/3.0"
)

var protocolsIdToName = map[uint64]string{
	0: HTTP10,
	1: HTTP11,
	2: HTTP20,
	3: HTTP30,
}

type panicInfo struct {
	paniced bool
	details string
}
type httpRequest struct {
	req        *C.httpRequest
	httpFilter api.StreamFilter
	pInfo      panicInfo
}

func (r *httpRequest) pluginName() string {
	return C.GoStringN(r.req.plugin_name.data, C.int(r.req.plugin_name.len))
}

func (r *httpRequest) sendPanicReply(details string) {
	defer r.RecoverPanic()
	cAPI.HttpSendPanicReply(unsafe.Pointer(r.req), details)
}

func (r *httpRequest) RecoverPanic() {
	if e := recover(); e != nil {
		// TODO: print an error message to Envoy error log.
		switch e {
		case errRequestFinished, errFilterDestroyed:
			// do nothing

		case errNotInGo:
			// We can not send local reply now, since not in go now,
			// will delay to the next time entering Go.
			r.pInfo = panicInfo{
				paniced: true,
				details: fmt.Sprint(e),
			}

		default:
			// The following safeReplyPanic should only may get errRequestFinished,
			// errFilterDestroyed or errNotInGo, won't hit this branch, so, won't dead loop here.

			// errInvalidPhase, or other panic, not from not-ok C return status.
			// It's safe to try send a local reply with 500 status.
			r.sendPanicReply(fmt.Sprint(e))
		}
	}
}

func (r *httpRequest) Continue(status api.StatusType) {
	if status == api.LocalReply {
		fmt.Printf("warning: LocalReply status is useless after sendLocalReply, ignoring")
		return
	}
	cAPI.HttpContinue(unsafe.Pointer(r.req), uint64(status))
}

func (r *httpRequest) SendLocalReply(responseCode int, bodyText string, headers map[string]string, grpcStatus int64, details string) {
	cAPI.HttpSendLocalReply(unsafe.Pointer(r.req), responseCode, bodyText, headers, grpcStatus, details)
}

func (r *httpRequest) Log(level api.LogType, message string) {
	// TODO performance optimization points:
	// Add a new goroutine to write logs asynchronously and avoid frequent cgo calls
	cAPI.HttpLog(level, fmt.Sprintf("[go_plugin_http][%v] %v", r.pluginName(), message))
}

func (r *httpRequest) StreamInfo() api.StreamInfo {
	return &streamInfo{
		request: r,
	}
}

func (r *httpRequest) Finalize(reason int) {
	cAPI.HttpFinalize(unsafe.Pointer(r.req), reason)
}

type streamInfo struct {
	request *httpRequest
}

func (s *streamInfo) GetRouteName() string {
	name, _ := cAPI.HttpGetStringValue(unsafe.Pointer(s.request.req), ValueRouteName)
	return name
}

func (s *streamInfo) FilterChainName() string {
	name, _ := cAPI.HttpGetStringValue(unsafe.Pointer(s.request.req), ValueFilterChainName)
	return name
}

func (s *streamInfo) Protocol() (string, bool) {
	if protocol, ok := cAPI.HttpGetIntegerValue(unsafe.Pointer(s.request.req), ValueProtocol); ok {
		if name, ok := protocolsIdToName[protocol]; ok {
			return name, true
		}
		panic(fmt.Sprintf("invalid protocol id: %d", protocol))
	}
	return "", false
}

func (s *streamInfo) ResponseCode() (uint32, bool) {
	if code, ok := cAPI.HttpGetIntegerValue(unsafe.Pointer(s.request.req), ValueResponseCode); ok {
		return uint32(code), true
	}
	return 0, false
}

func (s *streamInfo) ResponseCodeDetails() (string, bool) {
	return cAPI.HttpGetStringValue(unsafe.Pointer(s.request.req), ValueResponseCodeDetails)
}

func (s *streamInfo) AttemptCount() uint32 {
	count, _ := cAPI.HttpGetIntegerValue(unsafe.Pointer(s.request.req), ValueAttemptCount)
	return uint32(count)
}

type dynamicMetadata struct {
	request *httpRequest
}

func (s *streamInfo) DynamicMetadata() api.DynamicMetadata {
	return &dynamicMetadata{
		request: s.request,
	}
}

func (d *dynamicMetadata) Set(filterName string, key string, value interface{}) {
	cAPI.HttpSetDynamicMetadata(unsafe.Pointer(d.request.req), filterName, key, value)
}
