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
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/api"
)

var ErrDupRequestKey = errors.New("dup request key")

var Requests = &requestMap{}

type requestMap struct {
	m sync.Map // *C.httpRequest -> *httpRequest
}

func (f *requestMap) StoreReq(key *C.httpRequest, req *httpRequest) error {
	if _, loaded := f.m.LoadOrStore(key, req); loaded {
		return ErrDupRequestKey
	}
	return nil
}

func (f *requestMap) GetReq(key *C.httpRequest) *httpRequest {
	if v, ok := f.m.Load(key); ok {
		return v.(*httpRequest)
	}
	return nil
}

func (f *requestMap) DeleteReq(key *C.httpRequest) {
	f.m.Delete(key)
}

func (f *requestMap) Clear() {
	f.m.Range(func(key, _ interface{}) bool {
		f.m.Delete(key)
		return true
	})
}

func requestFinalize(r *httpRequest) {
	r.Finalize(api.NormalFinalize)
}

func createRequest(r *C.httpRequest) *httpRequest {
	req := &httpRequest{
		req: r,
	}
	// NP: make sure filter will be deleted.
	runtime.SetFinalizer(req, requestFinalize)

	err := Requests.StoreReq(r, req)
	if err != nil {
		panic(fmt.Sprintf("createRequest failed, err: %s", err.Error()))
	}

	configId := uint64(r.configId)
	filterFactory := getOrCreateHttpFilterFactory(req.pluginName(), configId)
	f := filterFactory(req)
	req.httpFilter = f

	return req
}

func getRequest(r *C.httpRequest) *httpRequest {
	return Requests.GetReq(r)
}

//export envoyGoFilterOnHttpHeader
func envoyGoFilterOnHttpHeader(r *C.httpRequest, endStream, headerNum, headerBytes uint64) uint64 {
	var req *httpRequest
	phase := api.EnvoyRequestPhase(r.phase)
	if phase == api.DecodeHeaderPhase {
		req = createRequest(r)
	} else {
		req = getRequest(r)
		// early sendLocalReply may skip the whole decode phase
		if req == nil {
			req = createRequest(r)
		}
	}
	if req.pInfo.paniced {
		// goroutine panic in the previous state that could not sendLocalReply, delay terminating the request here,
		// to prevent error from spreading.
		req.sendPanicReply(req.pInfo.details)
		return uint64(api.LocalReply)
	}
	defer req.RecoverPanic()
	f := req.httpFilter

	var status api.StatusType
	switch phase {
	case api.DecodeHeaderPhase:
		header := &requestHeaderMapImpl{
			requestOrResponseHeaderMapImpl{
				headerMapImpl{
					request:     req,
					headerNum:   headerNum,
					headerBytes: headerBytes,
				},
			},
		}
		status = f.DecodeHeaders(header, endStream == 1)
	case api.DecodeTrailerPhase:
		header := &requestTrailerMapImpl{
			requestOrResponseTrailerMapImpl{
				headerMapImpl{
					request:     req,
					headerNum:   headerNum,
					headerBytes: headerBytes,
				},
			},
		}
		status = f.DecodeTrailers(header)
	case api.EncodeHeaderPhase:
		header := &responseHeaderMapImpl{
			requestOrResponseHeaderMapImpl{
				headerMapImpl{
					request:     req,
					headerNum:   headerNum,
					headerBytes: headerBytes,
				},
			},
		}
		status = f.EncodeHeaders(header, endStream == 1)
	case api.EncodeTrailerPhase:
		header := &responseTrailerMapImpl{
			requestOrResponseTrailerMapImpl{
				headerMapImpl{
					request:     req,
					headerNum:   headerNum,
					headerBytes: headerBytes,
				},
			},
		}
		status = f.EncodeTrailers(header)
	}
	return uint64(status)
}

//export envoyGoFilterOnHttpData
func envoyGoFilterOnHttpData(r *C.httpRequest, endStream, buffer, length uint64) uint64 {
	req := getRequest(r)
	if req.pInfo.paniced {
		// goroutine panic in the previous state that could not sendLocalReply, delay terminating the request here,
		// to prevent error from spreading.
		req.sendPanicReply(req.pInfo.details)
		return uint64(api.LocalReply)
	}
	defer req.RecoverPanic()

	f := req.httpFilter
	isDecode := api.EnvoyRequestPhase(r.phase) == api.DecodeDataPhase

	buf := &httpBuffer{
		request:             req,
		envoyBufferInstance: buffer,
		length:              length,
	}

	var status api.StatusType
	if isDecode {
		status = f.DecodeData(buf, endStream == 1)
	} else {
		status = f.EncodeData(buf, endStream == 1)
	}
	return uint64(status)
}

//export envoyGoFilterOnHttpDestroy
func envoyGoFilterOnHttpDestroy(r *C.httpRequest, reason uint64) {
	req := getRequest(r)
	// do nothing even when req.panic is true, since filter is already destroying.
	defer req.RecoverPanic()

	v := api.DestroyReason(reason)

	f := req.httpFilter
	f.OnDestroy(v)

	Requests.DeleteReq(r)

	// no one is using req now, we can remove it manually, for better performance.
	if v == api.Normal {
		runtime.SetFinalizer(req, nil)
		req.Finalize(api.GCFinalize)
	}
}
