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
	"reflect"
	"runtime"
	"strings"
	"unsafe"

	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/api"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	ValueRouteName           = 1
	ValueFilterChainName     = 2
	ValueProtocol            = 3
	ValueResponseCode        = 4
	ValueResponseCodeDetails = 5
	ValueAttemptCount        = 6
)

type httpCApiImpl struct{}

// Only CAPIOK is expected, otherwise, it means unexpected stage when invoke C API,
// panic here and it will be recover in the Go entry function (TODO).
func handleCApiStatus(status C.CAPIStatus) {
	switch status {
	case C.CAPIOK:
		return
	case C.CAPIFilterIsGone:
		panic(errRequestFinished)
	case C.CAPIFilterIsDestroy:
		panic(errFilterDestroyed)
	case C.CAPINotInGo:
		panic(errNotInGo)
	case C.CAPIInvalidPhase:
		panic(errInvalidPhase)
	}
}

func (c *httpCApiImpl) HttpContinue(r unsafe.Pointer, status uint64) {
	res := C.envoyGoFilterHttpContinue(r, C.int(status))
	handleCApiStatus(res)
}

// Only may panic with errRequestFinished, errFilterDestroyed or errNotInGo,
// won't panic with errInvalidPhase and others, otherwise will cause deadloop, see RecoverPanic for the details.
func (c *httpCApiImpl) HttpSendLocalReply(r unsafe.Pointer, response_code int, body_text string, headers map[string]string, grpc_status int64, details string) {
	hLen := len(headers)
	strs := make([]string, 0, hLen)
	for k, v := range headers {
		strs = append(strs, k, v)
	}
	res := C.envoyGoFilterHttpSendLocalReply(r, C.int(response_code), unsafe.Pointer(&body_text), unsafe.Pointer(&strs), C.longlong(grpc_status), unsafe.Pointer(&details))
	handleCApiStatus(res)
}

func (c *httpCApiImpl) HttpSendPanicReply(r unsafe.Pointer, details string) {
	res := C.envoyGoFilterHttpSendPanicReply(r, unsafe.Pointer(&details))
	handleCApiStatus(res)
}

func (c *httpCApiImpl) HttpGetHeader(r unsafe.Pointer, key *string, value *string) {
	res := C.envoyGoFilterHttpGetHeader(r, unsafe.Pointer(key), unsafe.Pointer(value))
	handleCApiStatus(res)
}

func (c *httpCApiImpl) HttpCopyHeaders(r unsafe.Pointer, num uint64, bytes uint64) map[string][]string {
	// TODO: use a memory pool for better performance,
	// since these go strings in strs, will be copied into the following map.
	strs := make([]string, num*2)
	// but, this buffer can not be reused safely,
	// since strings may refer to this buffer as string data, and string is const in go.
	// we have to make sure the all strings is not using before reusing,
	// but strings may be alive beyond the request life.
	buf := make([]byte, bytes)
	sHeader := (*reflect.SliceHeader)(unsafe.Pointer(&strs))
	bHeader := (*reflect.SliceHeader)(unsafe.Pointer(&buf))

	res := C.envoyGoFilterHttpCopyHeaders(r, unsafe.Pointer(sHeader.Data), unsafe.Pointer(bHeader.Data))
	handleCApiStatus(res)

	m := make(map[string][]string, num)
	for i := uint64(0); i < num*2; i += 2 {
		key := strs[i]
		value := strs[i+1]

		if v, found := m[key]; !found {
			m[key] = []string{value}
		} else {
			m[key] = append(v, value)
		}
	}
	runtime.KeepAlive(buf)
	return m
}

func (c *httpCApiImpl) HttpSetHeader(r unsafe.Pointer, key *string, value *string, add bool) {
	var act C.headerAction
	if add {
		act = C.HeaderAdd
	} else {
		act = C.HeaderSet
	}
	res := C.envoyGoFilterHttpSetHeaderHelper(r, unsafe.Pointer(key), unsafe.Pointer(value), act)
	handleCApiStatus(res)
}

func (c *httpCApiImpl) HttpRemoveHeader(r unsafe.Pointer, key *string) {
	res := C.envoyGoFilterHttpRemoveHeader(r, unsafe.Pointer(key))
	handleCApiStatus(res)
}

func (c *httpCApiImpl) HttpGetBuffer(r unsafe.Pointer, bufferPtr uint64, value *string, length uint64) {
	buf := make([]byte, length)
	bHeader := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
	sHeader := (*reflect.StringHeader)(unsafe.Pointer(value))
	sHeader.Data = bHeader.Data
	sHeader.Len = int(length)
	res := C.envoyGoFilterHttpGetBuffer(r, C.ulonglong(bufferPtr), unsafe.Pointer(bHeader.Data))
	handleCApiStatus(res)
}

func (c *httpCApiImpl) HttpSetBufferHelper(r unsafe.Pointer, bufferPtr uint64, value string, action api.BufferAction) {
	sHeader := (*reflect.StringHeader)(unsafe.Pointer(&value))
	var act C.bufferAction
	switch action {
	case api.SetBuffer:
		act = C.Set
	case api.AppendBuffer:
		act = C.Append
	case api.PrependBuffer:
		act = C.Prepend
	}
	res := C.envoyGoFilterHttpSetBufferHelper(r, C.ulonglong(bufferPtr), unsafe.Pointer(sHeader.Data), C.int(sHeader.Len), act)
	handleCApiStatus(res)
}

func (c *httpCApiImpl) HttpCopyTrailers(r unsafe.Pointer, num uint64, bytes uint64) map[string][]string {
	// TODO: use a memory pool for better performance,
	// but, should be very careful, since string is const in go,
	// and we have to make sure the strings is not using before reusing,
	// strings may be alive beyond the request life.
	strs := make([]string, num*2)
	buf := make([]byte, bytes)
	sHeader := (*reflect.SliceHeader)(unsafe.Pointer(&strs))
	bHeader := (*reflect.SliceHeader)(unsafe.Pointer(&buf))

	res := C.envoyGoFilterHttpCopyTrailers(r, unsafe.Pointer(sHeader.Data), unsafe.Pointer(bHeader.Data))
	handleCApiStatus(res)

	m := make(map[string][]string, num)
	for i := uint64(0); i < num*2; i += 2 {
		key := strs[i]
		value := strs[i+1]

		if v, found := m[key]; !found {
			m[key] = []string{value}
		} else {
			m[key] = append(v, value)
		}
	}
	return m
}

func (c *httpCApiImpl) HttpSetTrailer(r unsafe.Pointer, key *string, value *string) {
	res := C.envoyGoFilterHttpSetTrailer(r, unsafe.Pointer(key), unsafe.Pointer(value))
	handleCApiStatus(res)
}

func (c *httpCApiImpl) HttpGetStringValue(r unsafe.Pointer, id int) (string, bool) {
	var value string
	// TODO: add a lock to protect filter->req_->strValue field in the Envoy side, from being writing concurrency,
	// since there might be multiple concurrency goroutines invoking this API on the Go side.
	res := C.envoyGoFilterHttpGetStringValue(r, C.int(id), unsafe.Pointer(&value))
	if res == C.CAPIValueNotFound {
		return "", false
	}
	handleCApiStatus(res)
	// copy the memory from c to Go.
	return strings.Clone(value), true
}

func (c *httpCApiImpl) HttpGetIntegerValue(r unsafe.Pointer, id int) (uint64, bool) {
	var value uint64
	res := C.envoyGoFilterHttpGetIntegerValue(r, C.int(id), unsafe.Pointer(&value))
	if res == C.CAPIValueNotFound {
		return 0, false
	}
	handleCApiStatus(res)
	return value, true
}

func (c *httpCApiImpl) HttpSetDynamicMetadata(r unsafe.Pointer, filterName string, key string, value interface{}) {
	v, err := structpb.NewValue(value)
	if err != nil {
		panic(err)
	}
	buf, err := proto.Marshal(v)
	if err != nil {
		panic(err)
	}
	res := C.envoyGoFilterHttpSetDynamicMetadata(r, unsafe.Pointer(&filterName), unsafe.Pointer(&key), unsafe.Pointer(&buf))
	handleCApiStatus(res)
}

func (c *httpCApiImpl) HttpLog(level api.LogType, message string) {
	C.envoyGoFilterHttpLog(C.uint32_t(level), unsafe.Pointer(&message))
}

func (c *httpCApiImpl) HttpFinalize(r unsafe.Pointer, reason int) {
	C.envoyGoFilterHttpFinalize(r, C.int(reason))
}

var cAPI api.HttpCAPI = &httpCApiImpl{}

// SetHttpCAPI for mock cAPI
func SetHttpCAPI(api api.HttpCAPI) {
	cAPI = api
}
