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

import (
	"strconv"
	"unsafe"

	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/api"
)

// panic error messages when C API return not ok
const (
	errRequestFinished = "request has been finished"
	errFilterDestroyed = "golang filter has been destroyed"
	errNotInGo         = "not proccessing Go"
	errInvalidPhase    = "invalid phase, maybe headers/buffer already continued"
)

// api.HeaderMap
type headerMapImpl struct {
	request     *httpRequest
	headers     map[string][]string
	headerNum   uint64
	headerBytes uint64
}

// ByteSize return size of HeaderMap
func (h *headerMapImpl) ByteSize() uint64 {
	return h.headerBytes
}

type requestOrResponseHeaderMapImpl struct {
	headerMapImpl
}

func (h *requestOrResponseHeaderMapImpl) initHeaders() {
	if h.headers == nil {
		h.headers = cAPI.HttpCopyHeaders(unsafe.Pointer(h.request.req), h.headerNum, h.headerBytes)
	}
}

func (h *requestOrResponseHeaderMapImpl) GetRaw(key string) string {
	var value string
	cAPI.HttpGetHeader(unsafe.Pointer(h.request.req), &key, &value)
	return value
}

func (h *requestOrResponseHeaderMapImpl) Get(key string) (string, bool) {
	h.initHeaders()
	value, ok := h.headers[key]
	if !ok {
		return "", false
	}
	return value[0], ok
}

func (h *requestOrResponseHeaderMapImpl) Values(key string) []string {
	h.initHeaders()
	value, ok := h.headers[key]
	if !ok {
		return nil
	}
	return value
}

func (h *requestOrResponseHeaderMapImpl) Set(key, value string) {
	// Get all header values first before setting a value, since the set operation may not take affects immediately
	// when it's invoked in a Go thread, instead, it will post a callback to run in the envoy worker thread.
	// Otherwise, we may get outdated values in a following Get call.
	h.initHeaders()
	if h.headers != nil {
		h.headers[key] = []string{value}
	}
	cAPI.HttpSetHeader(unsafe.Pointer(h.request.req), &key, &value, false)
}

func (h *requestOrResponseHeaderMapImpl) Add(key, value string) {
	h.initHeaders()
	if h.headers != nil {
		if hdrs, found := h.headers[key]; found {
			h.headers[key] = append(hdrs, value)
		} else {
			h.headers[key] = []string{value}
		}
	}
	cAPI.HttpSetHeader(unsafe.Pointer(h.request.req), &key, &value, true)
}

func (h *requestOrResponseHeaderMapImpl) Del(key string) {
	// Get all header values first before removing a key, since the del operation may not take affects immediately
	// when it's invoked in a Go thread, instead, it will post a callback to run in the envoy worker thread.
	// Otherwise, we may get outdated values in a following Get call.
	h.initHeaders()
	delete(h.headers, key)
	cAPI.HttpRemoveHeader(unsafe.Pointer(h.request.req), &key)
}

func (h *requestOrResponseHeaderMapImpl) Range(f func(key, value string) bool) {
	h.initHeaders()
	for key, values := range h.headers {
		for _, value := range values {
			if !f(key, value) {
				return
			}
		}
	}
}

// api.RequestHeaderMap
type requestHeaderMapImpl struct {
	requestOrResponseHeaderMapImpl
}

var _ api.RequestHeaderMap = (*requestHeaderMapImpl)(nil)

func (h *requestHeaderMapImpl) Protocol() string {
	v, _ := h.Get(":protocol")
	return v
}

func (h *requestHeaderMapImpl) Scheme() string {
	v, _ := h.Get(":scheme")
	return v
}

func (h *requestHeaderMapImpl) Method() string {
	v, _ := h.Get(":method")
	return v
}

func (h *requestHeaderMapImpl) Path() string {
	v, _ := h.Get(":path")
	return v
}

func (h *requestHeaderMapImpl) Host() string {
	v, _ := h.Get(":authority")
	return v
}

// api.ResponseHeaderMap
type responseHeaderMapImpl struct {
	requestOrResponseHeaderMapImpl
}

var _ api.ResponseHeaderMap = (*responseHeaderMapImpl)(nil)

func (h *responseHeaderMapImpl) Status() (int, bool) {
	if str, ok := h.Get(":status"); ok {
		v, _ := strconv.Atoi(str)
		return v, true
	}
	return 0, false
}

type requestOrResponseTrailerMapImpl struct {
	headerMapImpl
}

func (h *requestOrResponseTrailerMapImpl) initHeaders() {
	if h.headers == nil {
		h.headers = cAPI.HttpCopyTrailers(unsafe.Pointer(h.request.req), h.headerNum, h.headerBytes)
	}
}

func (h *requestOrResponseTrailerMapImpl) GetRaw(key string) string {
	panic("unsupported yet")
}

func (h *requestOrResponseTrailerMapImpl) Get(key string) (string, bool) {
	h.initHeaders()
	value, ok := h.headers[key]
	if !ok {
		return "", false
	}
	return value[0], ok
}

func (h *requestOrResponseTrailerMapImpl) Values(key string) []string {
	h.initHeaders()
	value, ok := h.headers[key]
	if !ok {
		return nil
	}
	return value
}

func (h *requestOrResponseTrailerMapImpl) Set(key, value string) {
	// Get all header values first before setting a value, since the set operation may not take affects immediately
	// when it's invoked in a Go thread, instead, it will post a callback to run in the envoy worker thread.
	// Otherwise, we may get outdated values in a following Get call.
	h.initHeaders()
	if h.headers != nil {
		h.headers[key] = []string{value}
	}

	cAPI.HttpSetTrailer(unsafe.Pointer(h.request.req), &key, &value)
}

func (h *requestOrResponseTrailerMapImpl) Add(key, value string) {
	panic("unsupported yet")
}

func (h *requestOrResponseTrailerMapImpl) Del(key string) {
	panic("unsupported yet")
}

func (h *requestOrResponseTrailerMapImpl) Range(f func(key, value string) bool) {
	h.initHeaders()
	for key, values := range h.headers {
		for _, value := range values {
			if !f(key, value) {
				return
			}
		}
	}
}

// api.RequestTrailerMap
type requestTrailerMapImpl struct {
	requestOrResponseTrailerMapImpl
}

var _ api.RequestTrailerMap = (*requestTrailerMapImpl)(nil)

// api.ResponseTrailerMap
type responseTrailerMapImpl struct {
	requestOrResponseTrailerMapImpl
}

var _ api.ResponseTrailerMap = (*responseTrailerMapImpl)(nil)

// api.BufferInstance
type httpBuffer struct {
	request             *httpRequest
	envoyBufferInstance uint64
	length              uint64
	value               string
}

var _ api.BufferInstance = (*httpBuffer)(nil)

func (b *httpBuffer) Write(p []byte) (n int, err error) {
	cAPI.HttpSetBufferHelper(unsafe.Pointer(b.request.req), b.envoyBufferInstance, string(p), api.AppendBuffer)
	return len(p), nil
}

func (b *httpBuffer) WriteString(s string) (n int, err error) {
	cAPI.HttpSetBufferHelper(unsafe.Pointer(b.request.req), b.envoyBufferInstance, s, api.AppendBuffer)
	return len(s), nil
}

func (b *httpBuffer) WriteByte(p byte) error {
	cAPI.HttpSetBufferHelper(unsafe.Pointer(b.request.req), b.envoyBufferInstance, string(p), api.AppendBuffer)
	return nil
}

func (b *httpBuffer) WriteUint16(p uint16) error {
	s := strconv.FormatUint(uint64(p), 10)
	_, err := b.WriteString(s)
	return err
}

func (b *httpBuffer) WriteUint32(p uint32) error {
	s := strconv.FormatUint(uint64(p), 10)
	_, err := b.WriteString(s)
	return err
}

func (b *httpBuffer) WriteUint64(p uint64) error {
	s := strconv.FormatUint(uint64(p), 10)
	_, err := b.WriteString(s)
	return err
}

func (b *httpBuffer) Peek(n int) []byte {
	panic("implement me")
}

func (b *httpBuffer) Bytes() []byte {
	if b.length == 0 {
		return nil
	}
	cAPI.HttpGetBuffer(unsafe.Pointer(b.request.req), b.envoyBufferInstance, &b.value, b.length)
	return []byte(b.value)
}

func (b *httpBuffer) Drain(offset int) {
	panic("implement me")
}

func (b *httpBuffer) Len() int {
	return int(b.length)
}

func (b *httpBuffer) Reset() {
	panic("implement me")
}

func (b *httpBuffer) String() string {
	if b.length == 0 {
		return ""
	}
	cAPI.HttpGetBuffer(unsafe.Pointer(b.request.req), b.envoyBufferInstance, &b.value, b.length)
	return b.value
}

func (b *httpBuffer) Append(data []byte) error {
	cAPI.HttpSetBufferHelper(unsafe.Pointer(b.request.req), b.envoyBufferInstance, string(data), api.AppendBuffer)
	return nil
}

func (b *httpBuffer) Prepend(data []byte) error {
	cAPI.HttpSetBufferHelper(unsafe.Pointer(b.request.req), b.envoyBufferInstance, string(data), api.PrependBuffer)
	return nil
}

func (b *httpBuffer) AppendString(s string) error {
	cAPI.HttpSetBufferHelper(unsafe.Pointer(b.request.req), b.envoyBufferInstance, s, api.AppendBuffer)
	return nil
}

func (b *httpBuffer) PrependString(s string) error {
	cAPI.HttpSetBufferHelper(unsafe.Pointer(b.request.req), b.envoyBufferInstance, s, api.PrependBuffer)
	return nil
}

func (b *httpBuffer) Set(data []byte) error {
	cAPI.HttpSetBufferHelper(unsafe.Pointer(b.request.req), b.envoyBufferInstance, string(data), api.SetBuffer)
	return nil
}

func (b *httpBuffer) SetString(s string) error {
	cAPI.HttpSetBufferHelper(unsafe.Pointer(b.request.req), b.envoyBufferInstance, s, api.SetBuffer)
	return nil
}
