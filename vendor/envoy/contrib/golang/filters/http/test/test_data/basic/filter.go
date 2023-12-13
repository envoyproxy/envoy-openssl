package main

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/api"
)

type filter struct {
	callbacks       api.FilterCallbackHandler
	req_body_length uint64
	query_params    url.Values
	protocol        string
	scheme          string
	method          string
	path            string
	host            string

	// for bad api call testing
	header api.RequestHeaderMap

	// test mode, from query parameters
	async       bool
	sleep       bool   // all sleep
	data_sleep  bool   // only sleep in data phase
	localreplay string // send local reply
	databuffer  string // return api.Stop
	panic       string // hit panic in which phase
	badapi      bool   // bad api call
}

func parseQuery(path string) url.Values {
	if idx := strings.Index(path, "?"); idx >= 0 {
		query := path[idx+1:]
		values, _ := url.ParseQuery(query)
		return values
	}
	return make(url.Values)
}

func badcode() {
	// panic index out of range
	s := []int{1}
	s[1] = s[5]
}

func (f *filter) initRequest(header api.RequestHeaderMap) {
	f.header = header

	f.req_body_length = 0

	f.protocol = header.Protocol()
	f.scheme = header.Scheme()
	f.method = header.Method()
	f.path = header.Path()
	f.host = header.Host()

	f.query_params = parseQuery(f.path)
	if f.query_params.Get("async") != "" {
		f.async = true
	}
	if f.query_params.Get("sleep") != "" {
		f.sleep = true
	}
	if f.query_params.Get("data_sleep") != "" {
		f.data_sleep = true
	}
	if f.query_params.Get("decode_localrepaly") != "" {
		f.data_sleep = true
	}
	f.databuffer = f.query_params.Get("databuffer")
	f.localreplay = f.query_params.Get("localreply")
	f.panic = f.query_params.Get("panic")
	f.badapi = f.query_params.Get("badapi") != ""
}

func (f *filter) fail(msg string, a ...any) api.StatusType {
	body := fmt.Sprintf(msg, a...)
	f.callbacks.SendLocalReply(500, body, nil, -1, "")
	return api.LocalReply
}

func (f *filter) sendLocalReply(phase string) api.StatusType {
	headers := make(map[string]string)
	body := fmt.Sprintf("forbidden from go in %s\r\n", phase)
	f.callbacks.SendLocalReply(403, body, headers, -1, "test-from-go")
	return api.LocalReply
}

// test: get, set, remove, values, add
func (f *filter) decodeHeaders(header api.RequestHeaderMap, endStream bool) api.StatusType {
	// test logging
	f.callbacks.Log(api.Trace, "log test")
	f.callbacks.Log(api.Debug, "log test")
	f.callbacks.Log(api.Info, "log test")
	f.callbacks.Log(api.Warn, "log test")
	f.callbacks.Log(api.Error, "log test")
	f.callbacks.Log(api.Critical, "log test")

	if f.sleep {
		time.Sleep(time.Millisecond * 100) // sleep 100 ms
	}

	_, found := header.Get("x-set-metadata")
	if found {
		md := f.callbacks.StreamInfo().DynamicMetadata()
		md.Set("filter.go", "foo", "bar")
	}

	if strings.Contains(f.localreplay, "decode-header") {
		return f.sendLocalReply("decode-header")
	}

	header.Range(func(key, value string) bool {
		if key == ":path" && value != f.path {
			f.fail("path not match in Range")
			return false
		}
		return true
	})

	origin, found := header.Get("x-test-header-0")
	hdrs := header.Values("x-test-header-0")
	if found {
		if origin != hdrs[0] {
			return f.fail("Values return incorrect data %v", hdrs)
		}
	} else if hdrs != nil {
		return f.fail("Values return unexpected data %v", hdrs)
	}

	header.Add("existed-header", "bar")
	header.Add("newly-added-header", "foo")
	header.Add("newly-added-header", "bar")

	header.Set("test-x-set-header-0", origin)
	header.Del("x-test-header-1")
	header.Set("req-route-name", f.callbacks.StreamInfo().GetRouteName())
	if !endStream && strings.Contains(f.databuffer, "decode-header") {
		return api.StopAndBuffer
	}

	if f.panic == "decode-header" {
		badcode()
	}
	return api.Continue
}

// test: get, set, append, prepend
func (f *filter) decodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	if f.sleep || f.data_sleep {
		time.Sleep(time.Millisecond * 100) // sleep 100 ms
	}
	if strings.Contains(f.localreplay, "decode-data") {
		return f.sendLocalReply("decode-data")
	}
	f.req_body_length += uint64(buffer.Len())
	if buffer.Len() != 0 {
		data := buffer.String()
		buffer.SetString(strings.ToUpper(data))
		buffer.AppendString("_append")
		buffer.PrependString("prepend_")
	}
	if !endStream && strings.Contains(f.databuffer, "decode-data") {
		return api.StopAndBuffer
	}

	if f.panic == "decode-data" {
		badcode()
	}
	if f.badapi {
		// set header after header continued will panic with the ErrInvalidPhase error message.
		f.header.Set("foo", "bar")
	}
	return api.Continue
}

func (f *filter) decodeTrailers(trailers api.RequestTrailerMap) api.StatusType {
	if f.sleep {
		time.Sleep(time.Millisecond * 100) // sleep 100 ms
	}
	if strings.Contains(f.localreplay, "decode-trailer") {
		return f.sendLocalReply("decode-trailer")
	}

	if f.panic == "decode-trailer" {
		badcode()
	}
	return api.Continue
}

func (f *filter) encodeHeaders(header api.ResponseHeaderMap, endStream bool) api.StatusType {
	if f.sleep {
		time.Sleep(time.Millisecond * 100) // sleep 100 ms
	}
	if strings.Contains(f.localreplay, "encode-header") {
		return f.sendLocalReply("encode-header")
	}

	if protocol, ok := f.callbacks.StreamInfo().Protocol(); ok {
		header.Set("rsp-protocol", protocol)
	}
	if code, ok := f.callbacks.StreamInfo().ResponseCode(); ok {
		header.Set("rsp-response-code", strconv.Itoa(int(code)))
	}
	if details, ok := f.callbacks.StreamInfo().ResponseCodeDetails(); ok {
		header.Set("rsp-response-code-details", details)
	}

	origin, found := header.Get("x-test-header-0")
	hdrs := header.Values("x-test-header-0")
	if found {
		if origin != hdrs[0] {
			return f.fail("Values return incorrect data %v", hdrs)
		}
	} else if hdrs != nil {
		return f.fail("Values return unexpected data %v", hdrs)
	}

	if status, ok := header.Status(); ok {
		header.Add("rsp-status", strconv.Itoa(status))
	}

	header.Add("existed-header", "bar")
	header.Add("newly-added-header", "foo")
	header.Add("newly-added-header", "bar")

	header.Set("test-x-set-header-0", origin)
	header.Del("x-test-header-1")
	header.Set("test-req-body-length", strconv.Itoa(int(f.req_body_length)))
	header.Set("test-query-param-foo", f.query_params.Get("foo"))
	header.Set("test-scheme", f.scheme)
	header.Set("test-method", f.method)
	header.Set("test-path", f.path)
	header.Set("test-host", f.host)
	header.Set("rsp-route-name", f.callbacks.StreamInfo().GetRouteName())
	header.Set("rsp-filter-chain-name", f.callbacks.StreamInfo().FilterChainName())
	header.Set("rsp-attempt-count", strconv.Itoa(int(f.callbacks.StreamInfo().AttemptCount())))

	if f.panic == "encode-header" {
		badcode()
	}
	return api.Continue
}

func (f *filter) encodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	if f.sleep || f.data_sleep {
		time.Sleep(time.Millisecond * 100) // sleep 100 ms
	}
	if strings.Contains(f.localreplay, "encode-data") {
		return f.sendLocalReply("encode-data")
	}
	data := buffer.String()
	buffer.SetString(strings.ToUpper(data))

	if f.panic == "encode-data" {
		badcode()
	}
	return api.Continue
}

func (f *filter) encodeTrailers(trailers api.ResponseTrailerMap) api.StatusType {
	if f.sleep {
		time.Sleep(time.Millisecond * 100) // sleep 100 ms
	}
	if strings.Contains(f.localreplay, "encode-trailer") {
		return f.sendLocalReply("encode-trailer")
	}

	if f.panic == "encode-trailer" {
		badcode()
	}
	return api.Continue
}

func (f *filter) DecodeHeaders(header api.RequestHeaderMap, endStream bool) api.StatusType {
	f.initRequest(header)
	if f.async {
		go func() {
			defer f.callbacks.RecoverPanic()

			status := f.decodeHeaders(header, endStream)
			if status != api.LocalReply {
				f.callbacks.Continue(status)
			}
		}()
		return api.Running
	} else {
		status := f.decodeHeaders(header, endStream)
		return status
	}
}

func (f *filter) DecodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	if f.async {
		go func() {
			defer f.callbacks.RecoverPanic()

			status := f.decodeData(buffer, endStream)
			if status != api.LocalReply {
				f.callbacks.Continue(status)
			}
		}()
		return api.Running
	} else {
		status := f.decodeData(buffer, endStream)
		return status
	}
}

func (f *filter) DecodeTrailers(trailers api.RequestTrailerMap) api.StatusType {
	if f.async {
		go func() {
			defer f.callbacks.RecoverPanic()

			status := f.decodeTrailers(trailers)
			if status != api.LocalReply {
				f.callbacks.Continue(status)
			}
		}()
		return api.Running
	} else {
		status := f.decodeTrailers(trailers)
		return status
	}
}

func (f *filter) EncodeHeaders(header api.ResponseHeaderMap, endStream bool) api.StatusType {
	if f.async {
		go func() {
			defer f.callbacks.RecoverPanic()

			status := f.encodeHeaders(header, endStream)
			if status != api.LocalReply {
				f.callbacks.Continue(status)
			}
		}()
		return api.Running
	} else {
		status := f.encodeHeaders(header, endStream)
		return status
	}
}

func (f *filter) EncodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	if f.async {
		go func() {
			defer f.callbacks.RecoverPanic()

			status := f.encodeData(buffer, endStream)
			if status != api.LocalReply {
				f.callbacks.Continue(status)
			}
		}()
		return api.Running
	} else {
		status := f.encodeData(buffer, endStream)
		return status
	}
}

func (f *filter) EncodeTrailers(trailers api.ResponseTrailerMap) api.StatusType {
	if f.async {
		go func() {
			defer f.callbacks.RecoverPanic()

			status := f.encodeTrailers(trailers)
			if status != api.LocalReply {
				f.callbacks.Continue(status)
			}
		}()
		return api.Running
	} else {
		status := f.encodeTrailers(trailers)
		return status
	}
}

func (f *filter) OnDestroy(reason api.DestroyReason) {
}
