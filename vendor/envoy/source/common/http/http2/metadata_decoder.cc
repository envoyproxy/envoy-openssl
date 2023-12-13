#include "source/common/http/http2/metadata_decoder.h"

#include "source/common/common/assert.h"
#include "source/common/runtime/runtime_features.h"

#include "absl/container/fixed_array.h"
#include "quiche/http2/decoder/decode_buffer.h"
#include "quiche/http2/hpack/decoder/hpack_decoder.h"
#include "quiche/http2/hpack/decoder/hpack_decoder_listener.h"

namespace Envoy {
namespace Http {
namespace Http2 {
namespace {

class QuicheDecoderListener : public http2::HpackDecoderListener {
public:
  explicit QuicheDecoderListener(MetadataMap& map) : map_(map) {}

  // HpackDecoderListener
  void OnHeaderListStart() override {}
  void OnHeader(const std::string& name, const std::string& value) override {
    map_.emplace(name, value);
  }
  void OnHeaderListEnd() override {}
  void OnHeaderErrorDetected(absl::string_view error_message) override {
    ENVOY_LOG_MISC(error, "Failed to decode payload: {}", error_message);
    map_.clear();
  }

private:
  MetadataMap& map_;
};

} // anonymous namespace

// Since QuicheDecoderListener and http2::HpackDecoder are implementation details, this struct is
// defined here rather than the header file.
struct MetadataDecoder::HpackDecoderContext {
  HpackDecoderContext(MetadataMap& map, size_t max_payload_size_bound)
      : listener(map), decoder(&listener, max_payload_size_bound) {}
  QuicheDecoderListener listener;
  http2::HpackDecoder decoder;
};

MetadataDecoder::MetadataDecoder(MetadataCallback cb) {
  nghttp2_hd_inflater* inflater;
  int rv = nghttp2_hd_inflate_new(&inflater);
  ASSERT(rv == 0);
  inflater_ = Inflater(inflater);

  ASSERT(cb != nullptr);
  callback_ = std::move(cb);

  resetDecoderContext();
}

MetadataDecoder::~MetadataDecoder() = default;

bool MetadataDecoder::receiveMetadata(const uint8_t* data, size_t len) {
  ASSERT(data != nullptr && len != 0);
  payload_.add(data, len);

  total_payload_size_ += len;
  return total_payload_size_ <= max_payload_size_bound_;
}

bool MetadataDecoder::onMetadataFrameComplete(bool end_metadata) {
  bool success;
  if (Runtime::runtimeFeatureEnabled(
          "envoy.reloadable_features.http2_decode_metadata_with_quiche")) {
    success = decodeMetadataPayload(end_metadata);
  } else {
    success = decodeMetadataPayloadUsingNghttp2(end_metadata);
  }
  if (!success) {
    return false;
  }

  if (end_metadata) {
    callback_(std::move(metadata_map_));
    resetDecoderContext();
  }
  return true;
}

bool MetadataDecoder::decodeMetadataPayloadUsingNghttp2(bool end_metadata) {
  Buffer::RawSliceVector slices = payload_.getRawSlices();
  const int num_slices = slices.size();

  // Data consumed by nghttp2 so far.
  ssize_t payload_size_consumed = 0;
  // Decodes header block using nghttp2.
  for (int i = 0; i < num_slices; i++) {
    nghttp2_nv nv;
    int inflate_flags = 0;
    auto slice = slices[i];
    // is_end indicates if the data in slice is the last data in the current
    // header block.
    bool is_end = i == (num_slices - 1) && end_metadata;

    // Feeds data to nghttp2 to decode.
    while (slice.len_ > 0) {
      ssize_t result =
          nghttp2_hd_inflate_hd2(inflater_.get(), &nv, &inflate_flags,
                                 reinterpret_cast<uint8_t*>(slice.mem_), slice.len_, is_end);
      if (result < 0 || (result == 0 && slice.len_ > 0)) {
        // If decoding fails, or there is data left in slice, but no data can be consumed by
        // nghttp2, return false.
        ENVOY_LOG(error, "Failed to decode payload.");
        return false;
      }

      slice.mem_ = reinterpret_cast<void*>(reinterpret_cast<uint8_t*>(slice.mem_) + result);
      slice.len_ -= result;
      payload_size_consumed += result;

      if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
        // One header key value pair has been successfully decoded.
        metadata_map_->emplace(std::string(reinterpret_cast<char*>(nv.name), nv.namelen),
                               std::string(reinterpret_cast<char*>(nv.value), nv.valuelen));
      }
    }

    if (slice.len_ == 0 && is_end) {
      // After one header block is decoded, reset inflater.
      ASSERT(end_metadata);
      nghttp2_hd_inflate_end_headers(inflater_.get());
    }
  }

  payload_.drain(payload_size_consumed);
  return true;
}

bool MetadataDecoder::decodeMetadataPayload(bool end_metadata) {
  Buffer::RawSliceVector slices = payload_.getRawSlices();

  // Data consumed by the decoder so far.
  ssize_t payload_size_consumed = 0;
  for (const Buffer::RawSlice& slice : slices) {
    http2::DecodeBuffer db(static_cast<char*>(slice.mem_), slice.len_);
    while (db.HasData()) {
      if (!decoder_context_->decoder.DecodeFragment(&db)) {
        ENVOY_LOG_MISC(error, "Failed to decode payload: {}",
                       decoder_context_->decoder.detailed_error());
        return false;
      }
    }
    payload_size_consumed += slice.len_;
  }
  if (end_metadata) {
    const bool result = decoder_context_->decoder.EndDecodingBlock();
    if (!result) {
      ENVOY_LOG_MISC(error, "Failed to decode payload: {}",
                     decoder_context_->decoder.detailed_error());
      return false;
    }
  }
  payload_.drain(payload_size_consumed);
  return true;
}

void MetadataDecoder::resetDecoderContext() {
  metadata_map_ = std::make_unique<MetadataMap>();
  decoder_context_ = std::make_unique<HpackDecoderContext>(*metadata_map_, max_payload_size_bound_);
}

} // namespace Http2
} // namespace Http
} // namespace Envoy
