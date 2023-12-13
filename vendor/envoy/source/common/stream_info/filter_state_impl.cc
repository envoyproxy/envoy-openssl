#include "source/common/stream_info/filter_state_impl.h"

#include "envoy/common/exception.h"

namespace Envoy {
namespace StreamInfo {

void FilterStateImpl::setData(absl::string_view data_name, std::shared_ptr<Object> data,
                              FilterState::StateType state_type, FilterState::LifeSpan life_span,
                              StreamSharingMayImpactPooling stream_sharing) {
  if (life_span > life_span_) {
    if (hasDataWithNameInternally(data_name)) {
      IS_ENVOY_BUG("FilterStateAccessViolation: FilterState::setData<T> called twice with "
                   "conflicting life_span on the same data_name.");
      return;
    }
    maybeCreateParent(ParentAccessMode::ReadWrite);
    parent_->setData(data_name, data, state_type, life_span, stream_sharing);
    return;
  }
  if (parent_ && parent_->hasDataWithName(data_name)) {
    IS_ENVOY_BUG("FilterStateAccessViolation: FilterState::setData<T> called twice with "
                 "conflicting life_span on the same data_name.");
    return;
  }
  const auto& it = data_storage_.find(data_name);
  if (it != data_storage_.end()) {
    // We have another object with same data_name. Check for mutability
    // violations namely: readonly data cannot be overwritten, mutable data
    // cannot be overwritten by readonly data.
    const FilterStateImpl::FilterObject* current = it->second.get();
    if (current->state_type_ == FilterState::StateType::ReadOnly) {
      IS_ENVOY_BUG("FilterStateAccessViolation: FilterState::setData<T> called twice on same "
                   "ReadOnly state.");
      return;
    }

    if (current->state_type_ != state_type) {
      IS_ENVOY_BUG("FilterStateAccessViolation: FilterState::setData<T> called twice with "
                   "different state types.");
      return;
    }
  }

  std::unique_ptr<FilterStateImpl::FilterObject> filter_object(new FilterStateImpl::FilterObject());
  filter_object->data_ = data;
  filter_object->state_type_ = state_type;
  filter_object->stream_sharing_ = stream_sharing;
  data_storage_[data_name] = std::move(filter_object);
}

bool FilterStateImpl::hasDataWithName(absl::string_view data_name) const {
  return hasDataWithNameInternally(data_name) || (parent_ && parent_->hasDataWithName(data_name));
}

const FilterState::Object*
FilterStateImpl::getDataReadOnlyGeneric(absl::string_view data_name) const {
  const auto it = data_storage_.find(data_name);

  if (it == data_storage_.end()) {
    if (parent_) {
      return parent_->getDataReadOnlyGeneric(data_name);
    }
    return nullptr;
  }

  const FilterStateImpl::FilterObject* current = it->second.get();
  return current->data_.get();
}

FilterState::Object* FilterStateImpl::getDataMutableGeneric(absl::string_view data_name) {
  return getDataSharedMutableGeneric(data_name).get();
}

std::shared_ptr<FilterState::Object>
FilterStateImpl::getDataSharedMutableGeneric(absl::string_view data_name) {
  const auto& it = data_storage_.find(data_name);

  if (it == data_storage_.end()) {
    if (parent_) {
      return parent_->getDataSharedMutableGeneric(data_name);
    }
    return nullptr;
  }

  FilterStateImpl::FilterObject* current = it->second.get();
  if (current->state_type_ == FilterState::StateType::ReadOnly) {
    IS_ENVOY_BUG("FilterStateAccessViolation: FilterState accessed immutable data as mutable.");
    // To reduce the chances of a crash, allow the mutation in this case instead of returning a
    // nullptr.
  }

  return current->data_;
}

bool FilterStateImpl::hasDataAtOrAboveLifeSpan(FilterState::LifeSpan life_span) const {
  if (life_span > life_span_) {
    return parent_ && parent_->hasDataAtOrAboveLifeSpan(life_span);
  }
  return !data_storage_.empty() || (parent_ && parent_->hasDataAtOrAboveLifeSpan(life_span));
}

FilterState::ObjectsPtr FilterStateImpl::objectsSharedWithUpstreamConnection() const {
  auto objects = parent_ ? parent_->objectsSharedWithUpstreamConnection()
                         : std::make_unique<FilterState::Objects>();
  for (const auto& [name, object] : data_storage_) {
    switch (object->stream_sharing_) {
    case StreamSharingMayImpactPooling::SharedWithUpstreamConnection:
      objects->push_back({object->data_, object->state_type_, object->stream_sharing_, name});
      break;
    case StreamSharingMayImpactPooling::SharedWithUpstreamConnectionOnce:
      objects->push_back(
          {object->data_, object->state_type_, StreamSharingMayImpactPooling::None, name});
      break;
    default:
      break;
    }
  }
  return objects;
}

bool FilterStateImpl::hasDataWithNameInternally(absl::string_view data_name) const {
  return data_storage_.count(data_name) > 0;
}

void FilterStateImpl::maybeCreateParent(ParentAccessMode parent_access_mode) {
  if (parent_ != nullptr) {
    return;
  }
  if (life_span_ >= FilterState::LifeSpan::TopSpan) {
    return;
  }
  if (absl::holds_alternative<FilterStateSharedPtr>(ancestor_)) {
    FilterStateSharedPtr ancestor = absl::get<FilterStateSharedPtr>(ancestor_);
    if (ancestor == nullptr || ancestor->lifeSpan() != life_span_ + 1) {
      parent_ = std::make_shared<FilterStateImpl>(ancestor, FilterState::LifeSpan(life_span_ + 1));
    } else {
      parent_ = ancestor;
    }
    return;
  }

  auto lazy_create_ancestor = absl::get<LazyCreateAncestor>(ancestor_);
  // If we're only going to read data from our parent, we don't need to create lazy ancestor,
  // because they're empty anyways.
  if (parent_access_mode == ParentAccessMode::ReadOnly && lazy_create_ancestor.first == nullptr) {
    return;
  }

  // Lazy ancestor is not our immediate parent.
  if (lazy_create_ancestor.second != life_span_ + 1) {
    parent_ = std::make_shared<FilterStateImpl>(lazy_create_ancestor,
                                                FilterState::LifeSpan(life_span_ + 1));
    return;
  }
  // Lazy parent is our immediate parent.
  if (lazy_create_ancestor.first == nullptr) {
    lazy_create_ancestor.first =
        std::make_shared<FilterStateImpl>(FilterState::LifeSpan(life_span_ + 1));
  }
  parent_ = lazy_create_ancestor.first;
}

} // namespace StreamInfo
} // namespace Envoy
