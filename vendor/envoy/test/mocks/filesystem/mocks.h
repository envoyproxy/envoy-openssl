#pragma once

#include <cstdint>
#include <string>

#include "envoy/filesystem/filesystem.h"
#include "envoy/filesystem/watcher.h"

#include "source/common/common/thread.h"

#include "gmock/gmock.h"

namespace Envoy {
namespace Filesystem {

class MockFile : public File {
public:
  MockFile();
  ~MockFile() override;

  // Filesystem::File
  Api::IoCallBoolResult open(FlagSet flag) override;
  Api::IoCallSizeResult write(absl::string_view buffer) override;
  Api::IoCallBoolResult close() override;
  Api::IoCallSizeResult pread(void* buf, uint64_t count, uint64_t offset) override;
  Api::IoCallSizeResult pwrite(const void* buf, uint64_t count, uint64_t offset) override;
  bool isOpen() const override { return is_open_; };
  MOCK_METHOD(std::string, path, (), (const));
  MOCK_METHOD(DestinationType, destinationType, (), (const));
  MOCK_METHOD(Api::IoCallResult<FileInfo>, info, ());

  // The first parameter here must be `const FlagSet&` otherwise it doesn't compile with libstdc++
  MOCK_METHOD(Api::IoCallBoolResult, open_, (const FlagSet& flag));
  MOCK_METHOD(Api::IoCallSizeResult, write_, (absl::string_view buffer));
  MOCK_METHOD(Api::IoCallBoolResult, close_, ());
  MOCK_METHOD(Api::IoCallSizeResult, pread_, (void* buf, uint64_t count, uint64_t offset));
  MOCK_METHOD(Api::IoCallSizeResult, pwrite_, (const void* buf, uint64_t count, uint64_t offset));

  size_t num_opens_;
  size_t num_writes_;
  size_t num_preads_;
  size_t num_pwrites_;
  Thread::MutexBasicLockable open_mutex_;
  Thread::MutexBasicLockable write_mutex_;
  Thread::MutexBasicLockable pread_mutex_;
  Thread::MutexBasicLockable pwrite_mutex_;
  Thread::CondVar open_event_;
  Thread::CondVar write_event_;
  Thread::CondVar pread_event_;
  Thread::CondVar pwrite_event_;

private:
  bool is_open_;
};

class MockInstance : public Instance {
public:
  MockInstance();
  ~MockInstance() override;

  // Filesystem::Instance
  MOCK_METHOD(FilePtr, createFile, (const FilePathAndType&));
  MOCK_METHOD(bool, fileExists, (const std::string&));
  MOCK_METHOD(bool, directoryExists, (const std::string&));
  MOCK_METHOD(ssize_t, fileSize, (const std::string&));
  MOCK_METHOD(std::string, fileReadToEnd, (const std::string&));
  MOCK_METHOD(PathSplitResult, splitPathFromFilename, (absl::string_view));
  MOCK_METHOD(bool, illegalPath, (const std::string&));
  MOCK_METHOD(Api::IoCallResult<FileInfo>, stat, (absl::string_view));
};

class MockWatcher : public Watcher {
public:
  MockWatcher();
  ~MockWatcher() override;

  MOCK_METHOD(void, addWatch, (absl::string_view, uint32_t, OnChangedCb));
};

} // namespace Filesystem
} // namespace Envoy
