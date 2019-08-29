// Copyright (c) 2010, Google Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// linux_dumper.cc: Implement google_breakpad::LinuxDumper.
// See linux_dumper.h for details.

// This code deals with the mechanics of getting information about a crashed
// process. Since this code may run in a compromised address space, the same
// rules apply as detailed at the top of minidump_writer.h: no libc calls and
// use the alternative allocator.

#include "client/linux/minidump_writer/linux_dumper.h"

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>

#include "client/linux/minidump_writer/line_reader.h"
#include "common/linux/file_id.h"
#include "common/linux/linux_libc_support.h"
#include "common/linux/memory_mapped_file.h"
#include "common/linux/safe_readlink.h"
#include "third_party/lss/linux_syscall_support.h"

static const char kMappedFileUnsafePrefix[] = "/dev/";
static const char kDeletedSuffix[] = " (deleted)";

inline static bool IsMappedFileOpenUnsafe(
    const google_breakpad::MappingInfo& mapping) {
  // It is unsafe to attempt to open a mapped file that lives under /dev,
  // because the semantics of the open may be driver-specific so we'd risk
  // hanging the crash dumper. And a file in /dev/ almost certainly has no
  // ELF file identifier anyways.
  return my_strncmp(mapping.name,
                    kMappedFileUnsafePrefix,
                    sizeof(kMappedFileUnsafePrefix) - 1) == 0;
}

namespace google_breakpad {

}  // namespace google_breakpad
