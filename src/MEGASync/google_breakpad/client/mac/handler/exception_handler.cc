// Copyright (c) 2006, Google Inc.
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

#include <mach/exc.h>
#include <mach/mig.h>
#include <pthread.h>
#include <signal.h>
#include <TargetConditionals.h>

#include <map>

#include "client/mac/handler/exception_handler.h"
#include "client/mac/handler/minidump_generator.h"
#include "common/mac/macho_utilities.h"
#include "common/mac/scoped_task_suspend-inl.h"
#include "google_breakpad/common/minidump_exception_mac.h"

#ifndef __EXCEPTIONS
// This file uses C++ try/catch (but shouldn't). Duplicate the macros from
// <c++/4.2.1/exception_defines.h> allowing this file to work properly with
// exceptions disabled even when other C++ libraries are used. #undef the try
// and catch macros first in case libstdc++ is in use and has already provided
// its own definitions.
#undef try
#define try       if (true)
#undef catch
#define catch(X)  if (false)
#endif  // __EXCEPTIONS

#ifndef USE_PROTECTED_ALLOCATIONS
#if TARGET_OS_IPHONE
#define USE_PROTECTED_ALLOCATIONS 1
#else
#define USE_PROTECTED_ALLOCATIONS 0
#endif
#endif

// If USE_PROTECTED_ALLOCATIONS is activated then the
// gBreakpadAllocator needs to be setup in other code
// ahead of time.  Please see ProtectedMemoryAllocator.h
// for more details.
#if USE_PROTECTED_ALLOCATIONS
  #include "protected_memory_allocator.h"
  extern ProtectedMemoryAllocator *gBreakpadAllocator;
#endif

namespace google_breakpad {

static union {
#if USE_PROTECTED_ALLOCATIONS
  char protected_buffer[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
#endif
  google_breakpad::ExceptionHandler *handler;
} gProtectedData;

using std::map;

// These structures and techniques are illustrated in
// Mac OS X Internals, Amit Singh, ch 9.7
struct ExceptionMessage {
  mach_msg_header_t           header;
  mach_msg_body_t             body;
  mach_msg_port_descriptor_t  thread;
  mach_msg_port_descriptor_t  task;
  NDR_record_t                ndr;
  exception_type_t            exception;
  mach_msg_type_number_t      code_count;
  integer_t                   code[EXCEPTION_CODE_MAX];
  char                        padding[512];
};

struct ExceptionParameters {
  ExceptionParameters() : count(0) {}
  mach_msg_type_number_t count;
  exception_mask_t masks[EXC_TYPES_COUNT];
  mach_port_t ports[EXC_TYPES_COUNT];
  exception_behavior_t behaviors[EXC_TYPES_COUNT];
  thread_state_flavor_t flavors[EXC_TYPES_COUNT];
};

struct ExceptionReplyMessage {
  mach_msg_header_t  header;
  NDR_record_t       ndr;
  kern_return_t      return_code;
};

// Only catch these three exceptions.  The other ones are nebulously defined
// and may result in treating a non-fatal exception as fatal.
exception_mask_t s_exception_mask = EXC_MASK_BAD_ACCESS |
EXC_MASK_BAD_INSTRUCTION | EXC_MASK_ARITHMETIC | EXC_MASK_BREAKPOINT;

#if !TARGET_OS_IPHONE
extern "C" {
  // Forward declarations for functions that need "C" style compilation
  boolean_t exc_server(mach_msg_header_t* request,
                       mach_msg_header_t* reply);

  // This symbol must be visible to dlsym() - see
  // http://code.google.com/p/google-breakpad/issues/detail?id=345 for details.
  kern_return_t catch_exception_raise(mach_port_t target_port,
                                      mach_port_t failed_thread,
                                      mach_port_t task,
                                      exception_type_t exception,
                                      exception_data_t code,
                                      mach_msg_type_number_t code_count)
      __attribute__((visibility("default")));
}
#endif

kern_return_t ForwardException(mach_port_t task,
                               mach_port_t failed_thread,
                               exception_type_t exception,
                               exception_data_t code,
                               mach_msg_type_number_t code_count);

#if TARGET_OS_IPHONE
// Implementation is based on the implementation generated by mig.
boolean_t breakpad_exc_server(mach_msg_header_t* InHeadP,
                              mach_msg_header_t* OutHeadP) {
  OutHeadP->msgh_bits =
      MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(InHeadP->msgh_bits), 0);
  OutHeadP->msgh_remote_port = InHeadP->msgh_remote_port;
  /* Minimal size: routine() will update it if different */
  OutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
  OutHeadP->msgh_local_port = MACH_PORT_NULL;
  OutHeadP->msgh_id = InHeadP->msgh_id + 100;

  if (InHeadP->msgh_id != 2401) {
    ((mig_reply_error_t*)OutHeadP)->NDR = NDR_record;
    ((mig_reply_error_t*)OutHeadP)->RetCode = MIG_BAD_ID;
    return FALSE;
  }

#ifdef  __MigPackStructs
#pragma pack(4)
#endif
  typedef struct {
    mach_msg_header_t Head;
    /* start of the kernel processed data */
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    /* end of the kernel processed data */
    NDR_record_t NDR;
    exception_type_t exception;
    mach_msg_type_number_t codeCnt;
    integer_t code[2];
    mach_msg_trailer_t trailer;
  } Request;

  typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
  } Reply;
#ifdef  __MigPackStructs
#pragma pack()
#endif

  Request* In0P = (Request*)InHeadP;
  Reply* OutP = (Reply*)OutHeadP;

  if (In0P->task.name != mach_task_self()) {
    return FALSE;
  }
  OutP->RetCode = ForwardException(In0P->task.name,
                                   In0P->thread.name,
                                   In0P->exception,
                                   In0P->code,
                                   In0P->codeCnt);
  OutP->NDR = NDR_record;
  return TRUE;
}
#else
boolean_t breakpad_exc_server(mach_msg_header_t* request,
                              mach_msg_header_t* reply) {
  return exc_server(request, reply);
}

// Callback from exc_server()
kern_return_t catch_exception_raise(mach_port_t port, mach_port_t failed_thread,
                                    mach_port_t task,
                                    exception_type_t exception,
                                    exception_data_t code,
                                    mach_msg_type_number_t code_count) {
  if (task != mach_task_self()) {
    return KERN_FAILURE;
  }
  return ForwardException(task, failed_thread, exception, code, code_count);
}
#endif

ExceptionHandler::ExceptionHandler(const string &dump_path,
                                   FilterCallback filter,
                                   MinidumpCallback callback,
                                   void* callback_context,
                                   bool install_handler,
                                   const char* port_name)
    : dump_path_(),
      filter_(filter),
      callback_(callback),
      callback_context_(callback_context),
      directCallback_(NULL),
      handler_thread_(NULL),
      handler_port_(MACH_PORT_NULL),
      previous_(NULL),
      installed_exception_handler_(false),
      is_in_teardown_(false),
      last_minidump_write_result_(false),
      use_minidump_write_mutex_(false) {
}

// special constructor if we want to bypass minidump writing and
// simply get a callback with the exception information
ExceptionHandler::ExceptionHandler(DirectCallback callback,
                                   void* callback_context,
                                   bool install_handler)
    : dump_path_(),
      filter_(NULL),
      callback_(NULL),
      callback_context_(callback_context),
      directCallback_(callback),
      handler_thread_(NULL),
      handler_port_(MACH_PORT_NULL),
      previous_(NULL),
      installed_exception_handler_(false),
      is_in_teardown_(false),
      last_minidump_write_result_(false),
      use_minidump_write_mutex_(false) {
  MinidumpGenerator::GatherSystemInformation();
  Setup(install_handler);
}

ExceptionHandler::~ExceptionHandler() {
  Teardown();
}

bool ExceptionHandler::WriteMinidump(bool write_exception_stream) {
}

// static
bool ExceptionHandler::WriteMinidump(const string &dump_path,
                                     bool write_exception_stream,
                                     MinidumpCallback callback,
                                     void* callback_context) {
}

// static
bool ExceptionHandler::WriteMinidumpForChild(mach_port_t child,
                                             mach_port_t child_blamed_thread,
                                             const string &dump_path,
                                             MinidumpCallback callback,
                                             void* callback_context) {
}

bool ExceptionHandler::WriteMinidumpWithException(
    int exception_type,
    int exception_code,
    int exception_subcode,
    breakpad_ucontext_t* task_context,
    mach_port_t thread_name,
    bool exit_after_write,
    bool report_current_thread) {
}

kern_return_t ForwardException(mach_port_t task, mach_port_t failed_thread,
                               exception_type_t exception,
                               exception_data_t code,
                               mach_msg_type_number_t code_count) {
}

// static
void* ExceptionHandler::WaitForMessage(void* exception_handler_class) {
}

// static
void ExceptionHandler::SignalHandler(int sig, siginfo_t* info, void* uc) {
}

bool ExceptionHandler::InstallHandler() {
  return false;
}

bool ExceptionHandler::UninstallHandler(bool in_exception) {
}

bool ExceptionHandler::Setup(bool install_handler) {
}

bool ExceptionHandler::Teardown() {
}

bool ExceptionHandler::SendMessageToHandlerThread(
    HandlerThreadMessage message_id) {
}

void ExceptionHandler::UpdateNextID() {
  next_minidump_path_ =
    (MinidumpGenerator::UniqueNameInDirectory(dump_path_, &next_minidump_id_));

  next_minidump_path_c_ = next_minidump_path_.c_str();
  next_minidump_id_c_ = next_minidump_id_.c_str();
}

bool ExceptionHandler::SuspendThreads() {
  thread_act_port_array_t   threads_for_task;
  mach_msg_type_number_t    thread_count;

  if (task_threads(mach_task_self(), &threads_for_task, &thread_count))
    return false;

  // suspend all of the threads except for this one
  for (unsigned int i = 0; i < thread_count; ++i) {
    if (threads_for_task[i] != mach_thread_self()) {
      if (thread_suspend(threads_for_task[i]))
        return false;
    }
  }

  return true;
}

bool ExceptionHandler::ResumeThreads() {
  thread_act_port_array_t   threads_for_task;
  mach_msg_type_number_t    thread_count;

  if (task_threads(mach_task_self(), &threads_for_task, &thread_count))
    return false;

  // resume all of the threads except for this one
  for (unsigned int i = 0; i < thread_count; ++i) {
    if (threads_for_task[i] != mach_thread_self()) {
      if (thread_resume(threads_for_task[i]))
        return false;
    }
  }

  return true;
}

}  // namespace google_breakpad
