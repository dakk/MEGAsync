// Copyright (c) 2010 Google Inc.
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

// The ExceptionHandler object installs signal handlers for a number of
// signals. We rely on the signal handler running on the thread which crashed
// in order to identify it. This is true of the synchronous signals (SEGV etc),
// but not true of ABRT. Thus, if you send ABRT to yourself in a program which
// uses ExceptionHandler, you need to use tgkill to direct it to the current
// thread.
//
// The signal flow looks like this:
//
//   SignalHandler (uses a global stack of ExceptionHandler objects to find
//        |         one to handle the signal. If the first rejects it, try
//        |         the second etc...)
//        V
//   HandleSignal ----------------------------| (clones a new process which
//        |                                   |  shares an address space with
//   (wait for cloned                         |  the crashed process. This
//     process)                               |  allows us to ptrace the crashed
//        |                                   |  process)
//        V                                   V
//   (set signal handler to             ThreadEntry (static function to bounce
//    SIG_DFL and rethrow,                    |      back into the object)
//    killing the crashed                     |
//    process)                                V
//                                          DoDump  (writes minidump)
//                                            |
//                                            V
//                                         exit
//

// This code is a little fragmented. Different functions of the ExceptionHandler
// class run in a number of different contexts. Some of them run in a normal
// context and are easy to code, others run in a compromised context and the
// restrictions at the top of minidump_writer.cc apply: no libc and use the
// alternative malloc. Each function should have comment above it detailing the
// context which it runs in.

#include "client/linux/handler/exception_handler.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sys/signal.h>
#include <sys/ucontext.h>
#include <sys/user.h>
#include <ucontext.h>

#include <algorithm>
#include <utility>
#include <vector>

#include "common/basictypes.h"
#include "common/linux/linux_libc_support.h"
#include "common/memory.h"
#include "client/linux/log/log.h"
#include "client/linux/minidump_writer/linux_dumper.h"
#include "client/linux/minidump_writer/minidump_writer.h"
#include "common/linux/eintr_wrapper.h"
#include "third_party/lss/linux_syscall_support.h"

#if defined(__ANDROID__)
#include "linux/sched.h"
#endif

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif

// A wrapper for the tgkill syscall: send a signal to a specific thread.
static int tgkill(pid_t tgid, pid_t tid, int sig) {
  // return syscall(__NR_tgkill, tgid, tid, sig);
  return 0;
}

namespace google_breakpad {

namespace {
// The list of signals which we consider to be crashes. The default action for
// all these signals must be Core (see man 7 signal) because we rethrow the
// signal after handling it and expect that it'll be fatal.
const int kExceptionSignals[] = {
  SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGBUS
};
const int kNumHandledSignals =
    sizeof(kExceptionSignals) / sizeof(kExceptionSignals[0]);
struct sigaction old_handlers[kNumHandledSignals];
bool handlers_installed = false;

// InstallAlternateStackLocked will store the newly installed stack in new_stack
// and (if it exists) the previously installed stack in old_stack.
stack_t old_stack;
stack_t new_stack;
bool stack_installed = false;

// Create an alternative stack to run the signal handlers on. This is done since
// the signal might have been caused by a stack overflow.
// Runs before crashing: normal context.
void InstallAlternateStackLocked() {
  if (stack_installed)
    return;

  memset(&old_stack, 0, sizeof(old_stack));
  memset(&new_stack, 0, sizeof(new_stack));

  // SIGSTKSZ may be too small to prevent the signal handlers from overrunning
  // the alternative stack. Ensure that the size of the alternative stack is
  // large enough.
  static const unsigned kSigStackSize = std::max(8192, SIGSTKSZ);

  // Only set an alternative stack if there isn't already one, or if the current
  // one is too small.
  if (sigaltstack(NULL, &old_stack) == -1 || !old_stack.ss_sp ||
      old_stack.ss_size < kSigStackSize) {
    new_stack.ss_sp = malloc(kSigStackSize);
    new_stack.ss_size = kSigStackSize;

    if (sigaltstack(&new_stack, NULL) == -1) {
      free(new_stack.ss_sp);
      return;
    }
    stack_installed = true;
  }
}

// Runs before crashing: normal context.
void RestoreAlternateStackLocked() {
  if (!stack_installed)
    return;

  stack_t current_stack;
  if (sigaltstack(NULL, &current_stack) == -1)
    return;

  // Only restore the old_stack if the current alternative stack is the one
  // installed by the call to InstallAlternateStackLocked.
  if (current_stack.ss_sp == new_stack.ss_sp) {
    if (old_stack.ss_sp) {
      if (sigaltstack(&old_stack, NULL) == -1)
        return;
    } else {
      stack_t disable_stack;
      disable_stack.ss_flags = SS_DISABLE;
      if (sigaltstack(&disable_stack, NULL) == -1)
        return;
    }
  }

  free(new_stack.ss_sp);
  stack_installed = false;
}

}  // namespace

// We can stack multiple exception handlers. In that case, this is the global
// which holds the stack.
std::vector<ExceptionHandler*>* ExceptionHandler::handler_stack_ = NULL;
pthread_mutex_t ExceptionHandler::handler_stack_mutex_ =
    PTHREAD_MUTEX_INITIALIZER;

// Runs before crashing: normal context.
ExceptionHandler::ExceptionHandler(const MinidumpDescriptor& descriptor,
                                   FilterCallback filter,
                                   MinidumpCallback callback,
                                   void* callback_context,
                                   bool install_handler,
                                   const int server_fd)
    : filter_(filter),
      callback_(callback),
      callback_context_(callback_context),
      minidump_descriptor_(descriptor),
      crash_handler_(NULL) {
  if (server_fd >= 0)
    crash_generation_client_.reset(CrashGenerationClient::TryCreate(server_fd));

  if (!IsOutOfProcess() && !minidump_descriptor_.IsFD())
    minidump_descriptor_.UpdatePath();

  pthread_mutex_lock(&handler_stack_mutex_);
  if (!handler_stack_)
    handler_stack_ = new std::vector<ExceptionHandler*>;
  if (install_handler) {
    InstallAlternateStackLocked();
    InstallHandlersLocked();
  }
  handler_stack_->push_back(this);
  pthread_mutex_unlock(&handler_stack_mutex_);
}

// Runs before crashing: normal context.
ExceptionHandler::~ExceptionHandler() {
  pthread_mutex_lock(&handler_stack_mutex_);
  std::vector<ExceptionHandler*>::iterator handler =
      std::find(handler_stack_->begin(), handler_stack_->end(), this);
  handler_stack_->erase(handler);
  if (handler_stack_->empty()) {
    RestoreAlternateStackLocked();
    RestoreHandlersLocked();
  }
  pthread_mutex_unlock(&handler_stack_mutex_);
}

// Runs before crashing: normal context.
// static
bool ExceptionHandler::InstallHandlersLocked() {
  if (handlers_installed)
    return false;

  // Fail if unable to store all the old handlers.
  for (int i = 0; i < kNumHandledSignals; ++i) {
    if (sigaction(kExceptionSignals[i], NULL, &old_handlers[i]) == -1)
      return false;
  }

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sigemptyset(&sa.sa_mask);

  // Mask all exception signals when we're handling one of them.
  for (int i = 0; i < kNumHandledSignals; ++i)
    sigaddset(&sa.sa_mask, kExceptionSignals[i]);

  sa.sa_sigaction = SignalHandler;
  sa.sa_flags = SA_ONSTACK | SA_SIGINFO;

  for (int i = 0; i < kNumHandledSignals; ++i) {
    if (sigaction(kExceptionSignals[i], &sa, NULL) == -1) {
      // At this point it is impractical to back out changes, and so failure to
      // install a signal is intentionally ignored.
    }
  }
  handlers_installed = true;
  return true;
}

// This function runs in a compromised context: see the top of the file.
// Runs on the crashing thread.
// static
void ExceptionHandler::RestoreHandlersLocked() {
  if (!handlers_installed)
    return;

  for (int i = 0; i < kNumHandledSignals; ++i) {
    if (sigaction(kExceptionSignals[i], &old_handlers[i], NULL) == -1) {
      signal(kExceptionSignals[i], SIG_DFL);
    }
  }
  handlers_installed = false;
}

// void ExceptionHandler::set_crash_handler(HandlerCallback callback) {
//   crash_handler_ = callback;
// }

// This function runs in a compromised context: see the top of the file.
// Runs on the crashing thread.
// static
void ExceptionHandler::SignalHandler(int sig, siginfo_t* info, void* uc) {
  // All the exception signals are blocked at this point.
  pthread_mutex_lock(&handler_stack_mutex_);

  // Sometimes, Breakpad runs inside a process where some other buggy code
  // saves and restores signal handlers temporarily with 'signal'
  // instead of 'sigaction'. This loses the SA_SIGINFO flag associated
  // with this function. As a consequence, the values of 'info' and 'uc'
  // become totally bogus, generally inducing a crash.
  //
  // The following code tries to detect this case. When it does, it
  // resets the signal handlers with sigaction + SA_SIGINFO and returns.
  // This forces the signal to be thrown again, but this time the kernel
  // will call the function with the right arguments.
  struct sigaction cur_handler;
  if (sigaction(sig, NULL, &cur_handler) == 0 &&
      (cur_handler.sa_flags & SA_SIGINFO) == 0) {
    // Reset signal handler with the right flags.
    sigemptyset(&cur_handler.sa_mask);
    sigaddset(&cur_handler.sa_mask, sig);

    cur_handler.sa_sigaction = SignalHandler;
    cur_handler.sa_flags = SA_ONSTACK | SA_SIGINFO;

    if (sigaction(sig, &cur_handler, NULL) == -1) {
      // When resetting the handler fails, try to reset the
      // default one to avoid an infinite loop here.
      signal(sig, SIG_DFL);
    }
    pthread_mutex_unlock(&handler_stack_mutex_);
    return;
  }

  bool handled = false;
  for (int i = handler_stack_->size() - 1; !handled && i >= 0; --i) {
    handled = (*handler_stack_)[i]->HandleSignal(sig, info, uc);
  }

  // Upon returning from this signal handler, sig will become unmasked and then
  // it will be retriggered. If one of the ExceptionHandlers handled it
  // successfully, restore the default handler. Otherwise, restore the
  // previously installed handler. Then, when the signal is retriggered, it will
  // be delivered to the appropriate handler.
  if (handled) {
    signal(sig, SIG_DFL);
  } else {
    RestoreHandlersLocked();
  }

  pthread_mutex_unlock(&handler_stack_mutex_);

  if (info->si_pid || sig == SIGABRT) {
    // This signal was triggered by somebody sending us the signal with kill().
    // In order to retrigger it, we have to queue a new signal by calling
    // kill() ourselves.  The special case (si_pid == 0 && sig == SIGABRT) is
    // due to the kernel sending a SIGABRT from a user request via SysRQ.
  } else {
    // This was a synchronous signal triggered by a hard fault (e.g. SIGSEGV).
    // No need to reissue the signal. It will automatically trigger again,
    // when we return from the signal handler.
  }
}

struct ThreadArgument {
  pid_t pid;  // the crashing process
  const MinidumpDescriptor* minidump_descriptor;
  ExceptionHandler* handler;
  const void* context;  // a CrashContext structure
  size_t context_size;
};

// This is the entry function for the cloned process. We are in a compromised
// context here: see the top of the file.
// static
int ExceptionHandler::ThreadEntry(void *arg) {
  const ThreadArgument *thread_arg = reinterpret_cast<ThreadArgument*>(arg);

  // Block here until the crashing process unblocks us when
  // we're allowed to use ptrace
  thread_arg->handler->WaitForContinueSignal();

  return thread_arg->handler->DoDump(thread_arg->pid, thread_arg->context,
                                     thread_arg->context_size) == false;
}

// This function runs in a compromised context: see the top of the file.
// Runs on the crashing thread.
bool ExceptionHandler::HandleSignal(int, siginfo_t* info, void* uc) {
  if (filter_ && !filter_(callback_context_))
    return false;

  // Allow ourselves to be dumped if the signal is trusted.
  bool signal_trusted = info->si_code > 0;
  // bool signal_pid_trusted = info->si_code == SI_USER ||
  //     info->si_code == SI_TKILL;
  if (signal_trusted || (info->si_pid == getpid())) {
    // prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
  }
  CrashContext context;
  memcpy(&context.siginfo, info, sizeof(siginfo_t));
  memcpy(&context.context, uc, sizeof(ucontext_t));
#if !defined(__ARM_EABI__) && !defined(__mips__)
  // FP state is not part of user ABI on ARM Linux.
  // In case of MIPS Linux FP state is already part of struct ucontext
  // and 'float_state' is not a member of CrashContext.
  ucontext_t *uc_ptr = (ucontext_t*)uc;
  // if (uc_ptr->uc_mcontext.fpregs) {
    // memcpy(&context.float_state,
    //        uc_ptr->uc_mcontext.fpregs,
    //        sizeof(context.float_state));
  // }
#endif
  // context.tid = syscall(__NR_gettid);
  if (crash_handler_ != NULL) {
    if (crash_handler_(&context, sizeof(context), callback_context_)) {
      return true;
    }
  }
  return GenerateDump(&context);
}

// This is a public interface to HandleSignal that allows the client to
// generate a crash dump. This function may run in a compromised context.
bool ExceptionHandler::SimulateSignalDelivery(int sig) {
  siginfo_t siginfo;
  memset(&siginfo, 0, sizeof(siginfo_t));
  // Mimic a trusted signal to allow tracing the process (see
  // ExceptionHandler::HandleSignal().
  siginfo.si_code = SI_USER;
  siginfo.si_pid = getpid();
  ucontext_t context;
  getcontext(&context);
  return HandleSignal(sig, &siginfo, &context);
}

// This function may run in a compromised context: see the top of the file.
bool ExceptionHandler::GenerateDump(CrashContext *context) {
  if (IsOutOfProcess())
    return crash_generation_client_->RequestDump(context, sizeof(*context));

  // Allocating too much stack isn't a problem, and better to err on the side
  // of caution than smash it into random locations.
  static const unsigned kChildStackSize = 16000;
  PageAllocator allocator;
  uint8_t* stack = (uint8_t*) allocator.Alloc(kChildStackSize);
  if (!stack)
    return false;
  // clone() needs the top-most address. (scrub just to be safe)
  stack += kChildStackSize;
  my_memset(stack - 16, 0, 16);

  ThreadArgument thread_arg;
  thread_arg.handler = this;
  thread_arg.minidump_descriptor = &minidump_descriptor_;
  thread_arg.pid = getpid();
  thread_arg.context = context;
  thread_arg.context_size = sizeof(*context);

  // We need to explicitly enable ptrace of parent processes on some
  // kernels, but we need to know the PID of the cloned process before we
  // can do this. Create a pipe here which we can use to block the
  // cloned process after creating it, until we have explicitly enabled ptrace
  if (pipe(fdes) == -1)
  {
    // Creating the pipe failed. We'll log an error but carry on anyway,
    // as we'll probably still get a useful crash report. All that will happen
    // is the write() and read() calls will fail with EBADF
    static const char no_pipe_msg[] = "ExceptionHandler::GenerateDump \
                                       pipe failed:";
    logger::write(no_pipe_msg, sizeof(no_pipe_msg) - 1);
    logger::write(strerror(errno), strlen(strerror(errno)));
    logger::write("\n", 1);
  }

  // const pid_t child = clone(
  //     ThreadEntry, stack, CLONE_FILES | CLONE_FS | CLONE_UNTRACED,
  //     &thread_arg, NULL, NULL, NULL);

  // int r, status;
  // // Allow the child to ptrace us
  // // prctl(PR_SET_PTRACER, child, 0, 0, 0);
  // SendContinueSignalToChild();
  // do {
  //   r = waitpid(child, &status, __WALL);
  // } while (r == -1 && errno == EINTR);

  // close(fdes[0]);
  // close(fdes[1]);

  // if (r == -1) {
  //   static const char msg[] = "ExceptionHandler::GenerateDump waitpid failed:";
  //   logger::write(msg, sizeof(msg) - 1);
  //   logger::write(strerror(errno), strlen(strerror(errno)));
  //   logger::write("\n", 1);
  // }

  // bool success = r != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
  // if (callback_)
  //   success = callback_(minidump_descriptor_, callback_context_, success);
  return false;
}

// This function runs in a compromised context: see the top of the file.
void ExceptionHandler::SendContinueSignalToChild() {
  static const char okToContinueMessage = 'a';
  int r;
  r = HANDLE_EINTR(write(fdes[1], &okToContinueMessage, sizeof(char)));
  if (r == -1)
  {
    static const char msg[] = "ExceptionHandler::SendContinueSignalToChild \
                               write failed:";
    logger::write(msg, sizeof(msg) - 1);
    logger::write(strerror(errno), strlen(strerror(errno)));
    logger::write("\n", 1);
  }
}

// This function runs in a compromised context: see the top of the file.
// Runs on the cloned process.
void ExceptionHandler::WaitForContinueSignal() {
  int r;
  char receivedMessage;
  r = HANDLE_EINTR(read(fdes[0], &receivedMessage, sizeof(char)));
  if (r == -1)
  {
    static const char msg[] = "ExceptionHandler::WaitForContinueSignal \
                               read failed:";
    logger::write(msg, sizeof(msg) - 1);
    logger::write(strerror(errno), strlen(strerror(errno)));
    logger::write("\n", 1);
  }
}

// This function runs in a compromised context: see the top of the file.
// Runs on the cloned process.
bool ExceptionHandler::DoDump(pid_t crashing_process, const void* context,
                              size_t context_size) {
}

// static
bool ExceptionHandler::WriteMinidump(const string& dump_path,
                                     MinidumpCallback callback,
                                     void* callback_context) {
}

bool ExceptionHandler::WriteMinidump() {
}

void ExceptionHandler::AddMappingInfo(const string& name,
                                      const uint8_t identifier[sizeof(MDGUID)],
                                      uintptr_t start_address,
                                      size_t mapping_size,
                                      size_t file_offset) {
}

void ExceptionHandler::RegisterAppMemory(void* ptr, size_t length) {
}

void ExceptionHandler::UnregisterAppMemory(void* ptr) {
}

// static
bool ExceptionHandler::WriteMinidumpForChild(pid_t child,
                                             pid_t child_blamed_thread,
                                             const string& dump_path,
                                             MinidumpCallback callback,
                                             void* callback_context) {}

}  // namespace google_breakpad
