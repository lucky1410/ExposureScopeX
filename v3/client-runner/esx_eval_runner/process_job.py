"""Windows command lifetime containment, including ordinary child processes.

A gated Python launcher cannot start the command until its parent assigns it
to a kill-on-close Job Object. No process-name lookup or taskkill is required.
This controls lifetime, not filesystem/network access or hostile code escape.
"""

import os
from pathlib import Path
import subprocess
import sys
import time


def run_windows_job(command, cwd, timeout, env=None):
    import ctypes
    from ctypes import wintypes as w

    class BasicLimits(ctypes.Structure):
        _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                    ("flags", w.DWORD), ("min_working_set", ctypes.c_size_t),
                    ("max_working_set", ctypes.c_size_t), ("active_processes", w.DWORD),
                    ("affinity", ctypes.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD)]

    class IOCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in
                    ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [("basic", BasicLimits), ("io", IOCounters),
                    ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                    ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]

    class Accounting(ctypes.Structure):
        _fields_ = [(name, ctypes.c_longlong) for name in
                    ("user_time", "kernel_time", "period_user_time", "period_kernel_time")] + [
                    (name, w.DWORD) for name in ("page_faults", "total_processes", "active_processes", "terminated_processes")]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
    kernel.CreateJobObjectW.restype = w.HANDLE
    kernel.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
    kernel.SetInformationJobObject.restype = w.BOOL
    kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
    kernel.AssignProcessToJobObject.restype = w.BOOL
    kernel.TerminateJobObject.argtypes = [w.HANDLE, w.UINT]
    kernel.TerminateJobObject.restype = w.BOOL
    kernel.QueryInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.c_void_p]
    kernel.QueryInformationJobObject.restype = w.BOOL
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
    kernel.WaitForSingleObject.restype = w.DWORD
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CloseHandle.restype = w.BOOL
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    process = None
    assigned = False
    wait_handles = []
    try:
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise ctypes.WinError(ctypes.get_last_error())
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), *command], cwd=cwd, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW)
        if not kernel.AssignProcessToJobObject(job, int(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())
        assigned = True
        process.stdin.write(b"G")
        process.stdin.close()
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None
    finally:
        try:
            if assigned:
                # Termination is not completion. Wait for all descendants to
                # exit before callers clean up working directories or fixtures.
                capacity = 64
                while True:
                    class ProcessIds(ctypes.Structure):
                        _fields_ = [("assigned", w.DWORD), ("count", w.DWORD),
                                    ("ids", ctypes.c_size_t * capacity)]
                    members = ProcessIds()
                    ok = kernel.QueryInformationJobObject(job, 3, ctypes.byref(members), ctypes.sizeof(members), None)
                    if ok and members.count >= members.assigned:
                        break
                    if (not ok and ctypes.get_last_error() != 234) or capacity >= 65536:
                        raise OSError("Could not enumerate owned Windows command processes for cleanup")
                    capacity *= 2
                for pid in members.ids[:members.count]:
                    handle = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE, never terminate by PID
                    if handle:
                        wait_handles.append(handle)
                if not kernel.TerminateJobObject(job, 125):
                    raise ctypes.WinError(ctypes.get_last_error())
                deadline = time.monotonic() + 10
                for handle in wait_handles:
                    remaining = max(0, int((deadline - time.monotonic()) * 1000))
                    if kernel.WaitForSingleObject(handle, remaining) != 0:
                        raise OSError("Windows command process termination did not complete")
                while True:
                    accounting = Accounting()
                    if not kernel.QueryInformationJobObject(job, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None):
                        raise ctypes.WinError(ctypes.get_last_error())
                    if not accounting.active_processes:
                        break
                    if time.monotonic() >= deadline:
                        raise OSError("Windows command descendants did not finish terminating within the cleanup deadline")
                    time.sleep(.01)
        finally:
            for handle in wait_handles:
                kernel.CloseHandle(handle)
            # Kill-on-close remains the fallback if querying/termination fails.
            kernel.CloseHandle(job)
            if process is not None:
                if process.stdin and not process.stdin.closed:
                    process.stdin.close()
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=10)


if __name__ == "__main__":
    if os.name != "nt" or sys.stdin.buffer.read(1) != b"G" or len(sys.argv) < 2:
        raise SystemExit(125)
    raise SystemExit(subprocess.run(sys.argv[1:], stdin=subprocess.DEVNULL).returncode)
