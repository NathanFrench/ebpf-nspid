Displaying a process ID (PID) which resides inside a namespace can be tricky when it comes to EBPF. This code shows the basic tools needed to emulate the `VNR` functions found within sched.h in LLVM-aware C eBPF.


```sh
make
sudo -E go run ./load.go
# in another terminal
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

The data written to `trace_pipe` will contain messages along the lines of:

```
top-13392 [000] .... 1033211.910189: 0x00000001: >> PID=13392 NSPID=15
top-13392 [000] .... 1033211.910590: 0x00000001: >> PID=13392 NSPID=15
top-13392 [000] .... 1033211.910780: 0x00000001: >> PID=13392 NSPID=15
top-13392 [000] .... 1033211.910827: 0x00000001: >> PID=13392 NSPID=15
```

In the above case, I am running `top` inside an ubuntu docker container. The parent system marks the pid as 13392, and the pid inside the container is 15.
