# bperf

Utility for high-frequency profiling of Intel hardware counters.

This tool has two components - a Linux kernel module for the actual profiling, and a userspace
application that configures the events to collect, reads data from the kernel module, and writes it
to a csv file.

## Building and running

To build everything, run

```bash
$ make
```

Load the kernel module

```bash
$ sudo insmod ./src/bperf.ko
```

You can see the list of loaded kernel modules using `lsmod`. You can also inspect the files it adds
under the `/sys/kernel/bperf` directory.

```bash
$ lsmod | grep bperf
$ ls /sys/kernel/bperf
```

### Running the userspace application

The userspace application is `bperf` in the project root directory. It needs to be run as root.
The help output details the available options. But in the most basic form, you need to provide it a
list of events to collect using the configurable counters.

A bit of detail - Intel processors have a few fixed-function counters (usually 3), which collect
pre-defined events (instructions retired, clock cycles, reference clock cycles). There are also a
few configurable counters (around 4), which can be configured to collect different events. You can
get the number of fixed and configurable counters by reading the `num_fixed` and `num_pmc` files in
`/sys/kernel/bperf`. You can get the list of available events for the current architecture using
the `-l` option when running `bperf`.

```bash
$ bperf -l               # Get list of available events
$ bperf L2_RQSTS.MISS    # Start profiling and set PMC0 to collect the specified event
```

## Extending the tool

### Adding more events

All you'll need to do is all the event to the huge macro inside `src/arch_def_macro.h`. For instace,
to add the hypothetical event `ABC.XYZ`, you'll add a line that looks something like this

```c
__BPERF_PER_EVENT(ABC, XYZ)
```

### Adding support for more architectures

This is more involved. You'll need to modify `src/arch_events.c`.

#### Step 1 - Add list of events

You can look at the existing list of events, for example `EVENTS_XEON_E5_V3`. These just linearly
list events from the Intel Software Development Manuals, volume 3. There are helpful macros like
`PMC`, `PMC_CMASK` etc. to help define events, and you really should use those since those macros
are redefined at multiple places to do different things. So for the hypothetical architecture
"Arch X", you might add a list that looks like -

```c
static struct bperf_event_tuple EVENTS_ARCH_X[] = {
  ...
  ...
  { 0 }
};
```

It's really important to terminate the list with a null entry, a struct where every element is 0.
That's how a lot of code knows when to stop iterating through the list.

#### Step 2 - Map architecture(s) to list of events

Next, you go to the end of the file, and add another entry to the `EVENTS` array. This is an array
of structs with three fields, the cpu `family`, cpu `model`, and an array of `events` for that
architecture.
