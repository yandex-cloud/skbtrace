## skbtrace timeit tcp handshake

Measures time for TCP handshake

```
skbtrace timeit tcp handshake {--ingress|--egress} [--underlay] -i ITF [flags]
```

### Examples

```
handshake --ingress -i tapxx-0 -6
```

### Options

```
  -h, --help   help for handshake
```

### Options inherited from parent commands

```
      --bpftrace string    path to bpftrace binary (default "bpftrace")
  -D, --dump               "dump bpftrace command instead of running it"
      --egress             Direction is egress (from specified interface)
  -e, --encap string       Type of encapsulation: 'gre' or 'udp' (default "gre")
  -F, --filter strings     Filters. Use 'fields' subcommand to list available fields.
  -p, --hint strings       Protocol hints for weak field aliases such as 'tcp' for 'sport'.
  -i, --iface string       Interface device name. Shortcut for '$netdev->name == "Device"' filter.
  -6, --inet6              If specified, skbtrace assumes that inner header is IPv6.
      --ingress            Direction is ingress (towards specified interface)
  -T, --timeout duration   Execution timeout for resulting bpftrace script (default 1m0s)
      --underlay           Capture TCP in underlay interface.
      --unit string        time unit using for measurements: 'sec', 'ms', 'us' - default or 'ns' (default "us")
```

### SEE ALSO

* [skbtrace timeit tcp](skbtrace_timeit_tcp.md)	 - Measures tcp-related timings and outliers
* [skbtrace timeit tcp handshake aggregate](skbtrace_timeit_tcp_handshake_aggregate.md)	 - Aggregates time delta using specified function
* [skbtrace timeit tcp handshake evcount](skbtrace_timeit_tcp_handshake_evcount.md)	 - Counts each time from or to probe is hit. Useful for testing filters.
* [skbtrace timeit tcp handshake outliers](skbtrace_timeit_tcp_handshake_outliers.md)	 - Dumps structures that exceed specified threshold

###### Auto generated by spf13/cobra on 11-Oct-2021
