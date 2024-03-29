## skbtrace timeit from to evcount

Counts each time from or to probe is hit. Useful for testing filters.

```
skbtrace timeit from to evcount [flags]
```

### Options

```
  -h, --help   help for evcount
```

### Options inherited from parent commands

```
      --bpftrace string         Path to bpftrace binary (default "bpftrace")
  -D, --dump                    Dump bpftrace command instead of running it
  -e, --encap string            Type of encapsulation: 'gre' or 'udp' (default "gre")
  -p, --hint strings            Protocol hints for weak field aliases such as 'tcp' for 'sport'.
  -i, --iface string            Interface device name. Shortcut for '$netdev->name == "Device"' filter.
  -6, --inet6                   If specified, skbtrace assumes that inner header is IPv6.
      --struct-keyword string   Use struct keyword in casts: "" - do not use, "struct" - use, "auto" - deduce based on bpftrace version. (default "auto")
  -T, --timeout duration        Execution timeout for resulting bpftrace script (default 1m0s)
      --unit string             Time unit using for measurements: 'sec', 'ms', 'us' - default or 'ns' (default "us")
```

### SEE ALSO

* [skbtrace timeit from to](skbtrace_timeit_from_to.md)	 - Specification of probe that measures time delta after 'from' probe firing

###### Auto generated by spf13/cobra on 21-Aug-2022
