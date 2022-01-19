`skbtrace` is a helper tool for generating and running BPFTrace scripts which trace and measure timings related 
to Linux Networking Stack, specifically SocKet Buffer contents (hence the name). 

It can be used to:
  - find TCP retransmits even in encapsulated packets;
  - roughly measure packet forwarding times;
  - simple tcpdump replacement which allows to trace some kernel routines which are not accessible by tcpdump. 

An example of such routine is `kfree_skb` which is called when kernel frees (drops) packet.

[![Go Reference](https://pkg.go.dev/badge/github.com/yandex-cloud/skbtrace.svg)](https://pkg.go.dev/github.com/yandex-cloud/skbtrace)

#### Usage

For the usage examples see [Usage](USAGE.md)

For full documentation see [skbtrace(1)](docs/skbtrace.md)

#### Building 

```bash
go get -u github.com/yandex-cloud/skbtrace
go build -o skbtrace 
```

or 

```bash
git clone github.com/yandex-cloud/skbtrace
make build
```

#### Requirements

`skbtrace` is tested with Linux Kernel 4.14 and BPFTrace 0.9.2.

#### Extending

`skbtrace` can be extended by:
- Adding extra shortcut commands and root command child while using one of the visitors 
such as `DumpTracerCommand`.
- Extending builder with additional protocols, field and probe descriptions in `SetUp()` method of cli 
dependencies structure.
- Or by simply contributing a patch (see [Contributing](CONTRIBUTING.md)).

#### License 

See [License](LICENSE.md)
