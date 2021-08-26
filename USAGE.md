### skbtrace dump

#### Example 1. Tracing VM-originated packet headers

```
$ skbtrace dump -P recv -i tapv3o26n4m0-1 -o task -o ip -o tcp 
Attaching 2 probes...
14:10:53.440666955 - kprobe:netif_receive_skb_internal
TASK: comm cgav3o26n4m0ihn pid 243419 tid 243419
IP: ihl/ver 45 tot_len 60 frag_off 0 (- DF) check f49d
IP: id 50354 ttl 64 protocol 6 saddr 192.168.0.13 daddr 192.168.0.14
TCP: source 53982 dest 80 check 819a
TCP: seq 4274905144 ack_seq 0 doff 10 win 29200
TCP: flags S----
```

In this example we trace packets sent by Virtual Machine `cgav3o26n4m0ihn`
(this is an incomplete id, as Yandex.Cloud VM ids have 20 characters, but only
16 fit into task comm). Note that we use `recv` probe because from the point
of virtual router, packets are received. 

#### Example 2. Tracing tunneled packet headers

```
$ skbtrace dump -e udp -u eth1 -F 'tcp-flags == S' -F 'dst == 192.168.0.14' \
 -P xmit -o outer-ip -o outer-udp -o outer-mpls -o inner-ip -o inner-tcp    
Attaching 2 probes...
14:04:58.100840452 - kprobe:dev_queue_xmit
OUTER-IP: ihl/ver 45 tot_len 92 frag_off 0 (- -) check bdfa
OUTER-IP: id 26347 ttl 64 protocol 17 saddr 10.2.32.173 daddr 10.2.32.251
OUTER-UDP: source 50017 dest 6635 check 0 len 72
OUTER-MPLS: label 25
INNER-IP: ihl/ver 45 tot_len 60 frag_off 0 (- DF) check 5365
INNER-IP: id 26347 ttl 63 protocol 6 saddr 192.168.0.13 daddr 192.168.0.14
INNER-TCP: source 47234 dest 80 check 989f
INNER-TCP: seq 2101063532 ack_seq 0 doff 10 win 29200
INNER-TCP: flags S----
```

`xmit` is an alias for `kprobe:dev_queue_xmit`. `dev_queue_xmit` is key function 
used to put packet into network device's queue, hence  its kprobe will be used in 
most examples.

The first line identifies time the packet was captured as default `--time-mode` is
`time` with nanosecond precision. The following line dump all headers in MPLSoUDP
encapsulation up to inner TCP header. Note that this requires `-e udp` encapsulation
type hint, and that skbtrace applies implicit filters such as IP version being
correct in inner/outer headers, while UDP destination port is 6635 (which is a
MPLSoUDP port).

This example also contains additional filters: only SYN packets going to Virtual
Machine with address `192.168.0.14` are traced.

### skbtrace aggregate

#### Example 1. Most active clients

```
$ skbtrace aggregate -P xmit -i tapaem6obrop-1 -p tcp -F 'dport == 80' -k src
Attaching 3 probes...
14:30:48
@[192.168.0.19]: 12
@[192.168.0.13]: 20
```

In this example we trace transmissions to `tapaem6obrop-1` interface to an
nginx target listening tcp port 80 and group them by IP Source Address. As 
aggregation (by default `count` is used) suggests, client `192.168.0.13` 
produces more connections than another VM.

### skbtrace timeit

#### Example 1. Forwarding time for packets

```
$ skbtrace timeit forward -e udp -i tapv3o26n4m0-1 --egress -p tcp
Attaching 6 probes...
14:17:51
@:
[8, 16)                5 |@@@@@@@@@@@@@                                       |
[16, 32)              20 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[32, 64)              10 |@@@@@@@@@@@@@@@@@@@@@@@@@@                          |
[64, 128)              1 |@@                                                  |
```

which is roughly equivalent to
```
$ skbtrace timeit -e udp -p tcp \
    from -P recv -i tapv3o26n4m0-1 -k 'dst,sport,dport,seq' \
    to -P xmit -u eth1 -k 'inner-dst,inner-sport,inner-dport,inner-seq' 
```

In this example, time spent delivering TCP packets from tap interface to eth1 
underlay interface is measured and aggregated in histogram. The histogram is 
printed once in 1s. Since `--unit` is not specified, the default time unit used
which is us (microseconds), hence median value of TCP delivery is about 20 us.

The `from` and `to` subcommands work similar to `dump` command: probe and its 
filter should be specified. However, there is a special required parameter: 
`-k` contains list of fields used to map packets (in this example it is source
address is excepted as it is the same for all ingress packets).

#### Example 2. Tracing long TCP handshake five tuples

``` 
$ skbtrace timeit tcp handshake -e udp -i tapv3o26n4m0-1 --egress -p tcp \
    outliers --threshold 1ms -o ip -o tcp
Attaching 4 probes...
TIME: 1594 us
14:25:08.903615363 - kprobe:netif_receive_skb_internal
IP: ihl/ver 45 tot_len 52 frag_off 0 (- DF) check a7f8
IP: id 4448 ttl 64 protocol 6 saddr 192.168.0.13 daddr 192.168.0.14
TCP: source 41980 dest 80 check 8192
TCP: seq 539588272 ack_seq 2481332728 doff 8 win 229
TCP: flags -A---
```

In this example first packet in TCP session is dumped because time since 
sending SYN exceeds 1 ms.
