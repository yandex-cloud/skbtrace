struct {
    uint8_t priority_version;
    uint8_t flow_lbl[3];
    uint16_t payload_len;
    uint8_t nexthdr;
    uint8_t hop_limit;
    union {
        uint8_t  saddr8[16];
        uint16_t saddr16[8];
        uint32_t saddr32[4];
        uint64_t saddr64[2];
    };
    union {
        uint8_t  daddr8[16];
        uint16_t daddr16[8];
        uint32_t daddr32[4];
        uint64_t daddr64[2];
    };
} __attribute__((packed));
