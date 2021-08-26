struct {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;

    uint8_t flags2_doff;
    uint8_t flags1;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;

    uint8_t options[8];
} __attribute__((packed));
