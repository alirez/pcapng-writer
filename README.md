# pcapng-writer

An implementation of the pcapng capture file format encoding.

This library is based on the draft standard version 02 ([draft-tuexen-opsawg-pcapng-02](https://tools.ietf.org/html/draft-tuexen-opsawg-pcapng-02)).

# Supported block types

| Block Type                       | Supported? |
| -------------------------------- | ---------- |
| Section Header Block             |  Yes       |
| Interface Description Block      |  Yes       |
| Enhanced Packet Block            |  Yes       |
| Simple Packet Block              |  Yes       |
| Name Resolution Block            |  No        |
| Interface Statistics Block       |  Yes       |
| systemd Journal Export Block     |  No        |
| Decryption Secrets Block         |  No        |
| Custom Block                     |  No        |


# Supported option types

| Block Type                       | Option             | Supported? |
| -------------------------------- | ------------------ | ---------- |
| Common                           | `opt_endofopt`     | Yes        |
| Common                           | `opt_comment`      | Yes        |
| Common                           | `opt_custom`       | No         |
| Section Header Block             | `shb_hardware`     | No         |
| Section Header Block             | `shb_os`           | No         |
| Section Header Block             | `shb_userappl`     | No         |
| Interface Description Block      | `if_name`          | Yes        |
| Interface Description Block      | `if_description`   | Yes        |
| Interface Description Block      | `if_IPv4addr`      | Yes        |
| Interface Description Block      | `if_IPv6addr`      | Yes        |
| Interface Description Block      | `if_MACaddr`       | Yes        |
| Interface Description Block      | `if_EUIaddr`       | No         |
| Interface Description Block      | `if_speed`         | No         |
| Interface Description Block      | `if_tsresol`       | Yes        |
| Interface Description Block      | `if_tzone`         | No         |
| Interface Description Block      | `if_filter`        | No         |
| Interface Description Block      | `if_os`            | No         |
| Interface Description Block      | `if_fcslen`        | No         |
| Interface Description Block      | `if_tsoffset`      | No         |
| Interface Description Block      | `if_hardware`      | No         |
| Enhanced Packet Block            | `epb_flags`        | Yes        |
| Enhanced Packet Block            | `epb_hash`         | No         |
| Enhanced Packet Block            | `epb_dropcount`    | No         |
| Name Resolution Block            | `ns_dnsname`       | No         |
| Name Resolution Block            | `ns_dnsIP4addr`    | No         |
| Name Resolution Block            | `ns_dnsIP6addr`    | No         |
| Interface Statistics Block       | `isb_starttime`    | No         |
| Interface Statistics Block       | `isb_endtime`      | No         |
| Interface Statistics Block       | `isb_ifrecv`       | No         |
| Interface Statistics Block       | `isb_ifdrop`       | No         |
| Interface Statistics Block       | `isb_filteraccept` | No         |
| Interface Statistics Block       | `isb_osdrop`       | No         |
| Interface Statistics Block       | `isb_usrdeliv`     | No         |


# License

This project is licensed under the MIT license.

See [LICENSE-MIT](LICENSE-MIT) for details.
