const ETHERNET_MIN_LENGTH = 64
const ETHERNET_FCS_LENGTH = 4

"""
    pcap_has_fcs(::PcapReader)

Heuristically determine whether captured frames contain Ethernet FCS or not.
Unfortunately, PCAP format doesn't provide this information explicitly.
"""
function pcap_has_fcs(reader::PcapReader)
    mark(reader)
    try
        while !eof(reader)
            record = read(reader)

            hdr = record.header
            # In case of min-length packets we can't be certain whether they have FCS or not.
            hdr.orig_len <= ETHERNET_MIN_LENGTH && continue

            ep = decode_ethernet(record.data)
            ep.header.ethertype != ETHERTYPE_IPV4 && continue

            ipp = decode_ipv4(ep.payload)
            if ipp.header.total_length + sizeof(EthernetHeader) + ETHERNET_FCS_LENGTH == hdr.orig_len
                return true
            elseif ipp.header.total_length + sizeof(EthernetHeader) == hdr.orig_len
                return false
            end
        end
        # if we couldn't read single IP packet, it doesn't really matter what to return
        return false
    catch e
        if e isa EOFError
            return false
        else
            rethrow()
        end
    finally
        reset(reader)
    end
end

