const ETHERNET_FCS_LENGTH = 4

# NOTE: some constants pulled from NetworkProtocols.jl to avoid taking a dependency
const ETHERNET_MIN_LENGTH = 64
const ETHERNET_HEADER_SIZE = 14
const ETHERNET_ETHERTYPE_OFFSET = 12
const ETHERTYPE_IPV4 = UInt16(0x0800)
const IP_TOTAL_LENGTH_OFFSET = ETHERNET_HEADER_SIZE + 2

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

            frame = pointer(record.data)
            ethertype = GC.@preserve record unsafe_load(convert(Ptr{UInt16}, frame + ETHERNET_ETHERTYPE_OFFSET))
            ethertype = ntoh(ethertype)
            ethertype != ETHERTYPE_IPV4 && continue

            ip_total_length = GC.@preserve record unsafe_load(convert(Ptr{UInt16}, frame + IP_TOTAL_LENGTH_OFFSET))
            ip_total_length = ntoh(ip_total_length)
            if ip_total_length + ETHERNET_HEADER_SIZE + ETHERNET_FCS_LENGTH == hdr.orig_len
                return true
            elseif ip_total_length + ETHERNET_HEADER_SIZE == hdr.orig_len
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

"""
    compute_fcs(x::PcapRecord) -> UInt32

Recompute the FCS for a record.
"""
function compute_fcs(x::PcapRecord)
    data_no_fcs = UnsafeArray{UInt8, 1}(x.data.pointer, x.data.size .- ETHERNET_FCS_LENGTH)
    GC.@preserve x CRC32.unsafe_crc32(data_no_fcs, length(data_no_fcs) % Csize_t, 0x00000000)
end


"""
    check_fcs(x::PcapRecord) -> Bool

Check the FCS is correct for a record. Assumes that the FCS exists.
"""
check_fcs(x::PcapRecord) = x.fcs == compute_fcs(x)
