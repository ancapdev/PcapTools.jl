struct PcapRecord{T}
    header::RecordHeader
    timestamp::Dates.Nanosecond
    data::T
end

"""
Non-owning record of pcap data.
Facilitates zero-copy and zero-allocation reading of pcap data.
Underlying [`PcapBufferReader`](@ref) must remain referenced.
"""
const ZeroCopyPcapRecord = PcapRecord{UnsafeArray{UInt8, 1}}

"""
Owning record of pcap data.
"""
const ArrayPcapRecord = PcapRecord{Vector{UInt8}}
