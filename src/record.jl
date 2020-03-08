abstract type PcapRecord end

"""
Non-owning record of pcap data.
Facilitates zero-copy and zero-allocation reading of pcap data.
Underlying [`PcapBufferReader`](@PcapBufferReader) must remain referenced.
"""
struct ZeroCopyPcapRecord <: PcapRecord
    header::RecordHeader
    timestamp::Dates.Nanosecond
    data::Ptr{UInt8}
end

"""
Owning record of pcap data.
"""
struct ArrayPcapRecord <: PcapRecord
    header::RecordHeader
    timestamp::Dates.Nanosecond
    owned_data::Vector{UInt8}
end

function Base.getproperty(x::ArrayPcapRecord, f::Symbol)
    f == :data && return pointer(x.owned_data)
    getfield(x, f)
end

function Base.propertynames(x::ArrayPcapRecord, private = false)
    (fieldnames(ArrayPcapRecord)..., :data)
end
