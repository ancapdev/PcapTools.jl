mutable struct PcapWriter{Dst <: IO}
    dst::Dst

    function PcapWriter{Dst}(dst::Dst; thiszone = 0, snaplen = 65535) where {Dst <: IO}
        h = PcapHeader(
            0xa1b2c3d4,
            0x0002,
            0x0004,
            thiszone,
            0,
            snaplen,
            LINKTYPE_ETHERNET)
        write(dst, Ref(h))
        new(dst)
    end
end

PcapWriter(io::IO; kwargs...) = PcapWriter{typeof(io)}(io; kwargs...)

Base.close(x::PcapWriter) = close(x.dst)

function Base.write(x::PcapWriter, timestamp::Nanosecond, data::Ptr{UInt8}, data_length::Integer)
    sec, nsec = fldmod(timestamp.value, 1_000_000_000)
    h = RecordHeader(sec, nsec, data_length, data_length)
    write(x.dst, Ref(h))
    unsafe_write(x.dst, data, data_length)
    nothing
end
