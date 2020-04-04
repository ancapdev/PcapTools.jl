mutable struct PcapStreamWriter{Dst <: IO} <: PcapWriter
    dst::Dst

    function PcapStreamWriter{Dst}(dst::Dst; thiszone = 0, snaplen = 65535) where {Dst <: IO}
        h = PcapHeader(
            0xa1b23c4d,
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

PcapStreamWriter(io::IO; kwargs...) = PcapStreamWriter{typeof(io)}(io; kwargs...)
PcapStreamWriter(path::AbstractString; kwargs...) = PcapStreamWriter(open(path, "w"); kwargs...)

Base.close(x::PcapStreamWriter) = close(x.dst)

function Base.write(x::PcapStreamWriter, timestamp::UnixTime, data::DenseArray{UInt8})
    sec, nsec = fldmod(Dates.value(timestamp), 1_000_000_000)
    data_length = length(data)
    h = RecordHeader(sec, nsec, data_length, data_length)
    write(x.dst, Ref(h))
    write(x.dst, data)
    nothing
end
