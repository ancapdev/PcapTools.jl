"""
Reads pcap data from a stream.
"""
mutable struct PcapStreamReader{Src <: IO} <: PcapReader
    src::Src
    header::PcapHeader
    usec_mul::Int64
    bswapped::Bool

    @doc """
        PcapStreamReader(src::IO)

    Create reader over `src`. Will read and process pcap header,
    and yield records through `read(::PcapStreamReader)`.
    """
    function PcapStreamReader(src::Src) where {Src <: IO}
        header_ref = Ref{PcapHeader}()
        read!(src, header_ref)
        header, bswapped, nanotime = process_header(header_ref[])
        new{Src}(src, header, nanotime ? 1 : 1000, bswapped)
    end
end

"""
    PcapStreamReader(path)

Open file at `path` and create PcapStreamReader over its content.
"""
PcapStreamReader(path::AbstractString) = PcapStreamReader(open(path))

Base.close(x::PcapStreamReader) = close(x.src)
Base.position(x::PcapStreamReader) = position(x.src)
Base.seek(x::PcapStreamReader, pos) = seek(x.src, pos)
Base.mark(x::PcapStreamReader) = mark(x.src)
Base.unmark(x::PcapStreamReader) = unmark(x.src)
Base.ismarked(x::PcapStreamReader) = ismarked(x.src)
Base.reset(x::PcapStreamReader) = reset(x.src)
Base.eof(x::PcapStreamReader) = eof(x.src)

"""
    read(x::PcapStreamReader, ::Type{ArrayPcapRecord}) -> ArrayPcapRecord

Read one record from pcap data. Throws `EOFError` if no more data available.
"""
function Base.read(x::PcapStreamReader, ::Type{ArrayPcapRecord})
    record_header_ref = Ref{RecordHeader}()
    read!(x.src, record_header_ref)
    record_header = record_header_ref[]
    if x.bswapped
        record_header = bswap(record_header)
    end
    t1 = (record_header.ts_sec + x.header.thiszone) * 1_000_000_000
    t2 = Int64(record_header.ts_usec) * x.usec_mul
    t = UnixTime(Dates.UTInstant(Nanosecond(t1 + t2)))
    payload = read(x.src, record_header.incl_len)
    ArrayPcapRecord(record_header, t, payload)
end
