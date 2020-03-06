mutable struct PcapReader
    data::Vector{UInt8}
    header::PcapHeader
    offset::Int64
    mark::Int64
    usec_mul::Int64
    bswapped::Bool

    function PcapReader(data::Vector{UInt8})
        length(data) < sizeof(PcapHeader) && throw(EOFError())
        h = unsafe_load(Ptr{PcapHeader}(pointer(data)))
        if h.magic == 0xa1b2c3d4
            bswapped = false
            nanotime = false
        elseif h.magic == 0xd4c3b2a1
            bswapped = true
            nanotime = false
        elseif h.magic == 0xa1b23c4d
            bswapped = false
            nanotime = true
        elseif h.magic == 0x4d3cb2a1
            bswapped = true
            nanotime = true
        else
            throw(ArgumentError("Invalid pcap header"))
        end
        if bswapped
            h = bswap(h)
        end
        new(data, h, sizeof(h), -1, nanotime ? 1 : 1000, bswapped)
    end
end

function PcapReader(path::AbstractString)
    io = open(path)
    data = Mmap.mmap(io)
    PcapReader(data)
end

function Base.close(x::PcapReader)
    x.data = UInt8[]
    x.offset = 0
    nothing
end

Base.length(x::PcapReader) = length(x.data)
Base.position(x::PcapReader) = x.offset; nothing
Base.seek(x::PcapReader, pos) = x.offset = pos; nothing

function Base.mark(x::PcapReader)
    x.mark = x.offset
    x.mark
end

function Base.unmark(x::PcapReader)
    if x.mark >= 0
        x.mark = -1
        true
    else
        false
    end
end

Base.ismarked(x::PcapReader) = x.mark >= 0

function Base.reset(x::PcapReader)
    !ismarked(x) && error("PcapReader not marked")
    x.offset = x.mark
    x.mark = -1
    x.offset
end

Base.eof(x::PcapReader) = (length(x) - x.offset) < sizeof(RecordHeader)

function Base.read(x::PcapReader)
    eof(x) && throw(EOFError())
    h = unsafe_load(Ptr{RecordHeader}(pointer(x.data) + x.offset))
    x.offset += sizeof(RecordHeader)
    if x.bswapped
        h = bswap(h)
    end
    t1 = (h.ts_sec + x.header.thiszone) * 1_000_000_000
    t2 = Int64(h.ts_usec) * x.usec_mul
    t = Dates.Nanosecond(t1 + t2)
    payload = pointer(x.data) + x.offset
    x.offset += h.incl_len
    x.offset > length(x) && error("Insufficient data in pcap record")
    PcapRecord(h, t, payload)
end
