module PcapTools

using Blobs
using Mmap

export PcapStream
export PcapRecord

# NOTE: Not using @enum because it craps out when displaying unknown values
const LINKTYPE_NULL = UInt32(0)
const LINKTYPE_ETHERNET = UInt32(1)

struct PcapHeader
    magic::UInt32
    version_major::UInt16
    version_minor::UInt16
    thiszone::Int32
    sigfigs::UInt32
    snaplen::UInt32
    linktype::UInt32
end

function Base.bswap(x::PcapHeader)
    PcapHeader(
        bswap(x.magic),
        bswap(x.version_major),
        bswap(x.version_minor),
        bswap(x.thiszone),
        bswap(x.sigfigs),
        bswap(x.snaplen),
        bswap(x.linktype))
end

struct RecordHeader
    ts_sec::UInt32
    ts_usec::UInt32
    incl_len::UInt32
    orig_len::UInt32
end

function Base.bswap(x::RecordHeader)
    RecordHeader(
        bswap(x.ts_sec),
        bswap(x.ts_usec),
        bswap(x.incl_len),
        bswap(x.orig_len))
end

mutable struct PcapStream
    io::IOStream
    data::Vector{UInt8}
    header::PcapHeader
    offset::Int64
    mark::Int64
    bswapped::Bool
    nanotime::Bool

    function PcapStream(path::AbstractString)
        io = open(path)
        data = Mmap.mmap(io)
        p = convert(Ptr{Nothing}, pointer(data))
        h = Blob{PcapTools.PcapHeader}(p, 0, length(data))[]
        if h.magic == 0xa1b2c3d4
            bswapped = false
            nanotime = true
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
            throw(ArgumentError("$path is not a valid pcap file"))
        end
        if bswapped
            h = bswap(h)
        end
        new(io, data, h, sizeof(h), -1, bswapped, nanotime)
    end
end

function Base.close(x::PcapStream)
    close(x.io)
    x.data = UInt8[]
    x.offset = 0
    nothing
end

Base.length(x::PcapStream) = length(x.data)

struct PcapRecord
    timestamp::Int64 # nanoseconds since epoch
    length::Int64
    data::Ptr{Nothing}
end

function Base.mark(x::PcapStream)
    x.mark = x.offset
    x.mark
end

function Base.unmark(x::PcapStream)
    if x.mark >= 0
        x.mark = -1
        true
    else
        false
    end
end

Base.ismarked(x::PcapStream) = x.mark >= 0

function Base.reset(x::PcapStream)
    !ismarked(x) && error("Stream not marked")
    x.offset = x.mark
    x.mark = -1
    x.offset
end

Base.eof(x::PcapStream) = (length(x) - x.offset) < sizeof(RecordHeader)

function Base.read(x::PcapStream)
    p = convert(Ptr{Nothing}, pointer(x.data))
    o = x.offset
    h = Blob{RecordHeader}(p, o, length(x))[]
    if x.bswapped
        h = bswap(h)
    end
    # TODO: timezone adjustment
    t1 = (h.ts_sec + x.header.thiszone) * 1_000_000_000
    t2 = Int64(h.ts_usec)
    if !x.nanotime
        t2 *= 1000
    end
    t = t1 + t2
    x.offset = o + sizeof(RecordHeader) + h.incl_len
    PcapRecord(t, h.incl_len, pointer(x.data, o + sizeof(RecordHeader) + 1))
end


end
