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
