module PcapTools

using Dates
using Mmap
using UnixTimes
using UnsafeArrays
using CRC32

export PcapHeader, RecordHeader
export PcapRecord
export PcapReader, PcapStreamReader, PcapBufferReader
export PcapWriter, PcapStreamWriter
export LINKTYPE_NULL, LINKTYPE_ETHERNET
export splitcap
export pcap_has_fcs, check_fcs, compute_fcs, ETHERNET_FCS_LENGTH

abstract type PcapReader end
abstract type PcapWriter end

include("pcap_header.jl")
include("record_header.jl")
include("record.jl")
include("buffer_reader.jl")
include("stream_reader.jl")
include("stream_writer.jl")
include("splitcap.jl")
include("fcs.jl")

end
