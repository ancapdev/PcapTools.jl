module PcapTools

using Mmap
using Dates
using UnsafeArrays

export PcapRecord, ZeroCopyPcapRecord, ArrayPcapRecord
export PcapReader, PcapStreamReader, PcapBufferReader
export PcapWriter

export LINKTYPE_NULL, LINKTYPE_ETHERNET

abstract type PcapReader end

include("pcap_header.jl")
include("record_header.jl")
include("record.jl")
include("buffer_reader.jl")
include("stream_reader.jl")
include("writer.jl")

end
