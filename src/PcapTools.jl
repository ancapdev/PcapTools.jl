module PcapTools

using Mmap
using Dates

export PcapRecord
export PcapReader
export PcapWriter

export LINKTYPE_NULL, LINKTYPE_ETHERNET

include("pcap_header.jl")
include("record_header.jl")
include("record.jl")
include("reader.jl")
include("writer.jl")

end
