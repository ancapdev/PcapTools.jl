using Dates
using PcapTools
using Test
using UnixTimes

@testset "PcapTools.jl" begin
    include("reader_tests.jl")
    include("writer_tests.jl")
end
