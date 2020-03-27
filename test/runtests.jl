using PcapTools
using Dates
using Test

@testset "PcapTools.jl" begin
    include("reader_tests.jl")
    include("writer_tests.jl")
end
