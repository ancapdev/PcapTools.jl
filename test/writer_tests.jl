@testset "PcapStreamWriter" begin
    io = IOBuffer()
    writer = PcapStreamWriter(io)
    write(writer, UnixTime(Dates.UTInstant(Nanosecond(1234))), [0x5, 0x6, 0x7, 0x8, 0x9])
    data = take!(io)
    @assert length(data) == sizeof(PcapHeader) + sizeof(RecordHeader) + 5
    GC.@preserve data begin
        p = pointer(data)
        h = unsafe_load(Ptr{PcapHeader}(p))
        @test h.magic == 0xa1b23c4d
        @test h.version_major == 2
        @test h.version_minor == 4
        @test h.thiszone == 0
        @test h.sigfigs == 0
        @test h.linktype == LINKTYPE_ETHERNET
        rh = unsafe_load(Ptr{RecordHeader}(p + sizeof(PcapHeader)))
        @test rh.ts_sec == 0
        @test rh.ts_usec == 1234
        @test rh.incl_len == 5
        @test rh.orig_len == 5
    end
    @test data[end-4:end] == [0x5, 0x6, 0x7, 0x8, 0x9]
end
