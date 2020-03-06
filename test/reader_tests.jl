@testset "PcapReader" begin

@testset "empty" begin
    @test_throws EOFError PcapReader(UInt8[])
end

@testset "invalid" begin
    @test_throws EOFError PcapReader([0x0])
    @test_throws ArgumentError PcapReader(zeros(UInt8, 100))
end

@testset "formats" begin
    gendata(magic, swapfun) = begin
        data = zeros(UInt8, 24 + 16 + 8) # file header + record header + payload
        unsafe_store!(Ptr{UInt32}(pointer(data)), swapfun(magic)) # usec
        unsafe_store!(Ptr{UInt16}(pointer(data) + 4), swapfun(UInt16(0x0002))) # ver major
        unsafe_store!(Ptr{UInt16}(pointer(data) + 6), swapfun(UInt16(0x0004))) # ver minor
        unsafe_store!(Ptr{UInt32}(pointer(data) + 16), swapfun(UInt32(65535))) # snaplen
        unsafe_store!(Ptr{UInt32}(pointer(data) + 20), swapfun(LINKTYPE_ETHERNET)) # linktype
        unsafe_store!(Ptr{UInt32}(pointer(data) + 24), swapfun(UInt32(11))) # ts_sec
        unsafe_store!(Ptr{UInt32}(pointer(data) + 28), swapfun(UInt32(13))) # ts_usec
        unsafe_store!(Ptr{UInt32}(pointer(data) + 32), swapfun(UInt32(8))) # incl_len
        unsafe_store!(Ptr{UInt32}(pointer(data) + 36), swapfun(UInt32(8))) # orig_len
        unsafe_store!(Ptr{UInt64}(pointer(data) + 40), 0x0102030405060708) # orig_len
        data
    end
    checkreader(reader, ns) = begin
        @test reader.header.magic == (ns ? 0xa1b23c4d : 0xa1b2c3d4)
        @test reader.header.version_major == 2
        @test reader.header.version_minor == 4
        @test reader.header.snaplen == 65535
        @test reader.header.linktype == LINKTYPE_ETHERNET
        record = read(reader)
        @test eof(reader)
        @test record.header.ts_sec == 11
        @test record.header.ts_usec == 13
        @test record.header.incl_len == 8
        @test record.header.orig_len == 8
        @test record.timestamp.value == 11 * 1_000_000_000 + 13 * (ns ? 1 : 1000)
        @test unsafe_load(Ptr{UInt64}(record.data)) == 0x0102030405060708
    end
    checkreader(PcapReader(gendata(0xa1b2c3d4, identity)), false) # usec
    checkreader(PcapReader(gendata(0xa1b2c3d4, bswap)), false)    # usec, bswapped
    checkreader(PcapReader(gendata(0xa1b23c4d, identity)), true)  # nsec
    checkreader(PcapReader(gendata(0xa1b23c4d, bswap)), true)     # nsec, bswapped
end

end
