function splitcap(
    ::Type{KeyType},
    record2key,
    key2name,
    path::AbstractString,
    outbasepath::AbstractString) where {KeyType}

    reader = PcapBufferReader(path)
    outputs = Dict{KeyType, BufferedOutputStream{IOStream}}()
    p = Progress(length(reader.data), 0.1)
    last_progress_update = zero(reader.offset)
    progress_update_delta = ceil(Int, length(reader.data) / 100)
    try
        while !eof(reader)
            start_offset = reader.offset
            record = read(reader, ZeroCopyPcapRecord)
            dst = record2key(record)
            if dst isa KeyType
                output = get!(outputs, dst) do
                    dstpath = "$(outbasepath)_$(key2name(dst)).pcap"
                    o = BufferedOutputStream(open(dstpath, "w"))
                    append!(o, reader.data, 1, sizeof(PcapHeader))
                    o
                end
                append!(output, reader.data, start_offset + 1, reader.offset)
            end
            if reader.offset - last_progress_update > progress_update_delta
                update!(p, reader.offset)
                last_progress_update = reader.offset
            end
        end
        update!(p, reader.offset)
    finally
        for output in values(outputs)
            close(output)
        end
        close(reader)
    end
    nothing
end
