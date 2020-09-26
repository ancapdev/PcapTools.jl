strip_nothing_(::Type{Union{Nothing, T}}) where T = T
strip_nothing_(::Type{T}) where T = T
infer_key_type_(record2key) = strip_nothing_(Core.Compiler.return_type(record2key, (PcapRecord,)))

progress_noop_(n) = nothing

function splitcap(
    ::Type{KeyType},
    reader::PcapReader,
    record2key,
    key2stream,
    progress_callback = progress_noop_
) where {KeyType}
    buffer_size = 1024 * 512
    max_pending_buffers = 16
    outputs = Dict{KeyType, Tuple{Ref{Vector{UInt8}}, Channel{Vector{UInt8}}}}()
    finished_buffers = Channel{Vector{UInt8}}(Inf)
    n = 0
    @sync begin
        try
            while !eof(reader)
                record = read(reader)
                dst = record2key(record)
                if dst isa KeyType
                    buffer, ready_buffers = get!(outputs, dst) do
                        dstio = key2stream(dst)
                        buffer = sizehint!(UInt8[], buffer_size)
                        append!(buffer, reader.raw_header)
                        ready_buffers = Channel{Vector{UInt8}}(max_pending_buffers)
                        Threads.@spawn begin
                            try
                                for b in $(ready_buffers)
                                    write($dstio, b)
                                    empty!(b)
                                    put!($(finished_buffers), b)
                                end
                            finally
                                close($dstio)
                            end
                            nothing
                        end
                        Ref(buffer), ready_buffers
                    end
                    append!(buffer[], record.raw)
                    if length(buffer[]) >= buffer_size
                        put!(ready_buffers, buffer[])
                        if isready(finished_buffers)
                            buffer[] = take!(finished_buffers)
                        else
                            buffer[] = sizehint!(UInt8[], buffer_size)
                        end
                    end
                end
                n += 1
                progress_callback(n)
            end
        finally
            for (buffer, ready_buffers) in values(outputs)
                if !isempty(buffer[])
                    put!(ready_buffers, buffer[])
                end
            end
            for (buffer, ready_buffers) in values(outputs)
                close(ready_buffers)
            end
        end
    end
    nothing
end

splitcap(
    reader::PcapReader,
    record2key,
    key2stream,
    progress_callback = progress_noop_
) = splitcap(infer_key_type_(record2key), reader, record2key, key2stream, progress_callback)
