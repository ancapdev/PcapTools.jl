strip_nothing_(::Type{Union{Nothing, T}}) where T = T
strip_nothing_(::Type{T}) where T = T
infer_key_type_(record2key) = strip_nothing_(Core.Compiler.return_type(record2key, (ZeroCopyPcapRecord,)))

splitcap(record2key, key2stream, path::AbstractString) = splitcap(infer_key_type_(record2key), record2key, key2stream, path)

function splitcap(
    ::Type{KeyType},
    record2key,
    key2stream,
    path::AbstractString
) where {KeyType}
    buffer_size = 1024 * 512
    max_pending_buffers = 16
    reader = PcapBufferReader(path)
    outputs = Dict{KeyType, Tuple{Ref{Vector{UInt8}}, Channel{Vector{UInt8}}}}()
    p = Progress(length(reader.data), 0.1)
    last_progress_update = zero(reader.offset)
    progress_update_delta = ceil(Int, length(reader.data) / 100)
    inflight_buffers = 0
    max_inflight_buffers = max(Threads.nthreads() * 2 + max_pending_buffers, 128)
    finished_buffers = Channel{Vector{UInt8}}(max_inflight_buffers)
    @sync begin
        try
            while !eof(reader)
                start_offset = reader.offset
                record = read(reader, ZeroCopyPcapRecord)
                dst = record2key(record)
                if dst isa KeyType
                    buffer, ready_buffers = get!(outputs, dst) do
                        dstio = key2stream(dst)
                        buffer = sizehint!(UInt8[], buffer_size)
                        append!(buffer, @view reader.data[1:sizeof(PcapHeader)])
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
                    append!(buffer[], @view reader.data[start_offset + 1:reader.offset])
                    if length(buffer[]) >= buffer_size
                        put!(ready_buffers, buffer[])
                        inflight_buffers += 1
                        if isready(finished_buffers) || inflight_buffers >= max_inflight_buffers
                            buffer[] = take!(finished_buffers)
                            inflight_buffers -= 1
                        else
                            buffer[] = sizehint!(UInt8[], buffer_size)
                        end
                    end
                end
                if reader.offset - last_progress_update > progress_update_delta
                    update!(p, reader.offset)
                    last_progress_update = reader.offset
                end
            end
            update!(p, reader.offset)
        finally
            for (buffer, ready_buffers) in values(outputs)
                if !isempty(buffer[])
                    put!(ready_buffers, buffer[])
                end
            end
            for (buffer, ready_buffers) in values(outputs)
                close(ready_buffers)
            end
            while isready(finished_buffers)
                take!(finished_buffers)
            end
            close(reader)
        end
    end
    nothing
end
