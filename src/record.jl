struct PcapRecord
    header::RecordHeader
    timestamp::Dates.Nanosecond
    data::Ptr{UInt8}
end
