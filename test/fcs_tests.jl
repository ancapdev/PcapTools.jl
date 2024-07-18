const PCAP_FCS = base64decode("""
1MOyoQIABAAAAAAAAAAAAABAAAABAAAATHLDZMwhDABeAAAAXgAAAAEAXgByrQDXj6hWAQgARQAA
TGk3QAD9Eag2wR1YZ+AAcq1KeuaZADhwtSAAyDL/////HxIFAHRgAwAMAQAAAAAAAAzrS61s+HUX
EADJMv////9OAAAAAAAAALygjcY=
""")

const PCAP_NOFCS = base64decode("""
1MOyoQIABAAAAAAAAAAAAAAABAABAAAAablkZZ4hAgBiAAAAYgAAAAABIQIgTBjATYjFhQgARQAA
VMmzQABAAVv6CksAZQpLAAEIANTpAAIAAWm5ZGUAAAAAlCECAAAAAAAQERITFBUWFxgZGhscHR4f
ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3
""")

const PCAP_CORRUPT_FCS = base64decode("""
1MOyoQIABAAAAAAAAAAAAABAAAABAAAATHLDZMwhDABeAAAAXgAAAAEAXgByrQDXj6hWAQgARQAA
TGk3QAD9Eag2wR1YZ+AAcq1KeuaZADhwtSAAyDL/////HxIFAHRgAwAMAQAAAAAAAAzrS61s+HUX
EADJMv////9OAAAAAAAAALygjcg=
""")

@testset "pcap_has_fcs" begin
    @test pcap_has_fcs(PcapBufferReader(PCAP_FCS))
    @test !pcap_has_fcs(PcapBufferReader(PCAP_NOFCS))
end

@testset "compute_fcs" begin
    r_fcs = read(PcapBufferReader(PCAP_FCS))
    @test compute_fcs(r_fcs) == fcs(r_fcs)
    r_no_fcs = read(PcapBufferReader(PCAP_CORRUPT_FCS))
    @test compute_fcs(r_no_fcs) != fcs(r_no_fcs)
end
