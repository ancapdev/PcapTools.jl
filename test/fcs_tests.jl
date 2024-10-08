const PCAP_FILE_HEADER = "TTyyoQIABAAAAAAAAAAAAAAGAAABAAAA"

const PCAP_FCS = """
THLDZMwhDABeAAAAXgAAAAEAXgByrQDXj6hWAQgARQAA
TGk3QAD9Eag2wR1YZ+AAcq1KeuaZADhwtSAAyDL/////HxIFAHRgAwAMAQAAAAAAAAzrS61s+HUX
EADJMv////9OAAAAAAAAALygjcY=
"""

const PCAP_NOFCS = """
ablkZZ4hAgBiAAAAYgAAAAABIQIgTBjATYjFhQgARQAA
VMmzQABAAVv6CksAZQpLAAEIANTpAAIAAWm5ZGUAAAAAlCECAAAAAAAQERITFBUWFxgZGhscHR4f
ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3
"""

const PCAP_CORRUPT_FCS = """
THLDZMwhDABeAAAAXgAAAAEAXgByrQDXj6hWAQgARQAA
TGk3QAD9Eag2wR1YZ+AAcq1KeuaZADhwtSAAyDL/////HxIFAHRgAwAMAQAAAAAAAAzrS61s+HUX
EADJMv////9OAAAAAAAAALygjcg=
"""

# Miniumum ethernet packet size (60 bytes without FCS)
const PCAP_SMALL = """
Tq98Zs+xVzM8AAAAPAAAAAEAXgBynQDXj6hFQQgARQAA
HrAOQAD9EV7swR1bGOAAcp3yuObOAAr2hcD4AAAAAAAAAAAAAAAAAAAAAA==
"""

# Non-IPv4 packet (ARP protocol)
const PCAP_NONIP = """
8+/iZolNFC1AAAAAQAAAAAD2Y0DDvGQ/XwHjQwgGAAEI
AAYEAAFkP18B40Na4gKMAAAAAAAAWuICgQAAAAAAAAAAAAAAAAAAAAAAAOr6Tyw=
"""

check_detect_fcs(packets; confirm_checksum=true) =
    pushfirst!(packets, PCAP_FILE_HEADER) |>
    join |>
    base64decode |>
    PcapBufferReader |>
    (x -> try_detect_fcs(x; confirm_checksum))

@testset "pcap_has_fcs" begin
    @test pcap_has_fcs(PcapBufferReader(base64decode(PCAP_FILE_HEADER * PCAP_FCS)))
    @test !pcap_has_fcs(PcapBufferReader(base64decode(PCAP_FILE_HEADER * PCAP_NOFCS)))
end

@testset "try_detect_fcs" begin
    @test check_detect_fcs([PCAP_NONIP]) == FCS_UNDETERMINED
    @test check_detect_fcs([PCAP_SMALL]) == FCS_UNDETERMINED
    @test check_detect_fcs([""]) == FCS_UNDETERMINED # empty pcap

    @test check_detect_fcs([PCAP_NONIP, PCAP_SMALL, PCAP_FCS]) == FCS_PRESENT
    @test check_detect_fcs([PCAP_NONIP, PCAP_SMALL, PCAP_NOFCS]) == FCS_ABSENT

    # Corrupt FCS packets will be ignored by default
    @test check_detect_fcs([PCAP_NONIP, PCAP_SMALL, PCAP_CORRUPT_FCS]) == FCS_UNDETERMINED
    # But corrupt FCS can be explicitly allowed
    @test check_detect_fcs([PCAP_NONIP, PCAP_SMALL, PCAP_CORRUPT_FCS]; confirm_checksum = false) == FCS_PRESENT

    # Make sure we skip corrupt frames if confirm_checksum is on
    @test check_detect_fcs([PCAP_NONIP, PCAP_SMALL, PCAP_CORRUPT_FCS, PCAP_FCS]) == FCS_PRESENT
    @test check_detect_fcs([PCAP_NONIP, PCAP_SMALL, PCAP_CORRUPT_FCS, PCAP_NOFCS]) == FCS_ABSENT
end

@testset "compute_fcs" begin
    r_fcs = read(PcapBufferReader(base64decode(PCAP_FILE_HEADER * PCAP_FCS)))
    @test check_fcs(r_fcs)
    r_no_fcs = read(PcapBufferReader(base64decode(PCAP_FILE_HEADER * PCAP_CORRUPT_FCS)))
    @test !check_fcs(r_no_fcs)
end
