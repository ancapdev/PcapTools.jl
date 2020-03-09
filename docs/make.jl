using Documenter, PcapTools

makedocs(
    sitename="PcapTools.jl",
    format = Documenter.HTML(
        prettyurls = get(ENV, "CI", nothing) == "true"))
