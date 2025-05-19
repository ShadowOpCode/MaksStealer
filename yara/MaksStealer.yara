rule MaksStealer {
  meta:
    author = "ShadowOpCode"
    description = "Detects MaksStealer main payload"
    last_modified = "2025-05-18"

  strings:
    $sig = "HellomynameisMaxIm17IlovemakingRAT" ascii
    $sig2 = "Max/Maxt" ascii

  condition:
    $sig or $sig2
}
