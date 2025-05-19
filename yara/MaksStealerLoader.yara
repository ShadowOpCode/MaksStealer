rule MaksStealer_Loader {
  meta:
    author = "ShadowOpCode"
    description = "Detects MaksStealer dropper/loader JAR"
    last_modified = "2025-05-18"

  strings:
    $s0 = "MaxCoffe" ascii nocase

  condition:
    uint16be(0) == 0x504B and
    $s0
}
