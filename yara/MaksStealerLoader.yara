rule MaksStealer_Loader {
  strings:
    $s0 = "MaxCoffe" ascii nocase
  condition:
    uint16be(0) == 0x504B and
    $s0
}