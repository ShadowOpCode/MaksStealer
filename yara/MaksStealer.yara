rule MaksStealer {
  strings:
    $sig = "HellomynameisMaxIm17IlovemakingRAT" ascii
	$sig2 = "Max/Maxt" ascii
  condition:
    $sig or $sig2
}