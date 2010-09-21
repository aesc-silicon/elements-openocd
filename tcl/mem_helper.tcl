# Helper for common memory read/modify/write procedures

# mrw: "memory read word", returns value of $reg
proc mrw {reg} {
	set value ""
	ocd_mem2array value 32 $reg 1
	return $value(0)
}

add_usage_text mrw "address"
add_help_text mrw "Returns value of word in memory."

# mmw: "memory modify word", updates value of $reg
#       $reg <== ((value & ~$clearbits) | $setbits)
proc mmw {reg setbits clearbits} {
	set old [mrw $reg]
	set new [expr ($old & ~$clearbits) | $setbits]
	mww $reg $new
}

add_usage_text mmw "address setbits clearbits"
add_help_text mmw "Modify word in memory. new_val = (old_val & ~clearbits) | setbits;"
