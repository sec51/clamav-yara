rule {{.RuleName}} : banker
{
      meta:
		author="malware-lu"
    strings: 
        $a = {6A 40 68 00 30 00 00 6A 14 8D 91}  
        $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
        $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"

    condition:
        $a or $b or $c
}