//### author = "Sec51"
//### url = "https://sec51.com"
//### email = "info@sec51.com"
//### total_rules = "{{.TotalSignatures}}"
//### last_generation = "{{.LastGeneration}}"

import "pe"
import "elf"
import "hash"
{{range .Sigs}}
rule {{.MalwareName}} : clamav
{
    strings:
        $signature = {{if .IsString}}"{{.SigHash}}"{{else}}{ {{.SigHash}} }{{end}}

    condition:
    	$signature {{if .IsNdbSignature}}{{if .NdbSig.IsAbsoluteOffset}}at {{.NdbSig.Offset}}
    	{{else if .NdbSig.IsEndOfFileMinusOffset}}at (filesize - {{.NdbSig.Offset}})    	
    	{{else if .NdbSig.RequirePEModule}}{{if .NdbSig.IsEntryPointPlusOffset}}in (pe.entry_point..pe.entry_point + {{.NdbSig.MaxShift}})
    	{{else if .NdbSig.IsEntryPointMinusOffset}}in (pe.entry_point..pe.entry_point - {{.NdbSig.MaxShift}})
    	{{else if .NdbSig.IsStartSectionAtOffset}}in (pe.sections[{{.NdbSig.Offset}}].virtual_address..pe.sections[{{.NdbSig.Offset}}].virtual_address + {{.NdbSig.MaxShift}}) or $signature in (pe.sections[{{.NdbSig.Offset}}].raw_data_offset..pe.sections[{{.NdbSig.Offset}}].raw_data_offset + {{.NdbSig.MaxShift}})
    	{{else if .NdbSig.IsLastSectionAtOffset}}in (pe.sections[(pe.number_of_sections -1)].virtual_address..pe.sections[(pe.number_of_sections -1)].virtual_address + {{.NdbSig.MaxShift}}) or $signature in (pe.sections[(pe.number_of_sections -1)].raw_data_offset..pe.sections[(pe.number_of_sections -1)].raw_data_offset + {{.NdbSig.MaxShift}})
    	{{else if .NdbSig.IsEntireSectionOffset}}at elf.sections[{{.NdbSig.Offset}}].virtual_address or $signature at elf.sections[{{.NdbSig.Offset}}].raw_data_offset{{end}}
		{{else if .NdbSig.RequirePEModule}}{{if .IsEntryPointPlusOffset}}in (elf.entry_point..elf.entry_point + {{.NdbSig.MaxShift}})
		{{else if .NdbSig.IsEntryPointMinusOffset}}in (elf.entry_point..elf.entry_point - {{.NdbSig.MaxShift}})
		{{else if .NdbSig.IsStartSectionAtOffset}}in (elf.sections[{{.NdbSig.Offset}}].virtual_address..elf.sections[{{.NdbSig.Offset}}].virtual_address + {{.NdbSig.MaxShift}}) or $signature in (elf.sections[{{.Offset}}].raw_data_offset..elf.sections[{{.NdbSig.Offset}}].raw_data_offset + {{.NdbSig.MaxShift}})
		{{else if .NdbSig.IsLastSectionAtOffset}}in (elf.sections[(elf.number_of_sections -1)].virtual_address..elf.sections[(elf.number_of_sections -1)].virtual_address + {{.NdbSig.MaxShift}}) or $signature in (elf.sections[(elf.number_of_sections -1)].raw_data_offset..elf.sections[(elf.number_of_sections -1)].raw_data_offset + {{.NdbSig.MaxShift}})
		{{else if .NdbSig.IsEntireSectionOffset}}at pe.sections[{{.Offset}}].virtual_address or $signature at pe.sections[{{.NdbSig.Offset}}].raw_data_offset{{end}}
		{{end}}{{end}}
}
{{end}}
