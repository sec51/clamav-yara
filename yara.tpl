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
    	$signature {{if .IsAbsoluteOffset}}at {{.Offset}}
    	{{else if .IsEndOfFileMinusOffset}}at (filesize - {{.Offset}})    	
    	{{else if .RequirePEModule}}{{if .IsEntryPointPlusOffset}}in (pe.entry_point..pe.entry_point + {{.MaxShift}})
    	{{else if .IsEntryPointMinusOffset}}in (pe.entry_point..pe.entry_point - {{.MaxShift}})
    	{{else if .IsStartSectionAtOffset}}in (pe.sections[{{.Offset}}].virtual_address..pe.sections[{{.Offset}}].virtual_address + {{.MaxShift}}) or $signature in (pe.sections[{{.Offset}}].raw_data_offset..pe.sections[{{.Offset}}].raw_data_offset + {{.MaxShift}})
    	{{else if .IsLastSectionAtOffset}}in (pe.sections[(pe.number_of_sections -1)].virtual_address..pe.sections[(pe.number_of_sections -1)].virtual_address + {{.MaxShift}}) or $signature in (pe.sections[(pe.number_of_sections -1)].raw_data_offset..pe.sections[(pe.number_of_sections -1)].raw_data_offset + {{.MaxShift}})
    	{{else if and .IsEntireSectionOffset .RequireELFModule}}at elf.sections[{{.Offset}}].virtual_address or $signature at elf.sections[{{.Offset}}].raw_data_offset{{end}}
		{{else if .RequirePEModule}}{{if .IsEntryPointPlusOffset}}in (elf.entry_point..elf.entry_point + {{.MaxShift}})
		{{else if .IsEntryPointMinusOffset}}in (elf.entry_point..elf.entry_point - {{.MaxShift}})
		{{else if .IsStartSectionAtOffset}}in (elf.sections[{{.Offset}}].virtual_address..elf.sections[{{.Offset}}].virtual_address + {{.MaxShift}}) or $signature in (elf.sections[{{.Offset}}].raw_data_offset..elf.sections[{{.Offset}}].raw_data_offset + {{.MaxShift}})
		{{else if .IsLastSectionAtOffset}}in (elf.sections[(elf.number_of_sections -1)].virtual_address..elf.sections[(elf.number_of_sections -1)].virtual_address + {{.MaxShift}}) or $signature in (elf.sections[(elf.number_of_sections -1)].raw_data_offset..elf.sections[(elf.number_of_sections -1)].raw_data_offset + {{.MaxShift}})
		{{else if and .IsEntireSectionOffset .RequirePEModule}}at pe.sections[{{.Offset}}].virtual_address or $signature at pe.sections[{{.Offset}}].raw_data_offset{{end}}
		{{end}}        
}
{{end}}
