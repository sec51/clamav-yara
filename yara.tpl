/*
    author = "Sec51"
	url = "https://sec51.com"
	email = "info@sec51.com"
*/
import "pe"
import "elf"
{{range .}}
rule {{.MalwareName}} : clamav
{
    strings:
        $signature = {{if .IsString}}"{{.SigHash}}"{{else}}{ {{.SigHash}} }{{end}}

    condition:
        $signature {{if .IsAbsoluteOffset}}at {{.Offset}}
        {{else if .IsEndOfFileMinusOffset}}at (filesize - {{.Offset}})
        {{else if and .IsEntryPointPlusOffset .RequirePEModule}}in (pe.entry_point..pe.entry_point + {{.MaxShift}})
        {{else if and .IsEntryPointMinusOffset .RequirePEModule}}in (pe.entry_point..pe.entry_point - {{.MaxShift}})
        {{else if and .IsEntryPointPlusOffset .RequireELFModule}}in (elf.entry_point..elf.entry_point + {{.MaxShift}})
        {{else if and .IsEntryPointMinusOffset .RequireELFModule}}in (elf.entry_point..elf.entry_point - {{.MaxShift}})
        {{else if and .IsStartSectionAtOffset .RequirePEModule}}in (pe.sections[{{.Offset}}].virtual_address..pe.sections[{{.Offset}}].virtual_address + {{.MaxShift}}) or $signature in (pe.sections[{{.Offset}}].raw_data_offset..pe.sections[{{.Offset}}].raw_data_offset + {{.MaxShift}})
        {{else if and .IsStartSectionAtOffset .RequireELFModule}}in (elf.sections[{{.Offset}}].virtual_address..elf.sections[{{.Offset}}].virtual_address + {{.MaxShift}}) or $signature in (elf.sections[{{.Offset}}].raw_data_offset..elf.sections[{{.Offset}}].raw_data_offset + {{.MaxShift}})
        {{else if and .IsLastSectionAtOffset .RequirePEModule}}in (pe.sections[(pe.number_of_sections -1)].virtual_address..pe.sections[(pe.number_of_sections -1)].virtual_address + {{.MaxShift}}) or $signature in (pe.sections[(pe.number_of_sections -1)].raw_data_offset..pe.sections[(pe.number_of_sections -1)].raw_data_offset + {{.MaxShift}})
        {{else if and .IsLastSectionAtOffset .RequireELFModule}}in (elf.sections[(elf.number_of_sections -1)].virtual_address..elf.sections[(elf.number_of_sections -1)].virtual_address + {{.MaxShift}}) or $signature in (elf.sections[(elf.number_of_sections -1)].raw_data_offset..elf.sections[(elf.number_of_sections -1)].raw_data_offset + {{.MaxShift}})
        {{else if and .IsEntireSectionOffset .RequireELFModule}}at elf.sections[{{.Offset}}].virtual_address or $signature at elf.sections[{{.Offset}}].raw_data_offset
        {{else if and .IsEntireSectionOffset .RequirePEModule}}at pe.sections[{{.Offset}}].virtual_address or $signature at pe.sections[{{.Offset}}].raw_data_offset{{end}}
}
{{end}}
