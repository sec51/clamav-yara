import "pe"
import "elf"
{{range .}}
rule {{.MalwareName}} : clamav
{
	meta:
		author = "Sec51"
		url = "https://sec51.com"
		email = "info@sec51.com"

    strings:
        $signature = {{if .IsString}}"{{.SigHash}}"{{else}}{ {{.SigHash}} }{{end}}

    condition:
        $signature
}
{{end}}
