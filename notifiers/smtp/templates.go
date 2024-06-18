package smtp

var plaintextTmpl = `Status: {{ .Status }}
{{- if .Action }}
Action: {{ .Action }}
{{- end }}
{{- if .Actionner }}
Actionner: {{ .Actionner }}
{{- end }}
{{- if .Rule }}
Rule: {{ .Rule }}
{{- end }}
{{- if .Event }}
Event: {{ .Event }}
{{- end }}
Message: {{ .Message }}
{{- range $key, $value := .Objects }}
{{ $key }}: {{ $value }}
{{- end }}
{{- if .Error }}
Error: {{ .Error }}
{{- end }}
{{- if .Result }}
Result: {{ .Result }}
{{- end }}
{{- if .Output }}
Output: 
{{ .Output }}
{{- end }}
{{- if .Target }}
Target: {{ .Target }}
{{- end }}
Trace ID: {{ .TraceID }}
`

var htmlTmpl = `
{{ $color := "#858585" }}
{{ $prio := printf "%v" .Status }}
{{ if eq $prio "success" }}{{ $color = "#23ba47" }}{{ end }}
{{ if eq $prio "failure" }}{{ $color = "#e20b0b" }}{{ end }}
{{ if eq $prio "ignored" }}{{ $color = "#a4a8b1" }}{{ end }}

<meta http-equiv="Content-Type" content="text/html; charset=us-ascii">
<style type="text/css">
    td{font-family:arial,helvetica,sans-serif;}
</style>

<table cellpadding="5" cellspacing="0" style="font-family:arial,helvetica,sans-serif; height:2px; width:800px;">
    <tbody>
        <tr>
            <td><img src="https://raw.githubusercontent.com/cncf/artwork/master/projects/falco/horizontal/color/falco-horizontal-color.png" width="117px" height="47"></td>
            <td></td>
        </tr>
    </tbody>
</table>
<br>
<table cellpadding="3" cellspacing="0" style="font-family:arial,helvetica,sans-serif; height:2px; width:800px;">
    <tbody>
        <tr>
            <td style="background-color:{{ $color }}; width:800px; text-align:center;"><span style="font-size:12px; color:#fff;"><strong>{{ .Status }}</strong></span></td>
        </tr>
    </tbody>
</table>
<table cellpadding="5" cellspacing="0" style="font-family:arial,helvetica,sans-serif; width:800px; font-size:13px">
    <tbody>
        {{ if .Action }}
        <tr>
            <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Action</strong></span></td>
            <td style="background-color:#d1d6da">{{ .Action }}</td>
        </tr>
        {{ end }}
        {{ if .Actionner }}
        <tr>
            <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Actionner</strong></span></td>
            <td style="background-color:#d1d6da">{{ .Actionner }}</td>
        </tr>
        {{ end }}
        {{ if .Rule }}
        <tr>
            <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Rule</strong></span></td>
            <td style="background-color:#d1d6da">{{ .Rule }}</td>
        </tr>
        {{ end }}
        {{ range $key, $value := .Objects }}
            <tr>
                <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>{{ $key }}</strong></span></td>
                <td style="background-color:#d1d6da">{{ $value }}</td>
            </tr>
        {{ end }}
        {{ if .Event }}
        <tr>
            <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Event</strong></span></td>
            <td style="background-color:#d1d6da">{{ .Event }}</td>
        </tr>
        {{ end }}
        {{ if .Target }}
        <tr>
            <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Target</strong></span></td>
            <td style="background-color:#d1d6da">{{ .Target }}</td>
        </tr>
        {{ end }}
        <tr>
            <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Message</strong></span></td>
            <td style="background-color:#d1d6da">{{ .Message }}</td>
        </tr>
        <tr>
            <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Trace ID</strong></span></td>
            <td style="background-color:#d1d6da">{{ .TraceID }}</td>
        </tr>
        {{ if .Error }}
            <tr>
                <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Error</strong></span></td>
                <td style="background-color:#d1d6da">{{ .Error }}</td>
            </tr>
        {{ end }}
        {{ if .Result }}
            <tr>
                <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Result</strong></span></td>
                <td style="background-color:#d1d6da">{{ .Result }}</td>
            </tr>
        {{ end }}
        {{ if .Output }}
        <tr>
            <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Output</strong></span></td>
            <td style="background-color:#d1d6da;max-width:502px;overflow:hidden;">{{ printf "%s" .Output }}</td>
        </tr>
        {{ end }}
    </tbody>
</table>
<br>

--4t74weu9byeSdJTM--`
