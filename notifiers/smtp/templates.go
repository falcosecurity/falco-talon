package smtp

var plaintextTmpl = `Status: {{ .Status }}
Action: {{ .Action }}
Rule: {{ .Rule }}
Pod: {{ .Pod }}
Namespace: {{ .Namespace }}`

var htmlTmpl = `
{{ $color := "#858585" }}
{{ $prio := printf "%v" .Status }}
{{ if eq $prio "success" }}{{ $color = "#26CD29" }}{{ end }}
{{ if eq $prio "failure" }}{{ $color = "#EB2C1B" }}{{ end }}

<meta http-equiv="Content-Type" content="text/html; charset=us-ascii">
<style type="text/css">
    td{font-family:arial,helvetica,sans-serif;}
</style>

<table cellpadding="3" cellspacing="0" style="font-family:arial,helvetica,sans-serif; height:2px; width:700px;">
    <tbody>
        <tr>
            <td><img src="https://raw.githubusercontent.com/cncf/artwork/master/projects/falco/horizontal/color/falco-horizontal-color.png" width="117px" height="47"></td>
            <td></td>
        </tr>
    </tbody>
</table>
<br>
<table cellpadding="3" cellspacing="0" style="font-family:arial,helvetica,sans-serif; height:2px; width:700px;">
    <tbody>
        <tr>
            <td style="background-color:{{ $color }}; width:700px; text-align:center;"><span style="font-size:12px; color:#fff;"><strong>{{ .Status }}</strong></span></td>
        </tr>
    </tbody>
</table>
<table cellpadding="5" cellspacing="0" style="font-family:arial,helvetica,sans-serif; width:700px; font-size:13px">
    <tbody>
        <tr>
            <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Action</strong></span></td>
            <td style="background-color:#d1d6da">{{ .Action }}</td>
        </tr>
        <tr>
            <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Rule</strong></span></td>
            <td style="background-color:#d1d6da">{{ .Rule }}</td>
        </tr>
        <tr>
            <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Pod</strong></span></td>
            <td style="background-color:#d1d6da">{{ .Pod }}</td>
        </tr>
        <tr>
            <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Namespace</strong></span></td>
            <td style="background-color:#d1d6da">{{ .Namespace }}</td>
        </tr>
    </tbody>
</table>
<br>

--4t74weu9byeSdJTM--`
