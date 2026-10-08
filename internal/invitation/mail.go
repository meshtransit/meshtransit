package invitation

import (
	"bytes"
	"fmt"
	htmltemplate "html/template"
	"strings"
	texttemplate "text/template"
	"time"
)

// Mail is one rendered message; transports deliver it as is.
type Mail struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

var roleLabels = map[string]string{
	"admin": "Admin", "network_admin": "Network admin", "it_admin": "IT admin",
	"security_admin": "Security admin", "billing_admin": "Billing admin", "auditor": "Auditor",
}

type mailFields struct {
	Inviter   string
	Workspace string
	Role      string
	Link      string
	Expires   string
}

var textBody = texttemplate.Must(texttemplate.New("text").Parse(`{{.Inviter}} invited you to join the {{.Workspace}} Workspace on MeshTransit{{if .Role}} as {{.Role}}{{end}}.

Accept the invitation:
{{.Link}}

Sign in with the account of this email address. The link works once and expires on {{.Expires}}.
If you did not expect this invitation, you can ignore this email.
`))

var htmlBody = htmltemplate.Must(htmltemplate.New("html").Parse(`<!doctype html>
<html><body style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1f2328;line-height:1.5">
<p><strong>{{.Inviter}}</strong> invited you to join the <strong>{{.Workspace}}</strong> Workspace on MeshTransit{{if .Role}} as {{.Role}}{{end}}.</p>
<p><a href="{{.Link}}" style="display:inline-block;padding:10px 16px;background:#1f6feb;color:#ffffff;border-radius:6px;text-decoration:none">Accept invitation</a></p>
<p style="color:#59636e;font-size:13px">Sign in with the account of this email address. The link works once and expires on {{.Expires}}.<br>If you did not expect this invitation, you can ignore this email.</p>
</body></html>
`))

// render builds the invitation email; names are display text, never markup.
func render(invitation Invitation, workspaceName, link string) (Mail, error) {
	inviter := strings.TrimSpace(invitation.InvitedBy.DisplayName)
	if inviter == "" {
		inviter = "A Workspace administrator"
	}
	fields := mailFields{
		Inviter: inviter, Workspace: workspaceName, Role: roleLabels[invitation.Role], Link: link,
		Expires: invitation.ExpiresAt.UTC().Format("2 January 2006 15:04 UTC"),
	}
	var text, html bytes.Buffer
	if err := textBody.Execute(&text, fields); err != nil {
		return Mail{}, fmt.Errorf("render invitation text: %w", err)
	}
	if err := htmlBody.Execute(&html, fields); err != nil {
		return Mail{}, fmt.Errorf("render invitation html: %w", err)
	}
	subject := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, fmt.Sprintf("%s invited you to %s on MeshTransit", inviter, workspaceName))
	return Mail{To: invitation.Email, Subject: subject, Text: text.String(), HTML: html.String()}, nil
}

// expiresAt is when a link sent now stops working.
func expiresAt(now time.Time) time.Time { return now.Add(Lifetime).UTC().Truncate(time.Second) }
