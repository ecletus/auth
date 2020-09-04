package auth

import "net/mail"

// Schema auth schema
type Schema struct {
	Provider string
	UID      string

	Name      string
	Email     string
	FirstName string
	LastName  string
	Location  string
	Lang      []string
	Image     string
	Phone     string
	URL       string

	RawInfo interface{}
}

func (this *Schema) MailAddress() *mail.Address {
	if this.Email == "" {
		return nil
	}
	name := this.FirstName
	if name != "" {
		if this.LastName != "" {
			name += " " + this.LastName
		}
	} else {
		name = this.Name
	}
	return &mail.Address{name, this.Email}
}
