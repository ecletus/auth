package auth

type UIDFinder interface {
	FindUID(ctx *Context, identifier string) (uid string, err error)
}

type UIDFinders []UIDFinder

func (this UIDFinders) FindUID(ctx *Context, identifier string) (uid string, err error) {
	for _, finder := range this {
		if uid, err = finder.FindUID(ctx, identifier); uid != "" || err != nil {
			return
		}
	}
	return
}

func (this *UIDFinders) Add(finder ...UIDFinder) {
	if this == nil {
		*this = finder
	} else {
		*this = append(*this, finder...)
	}
}

func (this UIDFinders) Append(finder ...UIDFinder) UIDFinders {
	this = append(this, finder...)
	return this
}
