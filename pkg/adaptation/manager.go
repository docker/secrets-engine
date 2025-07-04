package adaptation

type registry interface {
	Add(plugin ...*runtime)
	GetAll() []*runtime
}
