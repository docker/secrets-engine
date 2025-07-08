package adaptation

type removeFunc func()

type registry interface {
	Register(plugin runtime) (removeFunc, error)
	GetAll() []runtime
}
