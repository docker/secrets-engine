module github.com/docker/secrets-engine/store

go 1.24.3

replace github.com/docker/secrets-engine => ../

require (
	github.com/docker/secrets-engine v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.10.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
