module github.com/copsec

go 1.25.0

replace (
	github.com/copsec/collector => ./collector
	github.com/copsec/controller => ./controller
)

require (
	github.com/copsec/controller v0.0.0-00010101000000-000000000000
	gopkg.in/yaml.v3 v3.0.1
)
