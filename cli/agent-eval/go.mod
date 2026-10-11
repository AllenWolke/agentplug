module github.com/lexagent/agent-eval

go 1.25.0

require (
	github.com/lexagent/agent-evaluation v0.0.0
	github.com/lexagent/agent-platform-sdk-go v0.0.0
	golang.org/x/term v0.34.0
)

require golang.org/x/sys v0.47.0 // indirect

replace github.com/lexagent/agent-evaluation => ../../contracts/agent-evaluation/go

replace github.com/lexagent/agent-platform-sdk-go => ../../sdk/go
