package specs

import "embed"

//go:embed providers/*.yaml
var ProviderFS embed.FS
