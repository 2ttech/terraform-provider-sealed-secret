package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
	"github.com/kita99/terraform-provider-kubeseal/kubeseal"
)

func main() {
	opts := &plugin.ServeOpts{ProviderFunc: kubeseal.Provider}
	plugin.Serve(opts)

	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: func() *schema.Provider {
			return hashicups.Provider()
		},
	})
}
