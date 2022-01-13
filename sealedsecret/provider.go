package sealedsecret

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Provider -
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{},
		ResourcesMap: map[string]*schema.Resource{
			"sealedsecret_raw_secret":  resourceRawSecret(),
			"sealedsecret_raw_secrets": resourceRawSecrets(),
		},
		DataSourcesMap: map[string]*schema.Resource{},
	}
}
