package sealedsecret

import (
	"bytes"
	"context"
	"terraform-provider-sealedsecret/sealedsecret/internal"

	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceRawSecret() *schema.Resource {
	return &schema.Resource{
		Description: "" +
			"`sealedsecret_raw_secret` creates a sealed secret from `value` input. The encrypted " +
			"value is available as `encrypted_value`. This is not marked as sensitive as it is " +
			"encrypted and can therefore safely be passed around.",

		CreateContext: resourceRawSecretCreate,
		ReadContext:   schema.NoopContext,
		Delete:        schema.RemoveFromState,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the sealed secret",
			},
			"namespace": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "If present, the namespace scope for this request",
			},
			"scope": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Default:     "strict",
				Description: "Set the scope of the sealed secret: strict, namespace-wide, cluster-wide (defaults to strict).",
				ValidateFunc: validation.StringInSlice([]string{
					"strict", "namespace-wide", "cluster-wide",
				}, false),
			},
			"certificate": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Public certificate to use for sealing secret.",
			},
			"value": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				ForceNew:    true,
				Description: "Secret value to seal.",
			},
			"encrypted_value": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Encrypted secret value",
			},
		},
	}
}

func resourceRawSecretCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var (
		sealingScope ssv1alpha1.SealingScope
		err          error
	)

	name := d.Get("name").(string)
	namespace := d.Get("namespace").(string)
	value := d.Get("value").(string)
	cert := d.Get("certificate").(string)
	scope := d.Get("scope").(string)

	err = sealingScope.Set(scope)
	if err != nil {
		return diag.FromErr(err)
	}

	pubKey, err := internal.ParseKey([]byte(cert))
	if err != nil {
		return diag.FromErr(err)
	}

	buf := new(bytes.Buffer)

	err = internal.EncryptSecretItem(buf, name, namespace, []byte(value), sealingScope, pubKey)
	if err != nil {
		return diag.FromErr(err)
	}

	id := string(ssv1alpha1.EncryptionLabel(namespace, name, sealingScope))

	d.SetId(id)
	d.Set("encrypted_value", buf.String())

	return nil
}
