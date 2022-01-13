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

func resourceRawSecrets() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceRawSecretsCreate,
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
			"values": {
				Type:        schema.TypeMap,
				Required:    true,
				Sensitive:   true,
				ForceNew:    true,
				Description: "Map of secret values to seal.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"encrypted_values": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Encrypted secret values",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func resourceRawSecretsCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var (
		sealingScope ssv1alpha1.SealingScope
		err          error
	)

	encryptedValues := map[string]string{}

	name := d.Get("name").(string)
	namespace := d.Get("namespace").(string)
	values := d.Get("values").(map[string]interface{})
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

	for k, v := range values {
		buf := new(bytes.Buffer)

		err = internal.EncryptSecretItem(buf, name, namespace, []byte(v.(string)), sealingScope, pubKey)
		if err != nil {
			return diag.FromErr(err)
		}

		encryptedValues[k] = buf.String()
	}

	id := string(ssv1alpha1.EncryptionLabel(namespace, name, sealingScope))

	d.SetId(id)
	d.Set("encrypted_values", encryptedValues)

	return nil
}
