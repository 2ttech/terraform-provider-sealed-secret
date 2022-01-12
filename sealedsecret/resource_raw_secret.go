package sealedsecret

import (
	"bytes"
	"context"
	"terraform-provider-sealedsecret/sealedsecret/internal"
	"time"

	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRawSecret() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceRawSecretCreate,
		ReadContext:   resourceRawSecretRead,
		UpdateContext: resourceRawSecretUpdate,
		DeleteContext: resourceRawSecretDelete,

		Schema: map[string]*schema.Schema{
			"last_modified": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the sealed secret",
			},
			"namespace": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "If present, the namespace scope for this request",
			},
			"scope": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "strict",
				Description:  "Set the scope of the sealed secret: strict, namespace-wide, cluster-wide (defaults to strict).",
				ExactlyOneOf: []string{"strict", "namespace-wide", "cluster-wide"},
			},
			"certificate": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Public certificate to use for sealing secret.",
			},
			"value": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Secret value to seal.",
			},
			"encrypted_value": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Encrypted secret value",
			},
		},

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
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

	id := ssv1alpha1.EncryptionLabel(namespace, name, sealingScope)

	d.SetId(string(id))
	d.Set("encrypted_value", buf.String())
	d.Set("last_modified", time.Now().Format(time.RFC850))

	return resourceRawSecretRead(ctx, d, m)
}

func resourceRawSecretRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return nil
}

func resourceRawSecretUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return resourceRawSecretRead(ctx, d, m)
}

func resourceRawSecretDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// d.SetId("") is automatically called assuming delete returns no errors, but
	// it is added here for explicitness.
	d.SetId("")

	return nil
}
