package objectstorage

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	awsTypes "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/terraform-providers/terraform-provider-ncloud/internal/common"
	"github.com/terraform-providers/terraform-provider-ncloud/internal/conn"
	"github.com/terraform-providers/terraform-provider-ncloud/internal/framework"
)

var (
	_ resource.Resource                = &bucketACLResource{}
	_ resource.ResourceWithConfigure   = &bucketACLResource{}
	_ resource.ResourceWithImportState = &bucketACLResource{}
)

func NewBucketACLResource() resource.Resource {
	return &bucketACLResource{}
}

type bucketACLResource struct {
	config *conn.ProviderConfig
}

func (b *bucketACLResource) Schema(_ context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": framework.IDAttribute(),
			"bucket_id": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.All(
						stringvalidator.RegexMatches(regexp.MustCompile(`^https:\/\/.*\.object\.ncloudstorage\.com\/[^\/]+\.*$`), "Requires pattern with link of target bucket"),
					),
				},
				Description: "Target bucket id",
			},
			"rule": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						string(awsTypes.BucketCannedACLPrivate),
						string(awsTypes.BucketCannedACLPublicRead),
						string(awsTypes.BucketCannedACLPublicReadWrite),
						string(awsTypes.BucketCannedACLAuthenticatedRead),
					),
				},
			},
			"grants": schema.StringAttribute{
				Computed: true,
			},
			"owner": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}

func (b *bucketACLResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan bucketACLResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	bucketName := BucketIDParser(plan.BucketID.String())

	reqParams := &s3.PutBucketAclInput{
		Bucket: aws.String(bucketName),
		ACL:    plan.Rule,
	}

	tflog.Info(ctx, "PutBucketACL reqParams="+common.MarshalUncheckedString(reqParams))

	response, err := b.config.Client.ObjectStorage.PutBucketAcl(ctx, reqParams)
	if err != nil {
		resp.Diagnostics.AddError("CREATING ERROR", err.Error())
	}

	tflog.Info(ctx, "PutObjectACL response="+common.MarshalUncheckedString(response))

	if err := waitBucketACLApplied(ctx, b.config, bucketName); err != nil {
		resp.Diagnostics.AddError("CREATING ERROR", err.Error())
		return
	}

	output, err := b.config.Client.ObjectStorage.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		resp.Diagnostics.AddError("READING ERROR", err.Error())
		return
	}

	plan.refreshFromOutput(output)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (b *bucketACLResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
}

func (b *bucketACLResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var plan bucketACLResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	bucketName := BucketIDParser(plan.BucketID.String())

	output, err := b.config.Client.ObjectStorage.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		resp.Diagnostics.AddError("READING ERROR", err.Error())
		return
	}

	plan.refreshFromOutput(output)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (b *bucketACLResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
}

func (b *bucketACLResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_objectstorage_bucket_acl"
}

func (b *bucketACLResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(*conn.ProviderConfig)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Exprected *ProviderConfig, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	b.config = config
}

func (b *bucketACLResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func waitBucketACLApplied(ctx context.Context, config *conn.ProviderConfig, bucketName string) error {
	stateConf := &retry.StateChangeConf{
		Pending: []string{"applying"},
		Target:  []string{"applied"},
		Refresh: func() (interface{}, string, error) {
			output, err := config.Client.ObjectStorage.GetBucketAcl(ctx, &s3.GetBucketAclInput{
				Bucket: aws.String(bucketName),
			})

			if output != nil {
				return output, "applied", nil
			}

			if err != nil {
				return output, "applying", nil
			}

			return output, "applying", nil
		},
		Timeout:    conn.DefaultTimeout,
		Delay:      5 * time.Second,
		MinTimeout: 3 * time.Second,
	}

	if _, err := stateConf.WaitForStateContext(ctx); err != nil {
		return fmt.Errorf("error waiting for bucket acl (%s) to be applied: %s", bucketName, err)
	}
	return nil
}

type bucketACLResourceModel struct {
	ID       types.String             `tfsdk:"id"`
	BucketID types.String             `tfsdk:"bucket_id"`
	Rule     awsTypes.BucketCannedACL `tfsdk:"rule"`
	Grants   types.String             `tfsdk:"grants"`
	Owner    types.String             `tfsdk:"owner"`
}

func (b *bucketACLResourceModel) refreshFromOutput(output *s3.GetBucketAclOutput) {
	if output == nil {
		return
	}

	if len(output.Grants) != 0 {
		b.Grants = types.StringPointerValue(output.Grants[0].Grantee.DisplayName)
	} else {
		b.Grants = types.StringValue("")
	}
	b.ID = types.StringValue(fmt.Sprintf("bucket_acl_%s", b.BucketID))
	b.Owner = types.StringValue(*output.Owner.ID)
}

func BucketIDParser(id string) string {
	if id == "" {
		return ""
	}

	id = strings.TrimPrefix(id, "\"")
	id = strings.TrimSuffix(id, "\"")

	parts := strings.Split(id, "/")
	if len(parts) < 4 {
		return ""
	}

	return parts[3]
}