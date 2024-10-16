package globaledge

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/terraform-providers/terraform-provider-ncloud/internal/conn"
	globaledge "github.com/terraform-providers/terraform-provider-ncloud/internal/service/globaledge/sdk"
)

var (
	_ resource.Resource                = &globaledgeResource{}
	_ resource.ResourceWithConfigure   = &globaledgeResource{}
	_ resource.ResourceWithImportState = &globaledgeResource{}
)

func NewGlobalEdgeResource() resource.Resource {
	return &globaledgeResource{}
}

type globaledgeResource struct {
	config *conn.ProviderConfig
}

func (g *globaledgeResource) Configure(context.Context, resource.ConfigureRequest, *resource.ConfigureResponse) {
	panic("unimplemented")
}

func (g *globaledgeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan GlobalEdgeModel
	var service globaledge.V1ApiService

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	reqParams := globaledge.EdgeConfig{
		AccessControl: &globaledge.AccessControl{},
	}

	_, httpRes, err := service.CdnEdgePost(ctx, reqParams)
	if err != nil {
		return
	}

	if httpRes.StatusCode <= 300 {
		return
	}

	plan.refreshFromOutput(ctx, &plan)
}

func (g *globaledgeResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
	panic("unimplemented")
}

func (g *globaledgeResource) ImportState(context.Context, resource.ImportStateRequest, *resource.ImportStateResponse) {
	panic("unimplemented")
}

func (g *globaledgeResource) Metadata(context.Context, resource.MetadataRequest, *resource.MetadataResponse) {
	panic("unimplemented")
}

func (g *globaledgeResource) Read(context.Context, resource.ReadRequest, *resource.ReadResponse) {
	panic("unimplemented")
}

func (g *globaledgeResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = GlobalEdgeResourceSchema(ctx)
}

func (g *globaledgeResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
	panic("unimplemented")
}

func (r *GlobalEdgeModel) refreshFromOutput(ctx context.Context, output *GlobalEdgeModel) {
	r = output
}

func convertSDK2Terraform(ctx context.Context, input *globaledge.EdgeConfig) GlobalEdgeModel {
	var target GlobalEdgeModel
	var c CachingConfigType

	geoPolicesValue, diags := types.ListValue(types.ListType{}, convertStringSliceToAttrValueSlice(input.AccessControl.GeoPolicies))
	if diags.HasError() {
		return GlobalEdgeModel{}
	}

	ipPoliciesValue, diags := types.ListValue(types.ListType{}, convertStringSliceToAttrValueSlice(input.AccessControl.IpPolicies))
	if diags.HasError() {
		return GlobalEdgeModel{}
	}

	refererPolicies, diags := types.ListValue(types.ListType{}, convertStringSliceToAttrValueSlice(input.AccessControl.RefererPolicies))
	if diags.HasError() {
		return GlobalEdgeModel{}
	}

	accessControlType := types.StringValue(input.AccessControl.Type_)

	accessControlMap := &AccessControlValue{
		GeoPolicies:       geoPolicesValue,
		IpPolicies:        ipPoliciesValue,
		RefererPolicies:   refererPolicies,
		AccessControlType: accessControlType,
	}

	// cdnCachingConfigValue, diags := c.ValueFromObject(ctx, types.ObjectValue(map[string]attr.Type{
	// 	"bypass_query_string": types.ObjectType{AttrTypes: map[string]attr.Type{
	// 		"enabled": types.BoolType,
	// 		"query_strings": types.ListType{
	// 			ElemType: types.StringType,
	// 		},
	// 	}},
	// 	"cache_key_hostname": types.StringType,
	// 	"cache_key_ignore_query_string": types.ObjectType{AttrTypes: map[string]attr.Type{
	// 		"query_strings": types.ListType{
	// 			ElemType: types.StringType,
	// 		},
	// 		"type": types.StringType,
	// 	}},
	// }, map[string]attr.Value{
	// 	"bypass_query_string": convertStringSliceToAttrValueSlice(input.CachingConfig.BypassQueryString),
	// 	"cache_key_host_name": types.StringType,
	// }))

	target.AccessControl = *accessControlMap

	if diags.HasError() {
		return GlobalEdgeModel{}
	}

	return target
}

func convertListValueToStringSlice(listValue basetypes.ListValue) []string {
	arr := make([]string, len(listValue.Elements()))
	for i, v := range listValue.Elements() {
		arr[i] = v.String()
	}

	return arr
}

func convertAttrValueToBool(val attr.Value) bool {
	if val.String() == "true" {
		return true
	}
	return false
}

func convertStringSliceToAttrValueSlice(strings []string) []attr.Value {
	attrValues := make([]attr.Value, len(strings))
	for i, s := range strings {
		attrValues[i] = types.StringValue(s)
	}

	return attrValues
}
