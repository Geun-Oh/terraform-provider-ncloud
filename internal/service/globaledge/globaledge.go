package globaledge

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
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
		AccessControl: &globaledge.AccessControl{
			GeoPolicies:     []string{"1", "2", "3"},
			IpPolicies:      []string{"1", "2", "3"},
			RefererPolicies: []string{"1", "2", "3"},
			Type_:           "test",
		},
	}

	_, httpRes, err := service.CdnEdgePost(ctx, reqParams)
	if err != nil {
		return
	}

	if httpRes.StatusCode <= 300 {
		return
	}

	convertedParams := Converter(ctx, &reqParams)
	resp.Diagnostics.Append(req.Plan.Set(ctx, &convertedParams)...)
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
