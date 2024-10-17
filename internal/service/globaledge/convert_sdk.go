package globaledge

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	globaledge "github.com/terraform-providers/terraform-provider-ncloud/internal/service/globaledge/sdk"
)

func Converter(ctx context.Context, input *globaledge.EdgeConfig) *GlobalEdgeModel {
	var target GlobalEdgeModel

	k := AccessControlValue{
		GeoPolicies:       diagOff(types.ListValueFrom, ctx, types.ListType{ElemType: types.StringType}.ElementType(), input.AccessControl.GeoPolicies),
		IpPolicies:        diagOff(types.ListValueFrom, ctx, types.ListType{ElemType: types.StringType}.ElementType(), input.AccessControl.IpPolicies),
		RefererPolicies:   diagOff(types.ListValueFrom, ctx, types.ListType{ElemType: types.StringType}.ElementType(), input.AccessControl.RefererPolicies),
		AccessControlType: types.StringValue(input.AccessControl.Type_),
	}

	target.AccessControl = k

	target.CachingConfig = CachingConfigValue{
		BypassQueryString: diagOff(types.ObjectValueFrom, ctx, types.ObjectType{AttrTypes: map[string]attr.Type{
			"enabled":      types.BoolType,
			"queryStrings": types.ListType{ElemType: types.StringType},
		}}.AttributeTypes(), input.CachingConfig.BypassQueryString),
		CacheKeyHostname: types.StringValue(input.CachingConfig.CacheKeyHostname),
		CacheKeyIgnoreQueryString: diagOff(types.ObjectValueFrom, ctx, types.ObjectType{AttrTypes: map[string]attr.Type{
			"queryStrings": types.ListType{ElemType: types.StringType},
			"type":         types.StringType,
		}}.AttributeTypes(), input.CachingConfig.CacheKeyIgnoreQueryString),
	}

	target.HeaderPolicies = diagOff(types.ListValueFrom, ctx, types.ListType{ElemType: types.ObjectType{AttrTypes: map[string]attr.Type{
		"header": types.ObjectType{AttrTypes: map[string]attr.Type{
			"name":  types.StringType,
			"type":  types.StringType,
			"value": types.StringType,
		}},
		"ruleName": types.StringType,
		"type":     types.StringType,
	}}}.ElementType(), input.HeaderPolicies)

	return &target
}

func PrettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

func diagOff[V, T interface{}](input func(ctx context.Context, elementType T, elements any) (V, diag.Diagnostics), ctx context.Context, elementType T, elements any) V {
	var emptyReturn V

	v, diags := input(ctx, elementType, elements)

	if diags.HasError() {
		fmt.Println("Error")
		return emptyReturn
	}

	fmt.Println("========================", v, reflect.TypeOf(v))
	return v
}
