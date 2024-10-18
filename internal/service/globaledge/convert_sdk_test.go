package globaledge

import (
	"context"
	"fmt"
	"testing"

	globaledge "github.com/terraform-providers/terraform-provider-ncloud/internal/service/globaledge/sdk"
	utils "github.com/terraform-providers/terraform-provider-ncloud/internal/service/globaledge/util"
)

func TestConvert(t *testing.T) {
	reqParams := &globaledge.EdgeConfig{
		AccessControl: &globaledge.AccessControl{
			GeoPolicies:     []string{"new", "2", "3"},
			IpPolicies:      []string{"1", "2", "3"},
			RefererPolicies: []string{"1", "2", "3"},
			Type_:           "test",
		},
	}

	vv := Converter(context.Background(), reqParams)

	fmt.Println(PrettyPrint(vv))
}

func TestGen(t *testing.T) {
	sdkStruct := &globaledge.EdgeConfig{}
	tfStruct := &GlobalEdgeModel{}
	utils.GenerateConverter_core(sdkStruct, tfStruct)
}
