package globaledge

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

func GlobalEdgeResourceSchema(ctx context.Context) schema.Schema {
	return schema.Schema{
		Attributes: map[string]schema.Attribute{
			"access_control": schema.SingleNestedAttribute{
				Attributes: map[string]schema.Attribute{
					"geo_policies": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
					},
					"ip_policies": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
					},
					"referer_policies": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
					},
					"type": schema.StringAttribute{
						Optional: true,
						Computed: true,
						Validators: []validator.String{
							stringvalidator.OneOf(
								"WHITELIST",
								"BLACKLIST",
							),
						},
					},
				},
				CustomType: AccessControlType{
					ObjectType: types.ObjectType{
						AttrTypes: AccessControlValue{}.AttributeTypes(ctx),
					},
				},
				Optional: true,
				Computed: true,
			},
			"caching_config": schema.SingleNestedAttribute{
				Attributes: map[string]schema.Attribute{
					"bypass_query_string": schema.SingleNestedAttribute{
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Optional: true,
								Computed: true,
							},
							"query_strings": schema.ListAttribute{
								ElementType: types.StringType,
								Optional:    true,
								Computed:    true,
							},
						},
						CustomType: BypassQueryStringType{
							ObjectType: types.ObjectType{
								AttrTypes: BypassQueryStringValue{}.AttributeTypes(ctx),
							},
						},
						Required: true,
					},
					"cache_key_hostname": schema.StringAttribute{
						Required: true,
						Validators: []validator.String{
							stringvalidator.OneOf(
								"INCOMING_HOST_HEADER",
								"ORIGIN_HOSTNAME",
							),
						},
					},
					"cache_key_ignore_query_string": schema.SingleNestedAttribute{
						Attributes: map[string]schema.Attribute{
							"query_strings": schema.ListAttribute{
								ElementType: types.StringType,
								Optional:    true,
								Computed:    true,
							},
							"type": schema.StringAttribute{
								Optional: true,
								Computed: true,
								Validators: []validator.String{
									stringvalidator.OneOf(
										"ALL_IGNORED",
										"ALL_ALLOWED",
										"ALLOW_SPECIFIC_STRING",
									),
								},
							},
						},
						CustomType: CacheKeyIgnoreQueryStringType{
							ObjectType: types.ObjectType{
								AttrTypes: CacheKeyIgnoreQueryStringValue{}.AttributeTypes(ctx),
							},
						},
						Required: true,
					},
					"caching_rules": schema.ListNestedAttribute{
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"access_deny": schema.BoolAttribute{
									Optional: true,
									Computed: true,
								},
								"browser_cache": schema.SingleNestedAttribute{
									Attributes: map[string]schema.Attribute{
										"age": schema.Int64Attribute{
											Optional: true,
											Computed: true,
										},
										"age_type": schema.StringAttribute{
											Optional: true,
											Computed: true,
											Validators: []validator.String{
												stringvalidator.OneOf(
													"SECONDS",
													"MINUTES",
													"HOURS",
													"DAYS",
												),
											},
										},
										"enabled": schema.BoolAttribute{
											Optional: true,
											Computed: true,
										},
										"type": schema.StringAttribute{
											Optional: true,
											Computed: true,
											Validators: []validator.String{
												stringvalidator.OneOf(
													"ALLOW_CACHE",
													"NO_CACHE",
												),
											},
										},
									},
									CustomType: BrowserCacheType{
										ObjectType: types.ObjectType{
											AttrTypes: BrowserCacheValue{}.AttributeTypes(ctx),
										},
									},
									Optional: true,
									Computed: true,
								},
								"cache_key_query_parameter": schema.SingleNestedAttribute{
									Attributes: map[string]schema.Attribute{
										"enabled": schema.BoolAttribute{
											Optional: true,
											Computed: true,
										},
										"query_parameters": schema.ListAttribute{
											ElementType: types.StringType,
											Optional:    true,
											Computed:    true,
										},
										"type": schema.StringAttribute{
											Optional: true,
											Computed: true,
											Validators: []validator.String{
												stringvalidator.OneOf(
													"ALL_IGNORED",
													"ALL_ALLOWED",
													"ALLOW_SPECIFIC_STRING",
													"IGNORE_SPECIFIC_STRING",
												),
											},
										},
									},
									CustomType: CacheKeyQueryParameterType{
										ObjectType: types.ObjectType{
											AttrTypes: CacheKeyQueryParameterValue{}.AttributeTypes(ctx),
										},
									},
									Optional: true,
									Computed: true,
								},
								"cache_revalidate_config": schema.SingleNestedAttribute{
									Attributes: map[string]schema.Attribute{
										"age": schema.Int64Attribute{
											Optional: true,
											Computed: true,
										},
										"age_type": schema.StringAttribute{
											Optional: true,
											Computed: true,
											Validators: []validator.String{
												stringvalidator.OneOf(
													"SECONDS",
													"MINUTES",
													"HOURS",
													"DAYS",
												),
											},
										},
										"type": schema.StringAttribute{
											Optional: true,
											Computed: true,
											Validators: []validator.String{
												stringvalidator.OneOf(
													"IF_POSSIBLE",
													"ALWAYS",
												),
											},
										},
									},
									CustomType: CacheRevalidateConfigType{
										ObjectType: types.ObjectType{
											AttrTypes: CacheRevalidateConfigValue{}.AttributeTypes(ctx),
										},
									},
									Optional: true,
									Computed: true,
								},
								"rule_based_routing_config": schema.SingleNestedAttribute{
									Attributes: map[string]schema.Attribute{
										"enabled": schema.BoolAttribute{
											Optional: true,
											Computed: true,
										},
										"original_copy_location": schema.SingleNestedAttribute{
											Attributes: map[string]schema.Attribute{
												"bucket_name": schema.StringAttribute{
													Optional: true,
													Computed: true,
												},
												"custom_location": schema.StringAttribute{
													Optional: true,
													Computed: true,
												},
												"region": schema.StringAttribute{
													Optional: true,
													Computed: true,
													Validators: []validator.String{
														stringvalidator.OneOf(
															"KR",
															"HK",
															"SGN",
															"JPN",
															"USWN",
															"DEN",
															"FKR",
														),
													},
												},
												"type": schema.StringAttribute{
													Optional: true,
													Computed: true,
													Validators: []validator.String{
														stringvalidator.OneOf(
															"OBJECT_STORAGE",
															"LOAD_BALANCER",
															"API_GATEWAY",
															"CUSTOM",
															"NONE",
														),
													},
												},
											},
											CustomType: OriginalCopyLocationType{
												ObjectType: types.ObjectType{
													AttrTypes: OriginalCopyLocationValue{}.AttributeTypes(ctx),
												},
											},
											Optional: true,
											Computed: true,
										},
									},
									CustomType: RuleBasedRoutingConfigType{
										ObjectType: types.ObjectType{
											AttrTypes: RuleBasedRoutingConfigValue{}.AttributeTypes(ctx),
										},
									},
									Optional: true,
									Computed: true,
								},
								"rule_conditions": schema.ListAttribute{
									ElementType: types.StringType,
									Optional:    true,
									Computed:    true,
								},
								"rule_definition_type": schema.StringAttribute{
									Optional: true,
									Computed: true,
									Validators: []validator.String{
										stringvalidator.OneOf(
											"CACHING",
											"BYPASS_CACHE",
											"ORIGIN_CACHE_CONTROL_HEADER",
										),
									},
								},
								"rule_name": schema.StringAttribute{
									Optional: true,
									Computed: true,
								},
								"rule_type": schema.StringAttribute{
									Optional: true,
									Computed: true,
									Validators: []validator.String{
										stringvalidator.OneOf(
											"DIRECTORY",
											"FILE_EXTENSION",
											"ADVANCED",
										),
									},
								},
								"url_redirect": schema.SingleNestedAttribute{
									Attributes: map[string]schema.Attribute{
										"destination_hostname": schema.StringAttribute{
											Optional: true,
											Computed: true,
										},
										"destination_path": schema.StringAttribute{
											Optional: true,
											Computed: true,
										},
										"destination_protocol": schema.StringAttribute{
											Optional: true,
											Computed: true,
											Validators: []validator.String{
												stringvalidator.OneOf(
													"HTTP",
													"HTTPS",
												),
											},
										},
										"enabled": schema.BoolAttribute{
											Optional: true,
											Computed: true,
										},
										"response_code": schema.StringAttribute{
											Optional: true,
											Computed: true,
											Validators: []validator.String{
												stringvalidator.OneOf(
													"MOVED_PERMANENTLY_301",
													"FOUND_302",
												),
											},
										},
									},
									CustomType: UrlRedirectType{
										ObjectType: types.ObjectType{
											AttrTypes: UrlRedirectValue{}.AttributeTypes(ctx),
										},
									},
									Optional: true,
									Computed: true,
								},
								"url_rewrite": schema.SingleNestedAttribute{
									Attributes: map[string]schema.Attribute{
										"enabled": schema.BoolAttribute{
											Optional: true,
											Computed: true,
										},
										"rewrite_target": schema.StringAttribute{
											Optional: true,
											Computed: true,
										},
									},
									CustomType: UrlRewriteType{
										ObjectType: types.ObjectType{
											AttrTypes: UrlRewriteValue{}.AttributeTypes(ctx),
										},
									},
									Optional: true,
									Computed: true,
								},
							},
							CustomType: CachingRulesType{
								ObjectType: types.ObjectType{
									AttrTypes: CachingRulesValue{}.AttributeTypes(ctx),
								},
							},
						},
						Optional: true,
						Computed: true,
					},
					"default_caching": schema.SingleNestedAttribute{
						Attributes: map[string]schema.Attribute{
							"cache_revalidate_config": schema.SingleNestedAttribute{
								Attributes: map[string]schema.Attribute{
									"age": schema.Int64Attribute{
										Optional: true,
										Computed: true,
									},
									"age_type": schema.StringAttribute{
										Optional: true,
										Computed: true,
										Validators: []validator.String{
											stringvalidator.OneOf(
												"SECONDS",
												"MINUTES",
												"HOURS",
												"DAYS",
											),
										},
									},
									"type": schema.StringAttribute{
										Optional: true,
										Computed: true,
										Validators: []validator.String{
											stringvalidator.OneOf(
												"IF_POSSIBLE",
												"ALWAYS",
											),
										},
									},
								},
								CustomType: CacheRevalidateConfigType{
									ObjectType: types.ObjectType{
										AttrTypes: CacheRevalidateConfigValue{}.AttributeTypes(ctx),
									},
								},
								Optional: true,
								Computed: true,
							},
							"enabled": schema.BoolAttribute{
								Optional: true,
								Computed: true,
							},
							"rule_definition_type": schema.StringAttribute{
								Optional: true,
								Computed: true,
								Validators: []validator.String{
									stringvalidator.OneOf(
										"CACHING",
										"BYPASS_CACHE",
										"ORIGIN_CACHE_CONTROL_HEADER",
									),
								},
							},
						},
						CustomType: DefaultCachingType{
							ObjectType: types.ObjectType{
								AttrTypes: DefaultCachingValue{}.AttributeTypes(ctx),
							},
						},
						Optional: true,
						Computed: true,
					},
					"edge_auth": schema.SingleNestedAttribute{
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Optional: true,
								Computed: true,
							},
							"token_key": schema.StringAttribute{
								Optional: true,
								Computed: true,
							},
							"token_name": schema.StringAttribute{
								Optional: true,
								Computed: true,
							},
							"type": schema.StringAttribute{
								Optional: true,
								Computed: true,
								Validators: []validator.String{
									stringvalidator.OneOf(
										"SIGNED_URL",
										"JWT",
										"MEDIA_VAULT",
									),
								},
							},
						},
						CustomType: EdgeAuthType{
							ObjectType: types.ObjectType{
								AttrTypes: EdgeAuthValue{}.AttributeTypes(ctx),
							},
						},
						Required: true,
					},
					"negative_ttl": schema.BoolAttribute{
						Optional: true,
						Computed: true,
					},
					"remove_vary_header": schema.BoolAttribute{
						Optional: true,
						Computed: true,
					},
				},
				CustomType: CachingConfigType{
					ObjectType: types.ObjectType{
						AttrTypes: CachingConfigValue{}.AttributeTypes(ctx),
					},
				},
				Required: true,
			},
			"distribution_config": schema.SingleNestedAttribute{
				Attributes: map[string]schema.Attribute{
					"edge_logging": schema.SingleNestedAttribute{
						Attributes: map[string]schema.Attribute{
							"bucket_prefix": schema.StringAttribute{
								Optional: true,
								Computed: true,
							},
							"enabled": schema.BoolAttribute{
								Optional: true,
								Computed: true,
							},
							"object_storage": schema.SingleNestedAttribute{
								Attributes: map[string]schema.Attribute{
									"bucket_name": schema.StringAttribute{
										Optional: true,
										Computed: true,
									},
									"region": schema.StringAttribute{
										Optional: true,
										Computed: true,
										Validators: []validator.String{
											stringvalidator.OneOf(
												"KR",
												"HK",
												"SGN",
												"JPN",
												"USWN",
												"DEN",
												"FKR",
											),
										},
									},
								},
								CustomType: ObjectStorageType{
									ObjectType: types.ObjectType{
										AttrTypes: ObjectStorageValue{}.AttributeTypes(ctx),
									},
								},
								Optional: true,
								Computed: true,
							},
						},
						CustomType: EdgeLoggingType{
							ObjectType: types.ObjectType{
								AttrTypes: EdgeLoggingValue{}.AttributeTypes(ctx),
							},
						},
						Required: true,
					},
					"protocol_type": schema.StringAttribute{
						Required: true,
						Validators: []validator.String{
							stringvalidator.OneOf(
								"HTTP",
								"HTTPS",
								"ALL",
							),
						},
					},
					"region_type": schema.StringAttribute{
						Required: true,
						Validators: []validator.String{
							stringvalidator.OneOf(
								"KOREA",
								"JAPAN",
								"GLOBAL",
							),
						},
					},
					"service_domain": schema.SingleNestedAttribute{
						Attributes: map[string]schema.Attribute{
							"certificate": schema.SingleNestedAttribute{
								Attributes: map[string]schema.Attribute{
									"domain": schema.StringAttribute{
										Optional: true,
										Computed: true,
									},
									"expiry_date": schema.StringAttribute{
										Optional: true,
										Computed: true,
									},
									"id": schema.Int64Attribute{
										Optional: true,
										Computed: true,
									},
								},
								CustomType: CertificateType{
									ObjectType: types.ObjectType{
										AttrTypes: CertificateValue{}.AttributeTypes(ctx),
									},
								},
								Optional: true,
								Computed: true,
							},
							"domain_name": schema.StringAttribute{
								Optional: true,
								Computed: true,
							},
							"domain_type": schema.StringAttribute{
								Optional: true,
								Computed: true,
								Validators: []validator.String{
									stringvalidator.OneOf(
										"NCP_DOMAIN_AUTO",
										"NCP_DOMAIN_CUSTOM",
										"CUSTOM_DOMAIN",
									),
								},
							},
						},
						CustomType: ServiceDomainType{
							ObjectType: types.ObjectType{
								AttrTypes: ServiceDomainValue{}.AttributeTypes(ctx),
							},
						},
						Required: true,
					},
				},
				CustomType: DistributionConfigType{
					ObjectType: types.ObjectType{
						AttrTypes: DistributionConfigValue{}.AttributeTypes(ctx),
					},
				},
				Required: true,
			},
			"edge_id": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Description:         "edgeId",
				MarkdownDescription: "edgeId",
			},
			"edge_name": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(3, 35),
					stringvalidator.RegexMatches(regexp.MustCompile("[a-zA-Z0-9_\\-]+"), ""),
				},
			},
			"header_policies": schema.ListNestedAttribute{
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"header": schema.SingleNestedAttribute{
							Attributes: map[string]schema.Attribute{
								"name": schema.StringAttribute{
									Optional: true,
									Computed: true,
								},
								"type": schema.StringAttribute{
									Optional: true,
									Computed: true,
									Validators: []validator.String{
										stringvalidator.OneOf(
											"ADD",
											"MODIFY",
											"REMOVE",
										),
									},
								},
								"value": schema.StringAttribute{
									Optional: true,
									Computed: true,
								},
							},
							CustomType: HeaderType{
								ObjectType: types.ObjectType{
									AttrTypes: HeaderValue{}.AttributeTypes(ctx),
								},
							},
							Optional: true,
							Computed: true,
						},
						"rule_name": schema.StringAttribute{
							Optional: true,
							Computed: true,
						},
						"type": schema.StringAttribute{
							Optional: true,
							Computed: true,
							Validators: []validator.String{
								stringvalidator.OneOf(
									"ORIGIN_REQUEST",
									"CLIENT_RESPONSE",
								),
							},
						},
					},
					CustomType: HeaderPoliciesType{
						ObjectType: types.ObjectType{
							AttrTypes: HeaderPoliciesValue{}.AttributeTypes(ctx),
						},
					},
				},
				Optional: true,
				Computed: true,
			},
			"managed_rule": schema.SingleNestedAttribute{
				Attributes: map[string]schema.Attribute{
					"cors": schema.BoolAttribute{
						Optional: true,
						Computed: true,
					},
					"hsts": schema.BoolAttribute{
						Optional: true,
						Computed: true,
					},
					"http2": schema.BoolAttribute{
						Optional: true,
						Computed: true,
					},
					"true_client_ip_header": schema.BoolAttribute{
						Optional: true,
						Computed: true,
					},
				},
				CustomType: ManagedRuleType{
					ObjectType: types.ObjectType{
						AttrTypes: ManagedRuleValue{}.AttributeTypes(ctx),
					},
				},
				Required: true,
			},
			"optimization_config": schema.SingleNestedAttribute{
				Attributes: map[string]schema.Attribute{
					"http_compression": schema.BoolAttribute{
						Optional: true,
						Computed: true,
					},
					"large_file_optimization": schema.BoolAttribute{
						Optional: true,
						Computed: true,
					},
				},
				CustomType: OptimizationConfigType{
					ObjectType: types.ObjectType{
						AttrTypes: OptimizationConfigValue{}.AttributeTypes(ctx),
					},
				},
				Required: true,
			},
			"original_copy_config": schema.SingleNestedAttribute{
				Attributes: map[string]schema.Attribute{
					"forward_host_header": schema.SingleNestedAttribute{
						Attributes: map[string]schema.Attribute{
							"custom_host_header": schema.StringAttribute{
								Optional: true,
								Computed: true,
							},
							"type": schema.StringAttribute{
								Optional: true,
								Computed: true,
								Validators: []validator.String{
									stringvalidator.OneOf(
										"INCOMING_HOST_HEADER",
										"ORIGIN_HOSTNAME",
										"CUSTOM",
									),
								},
							},
						},
						CustomType: ForwardHostHeaderType{
							ObjectType: types.ObjectType{
								AttrTypes: ForwardHostHeaderValue{}.AttributeTypes(ctx),
							},
						},
						Required: true,
					},
					"origin_failover_config": schema.SingleNestedAttribute{
						Attributes: map[string]schema.Attribute{
							"original_copy_location": schema.SingleNestedAttribute{
								Attributes: map[string]schema.Attribute{
									"bucket_name": schema.StringAttribute{
										Optional: true,
										Computed: true,
									},
									"custom_location": schema.StringAttribute{
										Optional: true,
										Computed: true,
									},
									"region": schema.StringAttribute{
										Optional: true,
										Computed: true,
										Validators: []validator.String{
											stringvalidator.OneOf(
												"KR",
												"HK",
												"SGN",
												"JPN",
												"USWN",
												"DEN",
												"FKR",
											),
										},
									},
									"type": schema.StringAttribute{
										Optional: true,
										Computed: true,
										Validators: []validator.String{
											stringvalidator.OneOf(
												"OBJECT_STORAGE",
												"LOAD_BALANCER",
												"API_GATEWAY",
												"CUSTOM",
												"NONE",
											),
										},
									},
								},
								CustomType: OriginalCopyLocationType{
									ObjectType: types.ObjectType{
										AttrTypes: OriginalCopyLocationValue{}.AttributeTypes(ctx),
									},
								},
								Optional: true,
								Computed: true,
							},
							"rule_name": schema.StringAttribute{
								Optional: true,
								Computed: true,
							},
							"status_codes": schema.ListAttribute{
								ElementType: types.Int64Type,
								Optional:    true,
								Computed:    true,
							},
						},
						CustomType: OriginFailoverConfigType{
							ObjectType: types.ObjectType{
								AttrTypes: OriginFailoverConfigValue{}.AttributeTypes(ctx),
							},
						},
						Optional: true,
						Computed: true,
					},
					"origin_shield": schema.SingleNestedAttribute{
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Optional: true,
								Computed: true,
							},
							"region": schema.StringAttribute{
								Optional: true,
								Computed: true,
								Validators: []validator.String{
									stringvalidator.OneOf(
										"KR",
										"HK",
										"SGN",
										"JPN",
										"USWN",
										"DEN",
										"FKR",
									),
								},
							},
						},
						CustomType: OriginShieldType{
							ObjectType: types.ObjectType{
								AttrTypes: OriginShieldValue{}.AttributeTypes(ctx),
							},
						},
						Required: true,
					},
					"original_copy_location": schema.SingleNestedAttribute{
						Attributes: map[string]schema.Attribute{
							"bucket_name": schema.StringAttribute{
								Optional: true,
								Computed: true,
							},
							"custom_location": schema.StringAttribute{
								Optional: true,
								Computed: true,
							},
							"region": schema.StringAttribute{
								Optional: true,
								Computed: true,
								Validators: []validator.String{
									stringvalidator.OneOf(
										"KR",
										"HK",
										"SGN",
										"JPN",
										"USWN",
										"DEN",
										"FKR",
									),
								},
							},
							"type": schema.StringAttribute{
								Optional: true,
								Computed: true,
								Validators: []validator.String{
									stringvalidator.OneOf(
										"OBJECT_STORAGE",
										"LOAD_BALANCER",
										"API_GATEWAY",
										"CUSTOM",
										"NONE",
									),
								},
							},
						},
						CustomType: OriginalCopyLocationType{
							ObjectType: types.ObjectType{
								AttrTypes: OriginalCopyLocationValue{}.AttributeTypes(ctx),
							},
						},
						Optional: true,
						Computed: true,
					},
					"original_copy_path": schema.StringAttribute{
						Optional: true,
						Computed: true,
						Validators: []validator.String{
							stringvalidator.LengthBetween(0, 100),
						},
					},
					"original_copy_protocol": schema.SingleNestedAttribute{
						Attributes: map[string]schema.Attribute{
							"port": schema.Int64Attribute{
								Optional: true,
								Computed: true,
							},
							"type": schema.StringAttribute{
								Optional: true,
								Computed: true,
								Validators: []validator.String{
									stringvalidator.OneOf(
										"HTTP",
										"HTTPS",
									),
								},
							},
						},
						CustomType: OriginalCopyProtocolType{
							ObjectType: types.ObjectType{
								AttrTypes: OriginalCopyProtocolValue{}.AttributeTypes(ctx),
							},
						},
						Required: true,
					},
				},
				CustomType: OriginalCopyConfigType{
					ObjectType: types.ObjectType{
						AttrTypes: OriginalCopyConfigValue{}.AttributeTypes(ctx),
					},
				},
				Required: true,
			},
			"profile_id": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Validators: []validator.Int64{
					int64validator.AtLeast(1),
				},
			},
		},
	}
}

type GlobalEdgeModel struct {
	AccessControl      AccessControlValue      `tfsdk:"access_control"`
	CachingConfig      CachingConfigValue      `tfsdk:"caching_config"`
	DistributionConfig DistributionConfigValue `tfsdk:"distribution_config"`
	EdgeId             types.String            `tfsdk:"edge_id"`
	EdgeName           types.String            `tfsdk:"edge_name"`
	HeaderPolicies     types.List              `tfsdk:"header_policies"`
	ManagedRule        ManagedRuleValue        `tfsdk:"managed_rule"`
	OptimizationConfig OptimizationConfigValue `tfsdk:"optimization_config"`
	OriginalCopyConfig OriginalCopyConfigValue `tfsdk:"original_copy_config"`
	ProfileId          types.Int64             `tfsdk:"profile_id"`
}

var _ basetypes.ObjectTypable = AccessControlType{}

type AccessControlType struct {
	basetypes.ObjectType
}

func (t AccessControlType) Equal(o attr.Type) bool {
	other, ok := o.(AccessControlType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t AccessControlType) String() string {
	return "AccessControlType"
}

func (t AccessControlType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	geoPoliciesAttribute, ok := attributes["geo_policies"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`geo_policies is missing from object`)

		return nil, diags
	}

	geoPoliciesVal, ok := geoPoliciesAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`geo_policies expected to be basetypes.ListValue, was: %T`, geoPoliciesAttribute))
	}

	ipPoliciesAttribute, ok := attributes["ip_policies"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`ip_policies is missing from object`)

		return nil, diags
	}

	ipPoliciesVal, ok := ipPoliciesAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`ip_policies expected to be basetypes.ListValue, was: %T`, ipPoliciesAttribute))
	}

	refererPoliciesAttribute, ok := attributes["referer_policies"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`referer_policies is missing from object`)

		return nil, diags
	}

	refererPoliciesVal, ok := refererPoliciesAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`referer_policies expected to be basetypes.ListValue, was: %T`, refererPoliciesAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return nil, diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return AccessControlValue{
		GeoPolicies:       geoPoliciesVal,
		IpPolicies:        ipPoliciesVal,
		RefererPolicies:   refererPoliciesVal,
		AccessControlType: typeVal,
		state:             attr.ValueStateKnown,
	}, diags
}

func NewAccessControlValueNull() AccessControlValue {
	return AccessControlValue{
		state: attr.ValueStateNull,
	}
}

func NewAccessControlValueUnknown() AccessControlValue {
	return AccessControlValue{
		state: attr.ValueStateUnknown,
	}
}

func NewAccessControlValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (AccessControlValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing AccessControlValue Attribute Value",
				"While creating a AccessControlValue value, a missing attribute value was detected. "+
					"A AccessControlValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("AccessControlValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid AccessControlValue Attribute Type",
				"While creating a AccessControlValue value, an invalid attribute value was detected. "+
					"A AccessControlValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("AccessControlValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("AccessControlValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra AccessControlValue Attribute Value",
				"While creating a AccessControlValue value, an extra attribute value was detected. "+
					"A AccessControlValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra AccessControlValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewAccessControlValueUnknown(), diags
	}

	geoPoliciesAttribute, ok := attributes["geo_policies"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`geo_policies is missing from object`)

		return NewAccessControlValueUnknown(), diags
	}

	geoPoliciesVal, ok := geoPoliciesAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`geo_policies expected to be basetypes.ListValue, was: %T`, geoPoliciesAttribute))
	}

	ipPoliciesAttribute, ok := attributes["ip_policies"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`ip_policies is missing from object`)

		return NewAccessControlValueUnknown(), diags
	}

	ipPoliciesVal, ok := ipPoliciesAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`ip_policies expected to be basetypes.ListValue, was: %T`, ipPoliciesAttribute))
	}

	refererPoliciesAttribute, ok := attributes["referer_policies"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`referer_policies is missing from object`)

		return NewAccessControlValueUnknown(), diags
	}

	refererPoliciesVal, ok := refererPoliciesAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`referer_policies expected to be basetypes.ListValue, was: %T`, refererPoliciesAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return NewAccessControlValueUnknown(), diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return NewAccessControlValueUnknown(), diags
	}

	return AccessControlValue{
		GeoPolicies:       geoPoliciesVal,
		IpPolicies:        ipPoliciesVal,
		RefererPolicies:   refererPoliciesVal,
		AccessControlType: typeVal,
		state:             attr.ValueStateKnown,
	}, diags
}

func NewAccessControlValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) AccessControlValue {
	object, diags := NewAccessControlValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewAccessControlValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t AccessControlType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewAccessControlValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewAccessControlValueUnknown(), nil
	}

	if in.IsNull() {
		return NewAccessControlValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewAccessControlValueMust(AccessControlValue{}.AttributeTypes(ctx), attributes), nil
}

func (t AccessControlType) ValueType(ctx context.Context) attr.Value {
	return AccessControlValue{}
}

var _ basetypes.ObjectValuable = AccessControlValue{}

type AccessControlValue struct {
	GeoPolicies       basetypes.ListValue   `tfsdk:"geo_policies"`
	IpPolicies        basetypes.ListValue   `tfsdk:"ip_policies"`
	RefererPolicies   basetypes.ListValue   `tfsdk:"referer_policies"`
	AccessControlType basetypes.StringValue `tfsdk:"type"`
	state             attr.ValueState
}

func (v AccessControlValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 4)

	var val tftypes.Value
	var err error

	attrTypes["geo_policies"] = basetypes.ListType{
		ElemType: types.StringType,
	}.TerraformType(ctx)
	attrTypes["ip_policies"] = basetypes.ListType{
		ElemType: types.StringType,
	}.TerraformType(ctx)
	attrTypes["referer_policies"] = basetypes.ListType{
		ElemType: types.StringType,
	}.TerraformType(ctx)
	attrTypes["type"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 4)

		val, err = v.GeoPolicies.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["geo_policies"] = val

		val, err = v.IpPolicies.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["ip_policies"] = val

		val, err = v.RefererPolicies.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["referer_policies"] = val

		val, err = v.AccessControlType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["type"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v AccessControlValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v AccessControlValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v AccessControlValue) String() string {
	return "AccessControlValue"
}

func (v AccessControlValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	geoPoliciesVal, d := types.ListValue(types.StringType, v.GeoPolicies.Elements())

	diags.Append(d...)

	if d.HasError() {
		return types.ObjectUnknown(map[string]attr.Type{
			"geo_policies": basetypes.ListType{
				ElemType: types.StringType,
			},
			"ip_policies": basetypes.ListType{
				ElemType: types.StringType,
			},
			"referer_policies": basetypes.ListType{
				ElemType: types.StringType,
			},
			"type": basetypes.StringType{},
		}), diags
	}

	ipPoliciesVal, d := types.ListValue(types.StringType, v.IpPolicies.Elements())

	diags.Append(d...)

	if d.HasError() {
		return types.ObjectUnknown(map[string]attr.Type{
			"geo_policies": basetypes.ListType{
				ElemType: types.StringType,
			},
			"ip_policies": basetypes.ListType{
				ElemType: types.StringType,
			},
			"referer_policies": basetypes.ListType{
				ElemType: types.StringType,
			},
			"type": basetypes.StringType{},
		}), diags
	}

	refererPoliciesVal, d := types.ListValue(types.StringType, v.RefererPolicies.Elements())

	diags.Append(d...)

	if d.HasError() {
		return types.ObjectUnknown(map[string]attr.Type{
			"geo_policies": basetypes.ListType{
				ElemType: types.StringType,
			},
			"ip_policies": basetypes.ListType{
				ElemType: types.StringType,
			},
			"referer_policies": basetypes.ListType{
				ElemType: types.StringType,
			},
			"type": basetypes.StringType{},
		}), diags
	}

	attributeTypes := map[string]attr.Type{
		"geo_policies": basetypes.ListType{
			ElemType: types.StringType,
		},
		"ip_policies": basetypes.ListType{
			ElemType: types.StringType,
		},
		"referer_policies": basetypes.ListType{
			ElemType: types.StringType,
		},
		"type": basetypes.StringType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"geo_policies":     geoPoliciesVal,
			"ip_policies":      ipPoliciesVal,
			"referer_policies": refererPoliciesVal,
			"type":             v.AccessControlType,
		})

	return objVal, diags
}

func (v AccessControlValue) Equal(o attr.Value) bool {
	other, ok := o.(AccessControlValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.GeoPolicies.Equal(other.GeoPolicies) {
		return false
	}

	if !v.IpPolicies.Equal(other.IpPolicies) {
		return false
	}

	if !v.RefererPolicies.Equal(other.RefererPolicies) {
		return false
	}

	if !v.AccessControlType.Equal(other.AccessControlType) {
		return false
	}

	return true
}

func (v AccessControlValue) Type(ctx context.Context) attr.Type {
	return AccessControlType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v AccessControlValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"geo_policies": basetypes.ListType{
			ElemType: types.StringType,
		},
		"ip_policies": basetypes.ListType{
			ElemType: types.StringType,
		},
		"referer_policies": basetypes.ListType{
			ElemType: types.StringType,
		},
		"type": basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = CachingConfigType{}

type CachingConfigType struct {
	basetypes.ObjectType
}

func (t CachingConfigType) Equal(o attr.Type) bool {
	other, ok := o.(CachingConfigType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t CachingConfigType) String() string {
	return "CachingConfigType"
}

func (t CachingConfigType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	bypassQueryStringAttribute, ok := attributes["bypass_query_string"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`bypass_query_string is missing from object`)

		return nil, diags
	}

	bypassQueryStringVal, ok := bypassQueryStringAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`bypass_query_string expected to be basetypes.ObjectValue, was: %T`, bypassQueryStringAttribute))
	}

	cacheKeyHostnameAttribute, ok := attributes["cache_key_hostname"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`cache_key_hostname is missing from object`)

		return nil, diags
	}

	cacheKeyHostnameVal, ok := cacheKeyHostnameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`cache_key_hostname expected to be basetypes.StringValue, was: %T`, cacheKeyHostnameAttribute))
	}

	cacheKeyIgnoreQueryStringAttribute, ok := attributes["cache_key_ignore_query_string"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`cache_key_ignore_query_string is missing from object`)

		return nil, diags
	}

	cacheKeyIgnoreQueryStringVal, ok := cacheKeyIgnoreQueryStringAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`cache_key_ignore_query_string expected to be basetypes.ObjectValue, was: %T`, cacheKeyIgnoreQueryStringAttribute))
	}

	cachingRulesAttribute, ok := attributes["caching_rules"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`caching_rules is missing from object`)

		return nil, diags
	}

	cachingRulesVal, ok := cachingRulesAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`caching_rules expected to be basetypes.ListValue, was: %T`, cachingRulesAttribute))
	}

	defaultCachingAttribute, ok := attributes["default_caching"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`default_caching is missing from object`)

		return nil, diags
	}

	defaultCachingVal, ok := defaultCachingAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`default_caching expected to be basetypes.ObjectValue, was: %T`, defaultCachingAttribute))
	}

	edgeAuthAttribute, ok := attributes["edge_auth"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`edge_auth is missing from object`)

		return nil, diags
	}

	edgeAuthVal, ok := edgeAuthAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`edge_auth expected to be basetypes.ObjectValue, was: %T`, edgeAuthAttribute))
	}

	negativeTtlAttribute, ok := attributes["negative_ttl"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`negative_ttl is missing from object`)

		return nil, diags
	}

	negativeTtlVal, ok := negativeTtlAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`negative_ttl expected to be basetypes.BoolValue, was: %T`, negativeTtlAttribute))
	}

	removeVaryHeaderAttribute, ok := attributes["remove_vary_header"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`remove_vary_header is missing from object`)

		return nil, diags
	}

	removeVaryHeaderVal, ok := removeVaryHeaderAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`remove_vary_header expected to be basetypes.BoolValue, was: %T`, removeVaryHeaderAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return CachingConfigValue{
		BypassQueryString:         bypassQueryStringVal,
		CacheKeyHostname:          cacheKeyHostnameVal,
		CacheKeyIgnoreQueryString: cacheKeyIgnoreQueryStringVal,
		CachingRules:              cachingRulesVal,
		DefaultCaching:            defaultCachingVal,
		EdgeAuth:                  edgeAuthVal,
		NegativeTtl:               negativeTtlVal,
		RemoveVaryHeader:          removeVaryHeaderVal,
		state:                     attr.ValueStateKnown,
	}, diags
}

func NewCachingConfigValueNull() CachingConfigValue {
	return CachingConfigValue{
		state: attr.ValueStateNull,
	}
}

func NewCachingConfigValueUnknown() CachingConfigValue {
	return CachingConfigValue{
		state: attr.ValueStateUnknown,
	}
}

func NewCachingConfigValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (CachingConfigValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing CachingConfigValue Attribute Value",
				"While creating a CachingConfigValue value, a missing attribute value was detected. "+
					"A CachingConfigValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("CachingConfigValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid CachingConfigValue Attribute Type",
				"While creating a CachingConfigValue value, an invalid attribute value was detected. "+
					"A CachingConfigValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("CachingConfigValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("CachingConfigValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra CachingConfigValue Attribute Value",
				"While creating a CachingConfigValue value, an extra attribute value was detected. "+
					"A CachingConfigValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra CachingConfigValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewCachingConfigValueUnknown(), diags
	}

	bypassQueryStringAttribute, ok := attributes["bypass_query_string"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`bypass_query_string is missing from object`)

		return NewCachingConfigValueUnknown(), diags
	}

	bypassQueryStringVal, ok := bypassQueryStringAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`bypass_query_string expected to be basetypes.ObjectValue, was: %T`, bypassQueryStringAttribute))
	}

	cacheKeyHostnameAttribute, ok := attributes["cache_key_hostname"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`cache_key_hostname is missing from object`)

		return NewCachingConfigValueUnknown(), diags
	}

	cacheKeyHostnameVal, ok := cacheKeyHostnameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`cache_key_hostname expected to be basetypes.StringValue, was: %T`, cacheKeyHostnameAttribute))
	}

	cacheKeyIgnoreQueryStringAttribute, ok := attributes["cache_key_ignore_query_string"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`cache_key_ignore_query_string is missing from object`)

		return NewCachingConfigValueUnknown(), diags
	}

	cacheKeyIgnoreQueryStringVal, ok := cacheKeyIgnoreQueryStringAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`cache_key_ignore_query_string expected to be basetypes.ObjectValue, was: %T`, cacheKeyIgnoreQueryStringAttribute))
	}

	cachingRulesAttribute, ok := attributes["caching_rules"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`caching_rules is missing from object`)

		return NewCachingConfigValueUnknown(), diags
	}

	cachingRulesVal, ok := cachingRulesAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`caching_rules expected to be basetypes.ListValue, was: %T`, cachingRulesAttribute))
	}

	defaultCachingAttribute, ok := attributes["default_caching"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`default_caching is missing from object`)

		return NewCachingConfigValueUnknown(), diags
	}

	defaultCachingVal, ok := defaultCachingAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`default_caching expected to be basetypes.ObjectValue, was: %T`, defaultCachingAttribute))
	}

	edgeAuthAttribute, ok := attributes["edge_auth"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`edge_auth is missing from object`)

		return NewCachingConfigValueUnknown(), diags
	}

	edgeAuthVal, ok := edgeAuthAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`edge_auth expected to be basetypes.ObjectValue, was: %T`, edgeAuthAttribute))
	}

	negativeTtlAttribute, ok := attributes["negative_ttl"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`negative_ttl is missing from object`)

		return NewCachingConfigValueUnknown(), diags
	}

	negativeTtlVal, ok := negativeTtlAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`negative_ttl expected to be basetypes.BoolValue, was: %T`, negativeTtlAttribute))
	}

	removeVaryHeaderAttribute, ok := attributes["remove_vary_header"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`remove_vary_header is missing from object`)

		return NewCachingConfigValueUnknown(), diags
	}

	removeVaryHeaderVal, ok := removeVaryHeaderAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`remove_vary_header expected to be basetypes.BoolValue, was: %T`, removeVaryHeaderAttribute))
	}

	if diags.HasError() {
		return NewCachingConfigValueUnknown(), diags
	}

	return CachingConfigValue{
		BypassQueryString:         bypassQueryStringVal,
		CacheKeyHostname:          cacheKeyHostnameVal,
		CacheKeyIgnoreQueryString: cacheKeyIgnoreQueryStringVal,
		CachingRules:              cachingRulesVal,
		DefaultCaching:            defaultCachingVal,
		EdgeAuth:                  edgeAuthVal,
		NegativeTtl:               negativeTtlVal,
		RemoveVaryHeader:          removeVaryHeaderVal,
		state:                     attr.ValueStateKnown,
	}, diags
}

func NewCachingConfigValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) CachingConfigValue {
	object, diags := NewCachingConfigValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewCachingConfigValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t CachingConfigType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewCachingConfigValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewCachingConfigValueUnknown(), nil
	}

	if in.IsNull() {
		return NewCachingConfigValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewCachingConfigValueMust(CachingConfigValue{}.AttributeTypes(ctx), attributes), nil
}

func (t CachingConfigType) ValueType(ctx context.Context) attr.Value {
	return CachingConfigValue{}
}

var _ basetypes.ObjectValuable = CachingConfigValue{}

type CachingConfigValue struct {
	BypassQueryString         basetypes.ObjectValue `tfsdk:"bypass_query_string"`
	CacheKeyHostname          basetypes.StringValue `tfsdk:"cache_key_hostname"`
	CacheKeyIgnoreQueryString basetypes.ObjectValue `tfsdk:"cache_key_ignore_query_string"`
	CachingRules              basetypes.ListValue   `tfsdk:"caching_rules"`
	DefaultCaching            basetypes.ObjectValue `tfsdk:"default_caching"`
	EdgeAuth                  basetypes.ObjectValue `tfsdk:"edge_auth"`
	NegativeTtl               basetypes.BoolValue   `tfsdk:"negative_ttl"`
	RemoveVaryHeader          basetypes.BoolValue   `tfsdk:"remove_vary_header"`
	state                     attr.ValueState
}

func (v CachingConfigValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 8)

	var val tftypes.Value
	var err error

	attrTypes["bypass_query_string"] = basetypes.ObjectType{
		AttrTypes: BypassQueryStringValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["cache_key_hostname"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["cache_key_ignore_query_string"] = basetypes.ObjectType{
		AttrTypes: CacheKeyIgnoreQueryStringValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["caching_rules"] = basetypes.ListType{
		ElemType: CachingRulesValue{}.Type(ctx),
	}.TerraformType(ctx)
	attrTypes["default_caching"] = basetypes.ObjectType{
		AttrTypes: DefaultCachingValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["edge_auth"] = basetypes.ObjectType{
		AttrTypes: EdgeAuthValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["negative_ttl"] = basetypes.BoolType{}.TerraformType(ctx)
	attrTypes["remove_vary_header"] = basetypes.BoolType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 8)

		val, err = v.BypassQueryString.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["bypass_query_string"] = val

		val, err = v.CacheKeyHostname.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["cache_key_hostname"] = val

		val, err = v.CacheKeyIgnoreQueryString.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["cache_key_ignore_query_string"] = val

		val, err = v.CachingRules.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["caching_rules"] = val

		val, err = v.DefaultCaching.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["default_caching"] = val

		val, err = v.EdgeAuth.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["edge_auth"] = val

		val, err = v.NegativeTtl.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["negative_ttl"] = val

		val, err = v.RemoveVaryHeader.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["remove_vary_header"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v CachingConfigValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v CachingConfigValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v CachingConfigValue) String() string {
	return "CachingConfigValue"
}

func (v CachingConfigValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	var bypassQueryString basetypes.ObjectValue

	if v.BypassQueryString.IsNull() {
		bypassQueryString = types.ObjectNull(
			BypassQueryStringValue{}.AttributeTypes(ctx),
		)
	}

	if v.BypassQueryString.IsUnknown() {
		bypassQueryString = types.ObjectUnknown(
			BypassQueryStringValue{}.AttributeTypes(ctx),
		)
	}

	if !v.BypassQueryString.IsNull() && !v.BypassQueryString.IsUnknown() {
		bypassQueryString = types.ObjectValueMust(
			BypassQueryStringValue{}.AttributeTypes(ctx),
			v.BypassQueryString.Attributes(),
		)
	}

	var cacheKeyIgnoreQueryString basetypes.ObjectValue

	if v.CacheKeyIgnoreQueryString.IsNull() {
		cacheKeyIgnoreQueryString = types.ObjectNull(
			CacheKeyIgnoreQueryStringValue{}.AttributeTypes(ctx),
		)
	}

	if v.CacheKeyIgnoreQueryString.IsUnknown() {
		cacheKeyIgnoreQueryString = types.ObjectUnknown(
			CacheKeyIgnoreQueryStringValue{}.AttributeTypes(ctx),
		)
	}

	if !v.CacheKeyIgnoreQueryString.IsNull() && !v.CacheKeyIgnoreQueryString.IsUnknown() {
		cacheKeyIgnoreQueryString = types.ObjectValueMust(
			CacheKeyIgnoreQueryStringValue{}.AttributeTypes(ctx),
			v.CacheKeyIgnoreQueryString.Attributes(),
		)
	}

	cachingRules := types.ListValueMust(
		CachingRulesType{
			basetypes.ObjectType{
				AttrTypes: CachingRulesValue{}.AttributeTypes(ctx),
			},
		},
		v.CachingRules.Elements(),
	)

	if v.CachingRules.IsNull() {
		cachingRules = types.ListNull(
			CachingRulesType{
				basetypes.ObjectType{
					AttrTypes: CachingRulesValue{}.AttributeTypes(ctx),
				},
			},
		)
	}

	if v.CachingRules.IsUnknown() {
		cachingRules = types.ListUnknown(
			CachingRulesType{
				basetypes.ObjectType{
					AttrTypes: CachingRulesValue{}.AttributeTypes(ctx),
				},
			},
		)
	}

	var defaultCaching basetypes.ObjectValue

	if v.DefaultCaching.IsNull() {
		defaultCaching = types.ObjectNull(
			DefaultCachingValue{}.AttributeTypes(ctx),
		)
	}

	if v.DefaultCaching.IsUnknown() {
		defaultCaching = types.ObjectUnknown(
			DefaultCachingValue{}.AttributeTypes(ctx),
		)
	}

	if !v.DefaultCaching.IsNull() && !v.DefaultCaching.IsUnknown() {
		defaultCaching = types.ObjectValueMust(
			DefaultCachingValue{}.AttributeTypes(ctx),
			v.DefaultCaching.Attributes(),
		)
	}

	var edgeAuth basetypes.ObjectValue

	if v.EdgeAuth.IsNull() {
		edgeAuth = types.ObjectNull(
			EdgeAuthValue{}.AttributeTypes(ctx),
		)
	}

	if v.EdgeAuth.IsUnknown() {
		edgeAuth = types.ObjectUnknown(
			EdgeAuthValue{}.AttributeTypes(ctx),
		)
	}

	if !v.EdgeAuth.IsNull() && !v.EdgeAuth.IsUnknown() {
		edgeAuth = types.ObjectValueMust(
			EdgeAuthValue{}.AttributeTypes(ctx),
			v.EdgeAuth.Attributes(),
		)
	}

	attributeTypes := map[string]attr.Type{
		"bypass_query_string": basetypes.ObjectType{
			AttrTypes: BypassQueryStringValue{}.AttributeTypes(ctx),
		},
		"cache_key_hostname": basetypes.StringType{},
		"cache_key_ignore_query_string": basetypes.ObjectType{
			AttrTypes: CacheKeyIgnoreQueryStringValue{}.AttributeTypes(ctx),
		},
		"caching_rules": basetypes.ListType{
			ElemType: CachingRulesValue{}.Type(ctx),
		},
		"default_caching": basetypes.ObjectType{
			AttrTypes: DefaultCachingValue{}.AttributeTypes(ctx),
		},
		"edge_auth": basetypes.ObjectType{
			AttrTypes: EdgeAuthValue{}.AttributeTypes(ctx),
		},
		"negative_ttl":       basetypes.BoolType{},
		"remove_vary_header": basetypes.BoolType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"bypass_query_string":           bypassQueryString,
			"cache_key_hostname":            v.CacheKeyHostname,
			"cache_key_ignore_query_string": cacheKeyIgnoreQueryString,
			"caching_rules":                 cachingRules,
			"default_caching":               defaultCaching,
			"edge_auth":                     edgeAuth,
			"negative_ttl":                  v.NegativeTtl,
			"remove_vary_header":            v.RemoveVaryHeader,
		})

	return objVal, diags
}

func (v CachingConfigValue) Equal(o attr.Value) bool {
	other, ok := o.(CachingConfigValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.BypassQueryString.Equal(other.BypassQueryString) {
		return false
	}

	if !v.CacheKeyHostname.Equal(other.CacheKeyHostname) {
		return false
	}

	if !v.CacheKeyIgnoreQueryString.Equal(other.CacheKeyIgnoreQueryString) {
		return false
	}

	if !v.CachingRules.Equal(other.CachingRules) {
		return false
	}

	if !v.DefaultCaching.Equal(other.DefaultCaching) {
		return false
	}

	if !v.EdgeAuth.Equal(other.EdgeAuth) {
		return false
	}

	if !v.NegativeTtl.Equal(other.NegativeTtl) {
		return false
	}

	if !v.RemoveVaryHeader.Equal(other.RemoveVaryHeader) {
		return false
	}

	return true
}

func (v CachingConfigValue) Type(ctx context.Context) attr.Type {
	return CachingConfigType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v CachingConfigValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"bypass_query_string": basetypes.ObjectType{
			AttrTypes: BypassQueryStringValue{}.AttributeTypes(ctx),
		},
		"cache_key_hostname": basetypes.StringType{},
		"cache_key_ignore_query_string": basetypes.ObjectType{
			AttrTypes: CacheKeyIgnoreQueryStringValue{}.AttributeTypes(ctx),
		},
		"caching_rules": basetypes.ListType{
			ElemType: CachingRulesValue{}.Type(ctx),
		},
		"default_caching": basetypes.ObjectType{
			AttrTypes: DefaultCachingValue{}.AttributeTypes(ctx),
		},
		"edge_auth": basetypes.ObjectType{
			AttrTypes: EdgeAuthValue{}.AttributeTypes(ctx),
		},
		"negative_ttl":       basetypes.BoolType{},
		"remove_vary_header": basetypes.BoolType{},
	}
}

var _ basetypes.ObjectTypable = BypassQueryStringType{}

type BypassQueryStringType struct {
	basetypes.ObjectType
}

func (t BypassQueryStringType) Equal(o attr.Type) bool {
	other, ok := o.(BypassQueryStringType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t BypassQueryStringType) String() string {
	return "BypassQueryStringType"
}

func (t BypassQueryStringType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return nil, diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	queryStringsAttribute, ok := attributes["query_strings"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`query_strings is missing from object`)

		return nil, diags
	}

	queryStringsVal, ok := queryStringsAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`query_strings expected to be basetypes.ListValue, was: %T`, queryStringsAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return BypassQueryStringValue{
		Enabled:      enabledVal,
		QueryStrings: queryStringsVal,
		state:        attr.ValueStateKnown,
	}, diags
}

func NewBypassQueryStringValueNull() BypassQueryStringValue {
	return BypassQueryStringValue{
		state: attr.ValueStateNull,
	}
}

func NewBypassQueryStringValueUnknown() BypassQueryStringValue {
	return BypassQueryStringValue{
		state: attr.ValueStateUnknown,
	}
}

func NewBypassQueryStringValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (BypassQueryStringValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing BypassQueryStringValue Attribute Value",
				"While creating a BypassQueryStringValue value, a missing attribute value was detected. "+
					"A BypassQueryStringValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("BypassQueryStringValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid BypassQueryStringValue Attribute Type",
				"While creating a BypassQueryStringValue value, an invalid attribute value was detected. "+
					"A BypassQueryStringValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("BypassQueryStringValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("BypassQueryStringValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra BypassQueryStringValue Attribute Value",
				"While creating a BypassQueryStringValue value, an extra attribute value was detected. "+
					"A BypassQueryStringValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra BypassQueryStringValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewBypassQueryStringValueUnknown(), diags
	}

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return NewBypassQueryStringValueUnknown(), diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	queryStringsAttribute, ok := attributes["query_strings"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`query_strings is missing from object`)

		return NewBypassQueryStringValueUnknown(), diags
	}

	queryStringsVal, ok := queryStringsAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`query_strings expected to be basetypes.ListValue, was: %T`, queryStringsAttribute))
	}

	if diags.HasError() {
		return NewBypassQueryStringValueUnknown(), diags
	}

	return BypassQueryStringValue{
		Enabled:      enabledVal,
		QueryStrings: queryStringsVal,
		state:        attr.ValueStateKnown,
	}, diags
}

func NewBypassQueryStringValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) BypassQueryStringValue {
	object, diags := NewBypassQueryStringValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewBypassQueryStringValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t BypassQueryStringType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewBypassQueryStringValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewBypassQueryStringValueUnknown(), nil
	}

	if in.IsNull() {
		return NewBypassQueryStringValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewBypassQueryStringValueMust(BypassQueryStringValue{}.AttributeTypes(ctx), attributes), nil
}

func (t BypassQueryStringType) ValueType(ctx context.Context) attr.Value {
	return BypassQueryStringValue{}
}

var _ basetypes.ObjectValuable = BypassQueryStringValue{}

type BypassQueryStringValue struct {
	Enabled      basetypes.BoolValue `tfsdk:"enabled"`
	QueryStrings basetypes.ListValue `tfsdk:"query_strings"`
	state        attr.ValueState
}

func (v BypassQueryStringValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 2)

	var val tftypes.Value
	var err error

	attrTypes["enabled"] = basetypes.BoolType{}.TerraformType(ctx)
	attrTypes["query_strings"] = basetypes.ListType{
		ElemType: types.StringType,
	}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 2)

		val, err = v.Enabled.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["enabled"] = val

		val, err = v.QueryStrings.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["query_strings"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v BypassQueryStringValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v BypassQueryStringValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v BypassQueryStringValue) String() string {
	return "BypassQueryStringValue"
}

func (v BypassQueryStringValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	queryStringsVal, d := types.ListValue(types.StringType, v.QueryStrings.Elements())

	diags.Append(d...)

	if d.HasError() {
		return types.ObjectUnknown(map[string]attr.Type{
			"enabled": basetypes.BoolType{},
			"query_strings": basetypes.ListType{
				ElemType: types.StringType,
			},
		}), diags
	}

	attributeTypes := map[string]attr.Type{
		"enabled": basetypes.BoolType{},
		"query_strings": basetypes.ListType{
			ElemType: types.StringType,
		},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"enabled":       v.Enabled,
			"query_strings": queryStringsVal,
		})

	return objVal, diags
}

func (v BypassQueryStringValue) Equal(o attr.Value) bool {
	other, ok := o.(BypassQueryStringValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Enabled.Equal(other.Enabled) {
		return false
	}

	if !v.QueryStrings.Equal(other.QueryStrings) {
		return false
	}

	return true
}

func (v BypassQueryStringValue) Type(ctx context.Context) attr.Type {
	return BypassQueryStringType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v BypassQueryStringValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"enabled": basetypes.BoolType{},
		"query_strings": basetypes.ListType{
			ElemType: types.StringType,
		},
	}
}

var _ basetypes.ObjectTypable = CacheKeyIgnoreQueryStringType{}

type CacheKeyIgnoreQueryStringType struct {
	basetypes.ObjectType
}

func (t CacheKeyIgnoreQueryStringType) Equal(o attr.Type) bool {
	other, ok := o.(CacheKeyIgnoreQueryStringType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t CacheKeyIgnoreQueryStringType) String() string {
	return "CacheKeyIgnoreQueryStringType"
}

func (t CacheKeyIgnoreQueryStringType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	queryStringsAttribute, ok := attributes["query_strings"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`query_strings is missing from object`)

		return nil, diags
	}

	queryStringsVal, ok := queryStringsAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`query_strings expected to be basetypes.ListValue, was: %T`, queryStringsAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return nil, diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return CacheKeyIgnoreQueryStringValue{
		QueryStrings:                  queryStringsVal,
		CacheKeyIgnoreQueryStringType: typeVal,
		state:                         attr.ValueStateKnown,
	}, diags
}

func NewCacheKeyIgnoreQueryStringValueNull() CacheKeyIgnoreQueryStringValue {
	return CacheKeyIgnoreQueryStringValue{
		state: attr.ValueStateNull,
	}
}

func NewCacheKeyIgnoreQueryStringValueUnknown() CacheKeyIgnoreQueryStringValue {
	return CacheKeyIgnoreQueryStringValue{
		state: attr.ValueStateUnknown,
	}
}

func NewCacheKeyIgnoreQueryStringValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (CacheKeyIgnoreQueryStringValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing CacheKeyIgnoreQueryStringValue Attribute Value",
				"While creating a CacheKeyIgnoreQueryStringValue value, a missing attribute value was detected. "+
					"A CacheKeyIgnoreQueryStringValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("CacheKeyIgnoreQueryStringValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid CacheKeyIgnoreQueryStringValue Attribute Type",
				"While creating a CacheKeyIgnoreQueryStringValue value, an invalid attribute value was detected. "+
					"A CacheKeyIgnoreQueryStringValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("CacheKeyIgnoreQueryStringValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("CacheKeyIgnoreQueryStringValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra CacheKeyIgnoreQueryStringValue Attribute Value",
				"While creating a CacheKeyIgnoreQueryStringValue value, an extra attribute value was detected. "+
					"A CacheKeyIgnoreQueryStringValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra CacheKeyIgnoreQueryStringValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewCacheKeyIgnoreQueryStringValueUnknown(), diags
	}

	queryStringsAttribute, ok := attributes["query_strings"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`query_strings is missing from object`)

		return NewCacheKeyIgnoreQueryStringValueUnknown(), diags
	}

	queryStringsVal, ok := queryStringsAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`query_strings expected to be basetypes.ListValue, was: %T`, queryStringsAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return NewCacheKeyIgnoreQueryStringValueUnknown(), diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return NewCacheKeyIgnoreQueryStringValueUnknown(), diags
	}

	return CacheKeyIgnoreQueryStringValue{
		QueryStrings:                  queryStringsVal,
		CacheKeyIgnoreQueryStringType: typeVal,
		state:                         attr.ValueStateKnown,
	}, diags
}

func NewCacheKeyIgnoreQueryStringValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) CacheKeyIgnoreQueryStringValue {
	object, diags := NewCacheKeyIgnoreQueryStringValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewCacheKeyIgnoreQueryStringValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t CacheKeyIgnoreQueryStringType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewCacheKeyIgnoreQueryStringValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewCacheKeyIgnoreQueryStringValueUnknown(), nil
	}

	if in.IsNull() {
		return NewCacheKeyIgnoreQueryStringValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewCacheKeyIgnoreQueryStringValueMust(CacheKeyIgnoreQueryStringValue{}.AttributeTypes(ctx), attributes), nil
}

func (t CacheKeyIgnoreQueryStringType) ValueType(ctx context.Context) attr.Value {
	return CacheKeyIgnoreQueryStringValue{}
}

var _ basetypes.ObjectValuable = CacheKeyIgnoreQueryStringValue{}

type CacheKeyIgnoreQueryStringValue struct {
	QueryStrings                  basetypes.ListValue   `tfsdk:"query_strings"`
	CacheKeyIgnoreQueryStringType basetypes.StringValue `tfsdk:"type"`
	state                         attr.ValueState
}

func (v CacheKeyIgnoreQueryStringValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 2)

	var val tftypes.Value
	var err error

	attrTypes["query_strings"] = basetypes.ListType{
		ElemType: types.StringType,
	}.TerraformType(ctx)
	attrTypes["type"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 2)

		val, err = v.QueryStrings.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["query_strings"] = val

		val, err = v.CacheKeyIgnoreQueryStringType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["type"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v CacheKeyIgnoreQueryStringValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v CacheKeyIgnoreQueryStringValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v CacheKeyIgnoreQueryStringValue) String() string {
	return "CacheKeyIgnoreQueryStringValue"
}

func (v CacheKeyIgnoreQueryStringValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	queryStringsVal, d := types.ListValue(types.StringType, v.QueryStrings.Elements())

	diags.Append(d...)

	if d.HasError() {
		return types.ObjectUnknown(map[string]attr.Type{
			"query_strings": basetypes.ListType{
				ElemType: types.StringType,
			},
			"type": basetypes.StringType{},
		}), diags
	}

	attributeTypes := map[string]attr.Type{
		"query_strings": basetypes.ListType{
			ElemType: types.StringType,
		},
		"type": basetypes.StringType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"query_strings": queryStringsVal,
			"type":          v.CacheKeyIgnoreQueryStringType,
		})

	return objVal, diags
}

func (v CacheKeyIgnoreQueryStringValue) Equal(o attr.Value) bool {
	other, ok := o.(CacheKeyIgnoreQueryStringValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.QueryStrings.Equal(other.QueryStrings) {
		return false
	}

	if !v.CacheKeyIgnoreQueryStringType.Equal(other.CacheKeyIgnoreQueryStringType) {
		return false
	}

	return true
}

func (v CacheKeyIgnoreQueryStringValue) Type(ctx context.Context) attr.Type {
	return CacheKeyIgnoreQueryStringType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v CacheKeyIgnoreQueryStringValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"query_strings": basetypes.ListType{
			ElemType: types.StringType,
		},
		"type": basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = CachingRulesType{}

type CachingRulesType struct {
	basetypes.ObjectType
}

func (t CachingRulesType) Equal(o attr.Type) bool {
	other, ok := o.(CachingRulesType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t CachingRulesType) String() string {
	return "CachingRulesType"
}

func (t CachingRulesType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	accessDenyAttribute, ok := attributes["access_deny"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`access_deny is missing from object`)

		return nil, diags
	}

	accessDenyVal, ok := accessDenyAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`access_deny expected to be basetypes.BoolValue, was: %T`, accessDenyAttribute))
	}

	browserCacheAttribute, ok := attributes["browser_cache"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`browser_cache is missing from object`)

		return nil, diags
	}

	browserCacheVal, ok := browserCacheAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`browser_cache expected to be basetypes.ObjectValue, was: %T`, browserCacheAttribute))
	}

	cacheKeyQueryParameterAttribute, ok := attributes["cache_key_query_parameter"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`cache_key_query_parameter is missing from object`)

		return nil, diags
	}

	cacheKeyQueryParameterVal, ok := cacheKeyQueryParameterAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`cache_key_query_parameter expected to be basetypes.ObjectValue, was: %T`, cacheKeyQueryParameterAttribute))
	}

	cacheRevalidateConfigAttribute, ok := attributes["cache_revalidate_config"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`cache_revalidate_config is missing from object`)

		return nil, diags
	}

	cacheRevalidateConfigVal, ok := cacheRevalidateConfigAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`cache_revalidate_config expected to be basetypes.ObjectValue, was: %T`, cacheRevalidateConfigAttribute))
	}

	ruleBasedRoutingConfigAttribute, ok := attributes["rule_based_routing_config"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`rule_based_routing_config is missing from object`)

		return nil, diags
	}

	ruleBasedRoutingConfigVal, ok := ruleBasedRoutingConfigAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`rule_based_routing_config expected to be basetypes.ObjectValue, was: %T`, ruleBasedRoutingConfigAttribute))
	}

	ruleConditionsAttribute, ok := attributes["rule_conditions"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`rule_conditions is missing from object`)

		return nil, diags
	}

	ruleConditionsVal, ok := ruleConditionsAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`rule_conditions expected to be basetypes.ListValue, was: %T`, ruleConditionsAttribute))
	}

	ruleDefinitionTypeAttribute, ok := attributes["rule_definition_type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`rule_definition_type is missing from object`)

		return nil, diags
	}

	ruleDefinitionTypeVal, ok := ruleDefinitionTypeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`rule_definition_type expected to be basetypes.StringValue, was: %T`, ruleDefinitionTypeAttribute))
	}

	ruleNameAttribute, ok := attributes["rule_name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`rule_name is missing from object`)

		return nil, diags
	}

	ruleNameVal, ok := ruleNameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`rule_name expected to be basetypes.StringValue, was: %T`, ruleNameAttribute))
	}

	ruleTypeAttribute, ok := attributes["rule_type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`rule_type is missing from object`)

		return nil, diags
	}

	ruleTypeVal, ok := ruleTypeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`rule_type expected to be basetypes.StringValue, was: %T`, ruleTypeAttribute))
	}

	urlRedirectAttribute, ok := attributes["url_redirect"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`url_redirect is missing from object`)

		return nil, diags
	}

	urlRedirectVal, ok := urlRedirectAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`url_redirect expected to be basetypes.ObjectValue, was: %T`, urlRedirectAttribute))
	}

	urlRewriteAttribute, ok := attributes["url_rewrite"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`url_rewrite is missing from object`)

		return nil, diags
	}

	urlRewriteVal, ok := urlRewriteAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`url_rewrite expected to be basetypes.ObjectValue, was: %T`, urlRewriteAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return CachingRulesValue{
		AccessDeny:             accessDenyVal,
		BrowserCache:           browserCacheVal,
		CacheKeyQueryParameter: cacheKeyQueryParameterVal,
		CacheRevalidateConfig:  cacheRevalidateConfigVal,
		RuleBasedRoutingConfig: ruleBasedRoutingConfigVal,
		RuleConditions:         ruleConditionsVal,
		RuleDefinitionType:     ruleDefinitionTypeVal,
		RuleName:               ruleNameVal,
		RuleType:               ruleTypeVal,
		UrlRedirect:            urlRedirectVal,
		UrlRewrite:             urlRewriteVal,
		state:                  attr.ValueStateKnown,
	}, diags
}

func NewCachingRulesValueNull() CachingRulesValue {
	return CachingRulesValue{
		state: attr.ValueStateNull,
	}
}

func NewCachingRulesValueUnknown() CachingRulesValue {
	return CachingRulesValue{
		state: attr.ValueStateUnknown,
	}
}

func NewCachingRulesValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (CachingRulesValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing CachingRulesValue Attribute Value",
				"While creating a CachingRulesValue value, a missing attribute value was detected. "+
					"A CachingRulesValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("CachingRulesValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid CachingRulesValue Attribute Type",
				"While creating a CachingRulesValue value, an invalid attribute value was detected. "+
					"A CachingRulesValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("CachingRulesValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("CachingRulesValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra CachingRulesValue Attribute Value",
				"While creating a CachingRulesValue value, an extra attribute value was detected. "+
					"A CachingRulesValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra CachingRulesValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewCachingRulesValueUnknown(), diags
	}

	accessDenyAttribute, ok := attributes["access_deny"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`access_deny is missing from object`)

		return NewCachingRulesValueUnknown(), diags
	}

	accessDenyVal, ok := accessDenyAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`access_deny expected to be basetypes.BoolValue, was: %T`, accessDenyAttribute))
	}

	browserCacheAttribute, ok := attributes["browser_cache"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`browser_cache is missing from object`)

		return NewCachingRulesValueUnknown(), diags
	}

	browserCacheVal, ok := browserCacheAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`browser_cache expected to be basetypes.ObjectValue, was: %T`, browserCacheAttribute))
	}

	cacheKeyQueryParameterAttribute, ok := attributes["cache_key_query_parameter"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`cache_key_query_parameter is missing from object`)

		return NewCachingRulesValueUnknown(), diags
	}

	cacheKeyQueryParameterVal, ok := cacheKeyQueryParameterAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`cache_key_query_parameter expected to be basetypes.ObjectValue, was: %T`, cacheKeyQueryParameterAttribute))
	}

	cacheRevalidateConfigAttribute, ok := attributes["cache_revalidate_config"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`cache_revalidate_config is missing from object`)

		return NewCachingRulesValueUnknown(), diags
	}

	cacheRevalidateConfigVal, ok := cacheRevalidateConfigAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`cache_revalidate_config expected to be basetypes.ObjectValue, was: %T`, cacheRevalidateConfigAttribute))
	}

	ruleBasedRoutingConfigAttribute, ok := attributes["rule_based_routing_config"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`rule_based_routing_config is missing from object`)

		return NewCachingRulesValueUnknown(), diags
	}

	ruleBasedRoutingConfigVal, ok := ruleBasedRoutingConfigAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`rule_based_routing_config expected to be basetypes.ObjectValue, was: %T`, ruleBasedRoutingConfigAttribute))
	}

	ruleConditionsAttribute, ok := attributes["rule_conditions"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`rule_conditions is missing from object`)

		return NewCachingRulesValueUnknown(), diags
	}

	ruleConditionsVal, ok := ruleConditionsAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`rule_conditions expected to be basetypes.ListValue, was: %T`, ruleConditionsAttribute))
	}

	ruleDefinitionTypeAttribute, ok := attributes["rule_definition_type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`rule_definition_type is missing from object`)

		return NewCachingRulesValueUnknown(), diags
	}

	ruleDefinitionTypeVal, ok := ruleDefinitionTypeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`rule_definition_type expected to be basetypes.StringValue, was: %T`, ruleDefinitionTypeAttribute))
	}

	ruleNameAttribute, ok := attributes["rule_name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`rule_name is missing from object`)

		return NewCachingRulesValueUnknown(), diags
	}

	ruleNameVal, ok := ruleNameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`rule_name expected to be basetypes.StringValue, was: %T`, ruleNameAttribute))
	}

	ruleTypeAttribute, ok := attributes["rule_type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`rule_type is missing from object`)

		return NewCachingRulesValueUnknown(), diags
	}

	ruleTypeVal, ok := ruleTypeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`rule_type expected to be basetypes.StringValue, was: %T`, ruleTypeAttribute))
	}

	urlRedirectAttribute, ok := attributes["url_redirect"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`url_redirect is missing from object`)

		return NewCachingRulesValueUnknown(), diags
	}

	urlRedirectVal, ok := urlRedirectAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`url_redirect expected to be basetypes.ObjectValue, was: %T`, urlRedirectAttribute))
	}

	urlRewriteAttribute, ok := attributes["url_rewrite"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`url_rewrite is missing from object`)

		return NewCachingRulesValueUnknown(), diags
	}

	urlRewriteVal, ok := urlRewriteAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`url_rewrite expected to be basetypes.ObjectValue, was: %T`, urlRewriteAttribute))
	}

	if diags.HasError() {
		return NewCachingRulesValueUnknown(), diags
	}

	return CachingRulesValue{
		AccessDeny:             accessDenyVal,
		BrowserCache:           browserCacheVal,
		CacheKeyQueryParameter: cacheKeyQueryParameterVal,
		CacheRevalidateConfig:  cacheRevalidateConfigVal,
		RuleBasedRoutingConfig: ruleBasedRoutingConfigVal,
		RuleConditions:         ruleConditionsVal,
		RuleDefinitionType:     ruleDefinitionTypeVal,
		RuleName:               ruleNameVal,
		RuleType:               ruleTypeVal,
		UrlRedirect:            urlRedirectVal,
		UrlRewrite:             urlRewriteVal,
		state:                  attr.ValueStateKnown,
	}, diags
}

func NewCachingRulesValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) CachingRulesValue {
	object, diags := NewCachingRulesValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewCachingRulesValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t CachingRulesType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewCachingRulesValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewCachingRulesValueUnknown(), nil
	}

	if in.IsNull() {
		return NewCachingRulesValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewCachingRulesValueMust(CachingRulesValue{}.AttributeTypes(ctx), attributes), nil
}

func (t CachingRulesType) ValueType(ctx context.Context) attr.Value {
	return CachingRulesValue{}
}

var _ basetypes.ObjectValuable = CachingRulesValue{}

type CachingRulesValue struct {
	AccessDeny             basetypes.BoolValue   `tfsdk:"access_deny"`
	BrowserCache           basetypes.ObjectValue `tfsdk:"browser_cache"`
	CacheKeyQueryParameter basetypes.ObjectValue `tfsdk:"cache_key_query_parameter"`
	CacheRevalidateConfig  basetypes.ObjectValue `tfsdk:"cache_revalidate_config"`
	RuleBasedRoutingConfig basetypes.ObjectValue `tfsdk:"rule_based_routing_config"`
	RuleConditions         basetypes.ListValue   `tfsdk:"rule_conditions"`
	RuleDefinitionType     basetypes.StringValue `tfsdk:"rule_definition_type"`
	RuleName               basetypes.StringValue `tfsdk:"rule_name"`
	RuleType               basetypes.StringValue `tfsdk:"rule_type"`
	UrlRedirect            basetypes.ObjectValue `tfsdk:"url_redirect"`
	UrlRewrite             basetypes.ObjectValue `tfsdk:"url_rewrite"`
	state                  attr.ValueState
}

func (v CachingRulesValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 11)

	var val tftypes.Value
	var err error

	attrTypes["access_deny"] = basetypes.BoolType{}.TerraformType(ctx)
	attrTypes["browser_cache"] = basetypes.ObjectType{
		AttrTypes: BrowserCacheValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["cache_key_query_parameter"] = basetypes.ObjectType{
		AttrTypes: CacheKeyQueryParameterValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["cache_revalidate_config"] = basetypes.ObjectType{
		AttrTypes: CacheRevalidateConfigValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["rule_based_routing_config"] = basetypes.ObjectType{
		AttrTypes: RuleBasedRoutingConfigValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["rule_conditions"] = basetypes.ListType{
		ElemType: types.StringType,
	}.TerraformType(ctx)
	attrTypes["rule_definition_type"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["rule_name"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["rule_type"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["url_redirect"] = basetypes.ObjectType{
		AttrTypes: UrlRedirectValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["url_rewrite"] = basetypes.ObjectType{
		AttrTypes: UrlRewriteValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 11)

		val, err = v.AccessDeny.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["access_deny"] = val

		val, err = v.BrowserCache.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["browser_cache"] = val

		val, err = v.CacheKeyQueryParameter.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["cache_key_query_parameter"] = val

		val, err = v.CacheRevalidateConfig.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["cache_revalidate_config"] = val

		val, err = v.RuleBasedRoutingConfig.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["rule_based_routing_config"] = val

		val, err = v.RuleConditions.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["rule_conditions"] = val

		val, err = v.RuleDefinitionType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["rule_definition_type"] = val

		val, err = v.RuleName.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["rule_name"] = val

		val, err = v.RuleType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["rule_type"] = val

		val, err = v.UrlRedirect.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["url_redirect"] = val

		val, err = v.UrlRewrite.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["url_rewrite"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v CachingRulesValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v CachingRulesValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v CachingRulesValue) String() string {
	return "CachingRulesValue"
}

func (v CachingRulesValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	var browserCache basetypes.ObjectValue

	if v.BrowserCache.IsNull() {
		browserCache = types.ObjectNull(
			BrowserCacheValue{}.AttributeTypes(ctx),
		)
	}

	if v.BrowserCache.IsUnknown() {
		browserCache = types.ObjectUnknown(
			BrowserCacheValue{}.AttributeTypes(ctx),
		)
	}

	if !v.BrowserCache.IsNull() && !v.BrowserCache.IsUnknown() {
		browserCache = types.ObjectValueMust(
			BrowserCacheValue{}.AttributeTypes(ctx),
			v.BrowserCache.Attributes(),
		)
	}

	var cacheKeyQueryParameter basetypes.ObjectValue

	if v.CacheKeyQueryParameter.IsNull() {
		cacheKeyQueryParameter = types.ObjectNull(
			CacheKeyQueryParameterValue{}.AttributeTypes(ctx),
		)
	}

	if v.CacheKeyQueryParameter.IsUnknown() {
		cacheKeyQueryParameter = types.ObjectUnknown(
			CacheKeyQueryParameterValue{}.AttributeTypes(ctx),
		)
	}

	if !v.CacheKeyQueryParameter.IsNull() && !v.CacheKeyQueryParameter.IsUnknown() {
		cacheKeyQueryParameter = types.ObjectValueMust(
			CacheKeyQueryParameterValue{}.AttributeTypes(ctx),
			v.CacheKeyQueryParameter.Attributes(),
		)
	}

	var cacheRevalidateConfig basetypes.ObjectValue

	if v.CacheRevalidateConfig.IsNull() {
		cacheRevalidateConfig = types.ObjectNull(
			CacheRevalidateConfigValue{}.AttributeTypes(ctx),
		)
	}

	if v.CacheRevalidateConfig.IsUnknown() {
		cacheRevalidateConfig = types.ObjectUnknown(
			CacheRevalidateConfigValue{}.AttributeTypes(ctx),
		)
	}

	if !v.CacheRevalidateConfig.IsNull() && !v.CacheRevalidateConfig.IsUnknown() {
		cacheRevalidateConfig = types.ObjectValueMust(
			CacheRevalidateConfigValue{}.AttributeTypes(ctx),
			v.CacheRevalidateConfig.Attributes(),
		)
	}

	var ruleBasedRoutingConfig basetypes.ObjectValue

	if v.RuleBasedRoutingConfig.IsNull() {
		ruleBasedRoutingConfig = types.ObjectNull(
			RuleBasedRoutingConfigValue{}.AttributeTypes(ctx),
		)
	}

	if v.RuleBasedRoutingConfig.IsUnknown() {
		ruleBasedRoutingConfig = types.ObjectUnknown(
			RuleBasedRoutingConfigValue{}.AttributeTypes(ctx),
		)
	}

	if !v.RuleBasedRoutingConfig.IsNull() && !v.RuleBasedRoutingConfig.IsUnknown() {
		ruleBasedRoutingConfig = types.ObjectValueMust(
			RuleBasedRoutingConfigValue{}.AttributeTypes(ctx),
			v.RuleBasedRoutingConfig.Attributes(),
		)
	}

	var urlRedirect basetypes.ObjectValue

	if v.UrlRedirect.IsNull() {
		urlRedirect = types.ObjectNull(
			UrlRedirectValue{}.AttributeTypes(ctx),
		)
	}

	if v.UrlRedirect.IsUnknown() {
		urlRedirect = types.ObjectUnknown(
			UrlRedirectValue{}.AttributeTypes(ctx),
		)
	}

	if !v.UrlRedirect.IsNull() && !v.UrlRedirect.IsUnknown() {
		urlRedirect = types.ObjectValueMust(
			UrlRedirectValue{}.AttributeTypes(ctx),
			v.UrlRedirect.Attributes(),
		)
	}

	var urlRewrite basetypes.ObjectValue

	if v.UrlRewrite.IsNull() {
		urlRewrite = types.ObjectNull(
			UrlRewriteValue{}.AttributeTypes(ctx),
		)
	}

	if v.UrlRewrite.IsUnknown() {
		urlRewrite = types.ObjectUnknown(
			UrlRewriteValue{}.AttributeTypes(ctx),
		)
	}

	if !v.UrlRewrite.IsNull() && !v.UrlRewrite.IsUnknown() {
		urlRewrite = types.ObjectValueMust(
			UrlRewriteValue{}.AttributeTypes(ctx),
			v.UrlRewrite.Attributes(),
		)
	}

	ruleConditionsVal, d := types.ListValue(types.StringType, v.RuleConditions.Elements())

	diags.Append(d...)

	if d.HasError() {
		return types.ObjectUnknown(map[string]attr.Type{
			"access_deny": basetypes.BoolType{},
			"browser_cache": basetypes.ObjectType{
				AttrTypes: BrowserCacheValue{}.AttributeTypes(ctx),
			},
			"cache_key_query_parameter": basetypes.ObjectType{
				AttrTypes: CacheKeyQueryParameterValue{}.AttributeTypes(ctx),
			},
			"cache_revalidate_config": basetypes.ObjectType{
				AttrTypes: CacheRevalidateConfigValue{}.AttributeTypes(ctx),
			},
			"rule_based_routing_config": basetypes.ObjectType{
				AttrTypes: RuleBasedRoutingConfigValue{}.AttributeTypes(ctx),
			},
			"rule_conditions": basetypes.ListType{
				ElemType: types.StringType,
			},
			"rule_definition_type": basetypes.StringType{},
			"rule_name":            basetypes.StringType{},
			"rule_type":            basetypes.StringType{},
			"url_redirect": basetypes.ObjectType{
				AttrTypes: UrlRedirectValue{}.AttributeTypes(ctx),
			},
			"url_rewrite": basetypes.ObjectType{
				AttrTypes: UrlRewriteValue{}.AttributeTypes(ctx),
			},
		}), diags
	}

	attributeTypes := map[string]attr.Type{
		"access_deny": basetypes.BoolType{},
		"browser_cache": basetypes.ObjectType{
			AttrTypes: BrowserCacheValue{}.AttributeTypes(ctx),
		},
		"cache_key_query_parameter": basetypes.ObjectType{
			AttrTypes: CacheKeyQueryParameterValue{}.AttributeTypes(ctx),
		},
		"cache_revalidate_config": basetypes.ObjectType{
			AttrTypes: CacheRevalidateConfigValue{}.AttributeTypes(ctx),
		},
		"rule_based_routing_config": basetypes.ObjectType{
			AttrTypes: RuleBasedRoutingConfigValue{}.AttributeTypes(ctx),
		},
		"rule_conditions": basetypes.ListType{
			ElemType: types.StringType,
		},
		"rule_definition_type": basetypes.StringType{},
		"rule_name":            basetypes.StringType{},
		"rule_type":            basetypes.StringType{},
		"url_redirect": basetypes.ObjectType{
			AttrTypes: UrlRedirectValue{}.AttributeTypes(ctx),
		},
		"url_rewrite": basetypes.ObjectType{
			AttrTypes: UrlRewriteValue{}.AttributeTypes(ctx),
		},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"access_deny":               v.AccessDeny,
			"browser_cache":             browserCache,
			"cache_key_query_parameter": cacheKeyQueryParameter,
			"cache_revalidate_config":   cacheRevalidateConfig,
			"rule_based_routing_config": ruleBasedRoutingConfig,
			"rule_conditions":           ruleConditionsVal,
			"rule_definition_type":      v.RuleDefinitionType,
			"rule_name":                 v.RuleName,
			"rule_type":                 v.RuleType,
			"url_redirect":              urlRedirect,
			"url_rewrite":               urlRewrite,
		})

	return objVal, diags
}

func (v CachingRulesValue) Equal(o attr.Value) bool {
	other, ok := o.(CachingRulesValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.AccessDeny.Equal(other.AccessDeny) {
		return false
	}

	if !v.BrowserCache.Equal(other.BrowserCache) {
		return false
	}

	if !v.CacheKeyQueryParameter.Equal(other.CacheKeyQueryParameter) {
		return false
	}

	if !v.CacheRevalidateConfig.Equal(other.CacheRevalidateConfig) {
		return false
	}

	if !v.RuleBasedRoutingConfig.Equal(other.RuleBasedRoutingConfig) {
		return false
	}

	if !v.RuleConditions.Equal(other.RuleConditions) {
		return false
	}

	if !v.RuleDefinitionType.Equal(other.RuleDefinitionType) {
		return false
	}

	if !v.RuleName.Equal(other.RuleName) {
		return false
	}

	if !v.RuleType.Equal(other.RuleType) {
		return false
	}

	if !v.UrlRedirect.Equal(other.UrlRedirect) {
		return false
	}

	if !v.UrlRewrite.Equal(other.UrlRewrite) {
		return false
	}

	return true
}

func (v CachingRulesValue) Type(ctx context.Context) attr.Type {
	return CachingRulesType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v CachingRulesValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"access_deny": basetypes.BoolType{},
		"browser_cache": basetypes.ObjectType{
			AttrTypes: BrowserCacheValue{}.AttributeTypes(ctx),
		},
		"cache_key_query_parameter": basetypes.ObjectType{
			AttrTypes: CacheKeyQueryParameterValue{}.AttributeTypes(ctx),
		},
		"cache_revalidate_config": basetypes.ObjectType{
			AttrTypes: CacheRevalidateConfigValue{}.AttributeTypes(ctx),
		},
		"rule_based_routing_config": basetypes.ObjectType{
			AttrTypes: RuleBasedRoutingConfigValue{}.AttributeTypes(ctx),
		},
		"rule_conditions": basetypes.ListType{
			ElemType: types.StringType,
		},
		"rule_definition_type": basetypes.StringType{},
		"rule_name":            basetypes.StringType{},
		"rule_type":            basetypes.StringType{},
		"url_redirect": basetypes.ObjectType{
			AttrTypes: UrlRedirectValue{}.AttributeTypes(ctx),
		},
		"url_rewrite": basetypes.ObjectType{
			AttrTypes: UrlRewriteValue{}.AttributeTypes(ctx),
		},
	}
}

var _ basetypes.ObjectTypable = BrowserCacheType{}

type BrowserCacheType struct {
	basetypes.ObjectType
}

func (t BrowserCacheType) Equal(o attr.Type) bool {
	other, ok := o.(BrowserCacheType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t BrowserCacheType) String() string {
	return "BrowserCacheType"
}

func (t BrowserCacheType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	ageAttribute, ok := attributes["age"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`age is missing from object`)

		return nil, diags
	}

	ageVal, ok := ageAttribute.(basetypes.Int64Value)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`age expected to be basetypes.Int64Value, was: %T`, ageAttribute))
	}

	ageTypeAttribute, ok := attributes["age_type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`age_type is missing from object`)

		return nil, diags
	}

	ageTypeVal, ok := ageTypeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`age_type expected to be basetypes.StringValue, was: %T`, ageTypeAttribute))
	}

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return nil, diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return nil, diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return BrowserCacheValue{
		Age:              ageVal,
		AgeType:          ageTypeVal,
		Enabled:          enabledVal,
		BrowserCacheType: typeVal,
		state:            attr.ValueStateKnown,
	}, diags
}

func NewBrowserCacheValueNull() BrowserCacheValue {
	return BrowserCacheValue{
		state: attr.ValueStateNull,
	}
}

func NewBrowserCacheValueUnknown() BrowserCacheValue {
	return BrowserCacheValue{
		state: attr.ValueStateUnknown,
	}
}

func NewBrowserCacheValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (BrowserCacheValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing BrowserCacheValue Attribute Value",
				"While creating a BrowserCacheValue value, a missing attribute value was detected. "+
					"A BrowserCacheValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("BrowserCacheValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid BrowserCacheValue Attribute Type",
				"While creating a BrowserCacheValue value, an invalid attribute value was detected. "+
					"A BrowserCacheValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("BrowserCacheValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("BrowserCacheValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra BrowserCacheValue Attribute Value",
				"While creating a BrowserCacheValue value, an extra attribute value was detected. "+
					"A BrowserCacheValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra BrowserCacheValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewBrowserCacheValueUnknown(), diags
	}

	ageAttribute, ok := attributes["age"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`age is missing from object`)

		return NewBrowserCacheValueUnknown(), diags
	}

	ageVal, ok := ageAttribute.(basetypes.Int64Value)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`age expected to be basetypes.Int64Value, was: %T`, ageAttribute))
	}

	ageTypeAttribute, ok := attributes["age_type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`age_type is missing from object`)

		return NewBrowserCacheValueUnknown(), diags
	}

	ageTypeVal, ok := ageTypeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`age_type expected to be basetypes.StringValue, was: %T`, ageTypeAttribute))
	}

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return NewBrowserCacheValueUnknown(), diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return NewBrowserCacheValueUnknown(), diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return NewBrowserCacheValueUnknown(), diags
	}

	return BrowserCacheValue{
		Age:              ageVal,
		AgeType:          ageTypeVal,
		Enabled:          enabledVal,
		BrowserCacheType: typeVal,
		state:            attr.ValueStateKnown,
	}, diags
}

func NewBrowserCacheValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) BrowserCacheValue {
	object, diags := NewBrowserCacheValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewBrowserCacheValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t BrowserCacheType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewBrowserCacheValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewBrowserCacheValueUnknown(), nil
	}

	if in.IsNull() {
		return NewBrowserCacheValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewBrowserCacheValueMust(BrowserCacheValue{}.AttributeTypes(ctx), attributes), nil
}

func (t BrowserCacheType) ValueType(ctx context.Context) attr.Value {
	return BrowserCacheValue{}
}

var _ basetypes.ObjectValuable = BrowserCacheValue{}

type BrowserCacheValue struct {
	Age              basetypes.Int64Value  `tfsdk:"age"`
	AgeType          basetypes.StringValue `tfsdk:"age_type"`
	Enabled          basetypes.BoolValue   `tfsdk:"enabled"`
	BrowserCacheType basetypes.StringValue `tfsdk:"type"`
	state            attr.ValueState
}

func (v BrowserCacheValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 4)

	var val tftypes.Value
	var err error

	attrTypes["age"] = basetypes.Int64Type{}.TerraformType(ctx)
	attrTypes["age_type"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["enabled"] = basetypes.BoolType{}.TerraformType(ctx)
	attrTypes["type"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 4)

		val, err = v.Age.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["age"] = val

		val, err = v.AgeType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["age_type"] = val

		val, err = v.Enabled.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["enabled"] = val

		val, err = v.BrowserCacheType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["type"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v BrowserCacheValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v BrowserCacheValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v BrowserCacheValue) String() string {
	return "BrowserCacheValue"
}

func (v BrowserCacheValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributeTypes := map[string]attr.Type{
		"age":      basetypes.Int64Type{},
		"age_type": basetypes.StringType{},
		"enabled":  basetypes.BoolType{},
		"type":     basetypes.StringType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"age":      v.Age,
			"age_type": v.AgeType,
			"enabled":  v.Enabled,
			"type":     v.BrowserCacheType,
		})

	return objVal, diags
}

func (v BrowserCacheValue) Equal(o attr.Value) bool {
	other, ok := o.(BrowserCacheValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Age.Equal(other.Age) {
		return false
	}

	if !v.AgeType.Equal(other.AgeType) {
		return false
	}

	if !v.Enabled.Equal(other.Enabled) {
		return false
	}

	if !v.BrowserCacheType.Equal(other.BrowserCacheType) {
		return false
	}

	return true
}

func (v BrowserCacheValue) Type(ctx context.Context) attr.Type {
	return BrowserCacheType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v BrowserCacheValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"age":      basetypes.Int64Type{},
		"age_type": basetypes.StringType{},
		"enabled":  basetypes.BoolType{},
		"type":     basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = CacheKeyQueryParameterType{}

type CacheKeyQueryParameterType struct {
	basetypes.ObjectType
}

func (t CacheKeyQueryParameterType) Equal(o attr.Type) bool {
	other, ok := o.(CacheKeyQueryParameterType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t CacheKeyQueryParameterType) String() string {
	return "CacheKeyQueryParameterType"
}

func (t CacheKeyQueryParameterType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return nil, diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	queryParametersAttribute, ok := attributes["query_parameters"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`query_parameters is missing from object`)

		return nil, diags
	}

	queryParametersVal, ok := queryParametersAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`query_parameters expected to be basetypes.ListValue, was: %T`, queryParametersAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return nil, diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return CacheKeyQueryParameterValue{
		Enabled:                    enabledVal,
		QueryParameters:            queryParametersVal,
		CacheKeyQueryParameterType: typeVal,
		state:                      attr.ValueStateKnown,
	}, diags
}

func NewCacheKeyQueryParameterValueNull() CacheKeyQueryParameterValue {
	return CacheKeyQueryParameterValue{
		state: attr.ValueStateNull,
	}
}

func NewCacheKeyQueryParameterValueUnknown() CacheKeyQueryParameterValue {
	return CacheKeyQueryParameterValue{
		state: attr.ValueStateUnknown,
	}
}

func NewCacheKeyQueryParameterValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (CacheKeyQueryParameterValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing CacheKeyQueryParameterValue Attribute Value",
				"While creating a CacheKeyQueryParameterValue value, a missing attribute value was detected. "+
					"A CacheKeyQueryParameterValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("CacheKeyQueryParameterValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid CacheKeyQueryParameterValue Attribute Type",
				"While creating a CacheKeyQueryParameterValue value, an invalid attribute value was detected. "+
					"A CacheKeyQueryParameterValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("CacheKeyQueryParameterValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("CacheKeyQueryParameterValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra CacheKeyQueryParameterValue Attribute Value",
				"While creating a CacheKeyQueryParameterValue value, an extra attribute value was detected. "+
					"A CacheKeyQueryParameterValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra CacheKeyQueryParameterValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewCacheKeyQueryParameterValueUnknown(), diags
	}

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return NewCacheKeyQueryParameterValueUnknown(), diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	queryParametersAttribute, ok := attributes["query_parameters"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`query_parameters is missing from object`)

		return NewCacheKeyQueryParameterValueUnknown(), diags
	}

	queryParametersVal, ok := queryParametersAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`query_parameters expected to be basetypes.ListValue, was: %T`, queryParametersAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return NewCacheKeyQueryParameterValueUnknown(), diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return NewCacheKeyQueryParameterValueUnknown(), diags
	}

	return CacheKeyQueryParameterValue{
		Enabled:                    enabledVal,
		QueryParameters:            queryParametersVal,
		CacheKeyQueryParameterType: typeVal,
		state:                      attr.ValueStateKnown,
	}, diags
}

func NewCacheKeyQueryParameterValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) CacheKeyQueryParameterValue {
	object, diags := NewCacheKeyQueryParameterValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewCacheKeyQueryParameterValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t CacheKeyQueryParameterType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewCacheKeyQueryParameterValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewCacheKeyQueryParameterValueUnknown(), nil
	}

	if in.IsNull() {
		return NewCacheKeyQueryParameterValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewCacheKeyQueryParameterValueMust(CacheKeyQueryParameterValue{}.AttributeTypes(ctx), attributes), nil
}

func (t CacheKeyQueryParameterType) ValueType(ctx context.Context) attr.Value {
	return CacheKeyQueryParameterValue{}
}

var _ basetypes.ObjectValuable = CacheKeyQueryParameterValue{}

type CacheKeyQueryParameterValue struct {
	Enabled                    basetypes.BoolValue   `tfsdk:"enabled"`
	QueryParameters            basetypes.ListValue   `tfsdk:"query_parameters"`
	CacheKeyQueryParameterType basetypes.StringValue `tfsdk:"type"`
	state                      attr.ValueState
}

func (v CacheKeyQueryParameterValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 3)

	var val tftypes.Value
	var err error

	attrTypes["enabled"] = basetypes.BoolType{}.TerraformType(ctx)
	attrTypes["query_parameters"] = basetypes.ListType{
		ElemType: types.StringType,
	}.TerraformType(ctx)
	attrTypes["type"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 3)

		val, err = v.Enabled.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["enabled"] = val

		val, err = v.QueryParameters.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["query_parameters"] = val

		val, err = v.CacheKeyQueryParameterType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["type"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v CacheKeyQueryParameterValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v CacheKeyQueryParameterValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v CacheKeyQueryParameterValue) String() string {
	return "CacheKeyQueryParameterValue"
}

func (v CacheKeyQueryParameterValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	queryParametersVal, d := types.ListValue(types.StringType, v.QueryParameters.Elements())

	diags.Append(d...)

	if d.HasError() {
		return types.ObjectUnknown(map[string]attr.Type{
			"enabled": basetypes.BoolType{},
			"query_parameters": basetypes.ListType{
				ElemType: types.StringType,
			},
			"type": basetypes.StringType{},
		}), diags
	}

	attributeTypes := map[string]attr.Type{
		"enabled": basetypes.BoolType{},
		"query_parameters": basetypes.ListType{
			ElemType: types.StringType,
		},
		"type": basetypes.StringType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"enabled":          v.Enabled,
			"query_parameters": queryParametersVal,
			"type":             v.CacheKeyQueryParameterType,
		})

	return objVal, diags
}

func (v CacheKeyQueryParameterValue) Equal(o attr.Value) bool {
	other, ok := o.(CacheKeyQueryParameterValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Enabled.Equal(other.Enabled) {
		return false
	}

	if !v.QueryParameters.Equal(other.QueryParameters) {
		return false
	}

	if !v.CacheKeyQueryParameterType.Equal(other.CacheKeyQueryParameterType) {
		return false
	}

	return true
}

func (v CacheKeyQueryParameterValue) Type(ctx context.Context) attr.Type {
	return CacheKeyQueryParameterType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v CacheKeyQueryParameterValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"enabled": basetypes.BoolType{},
		"query_parameters": basetypes.ListType{
			ElemType: types.StringType,
		},
		"type": basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = CacheRevalidateConfigType{}

func (t CacheRevalidateConfigType) Equal(o attr.Type) bool {
	other, ok := o.(CacheRevalidateConfigType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t CacheRevalidateConfigType) String() string {
	return "CacheRevalidateConfigType"
}

func (t CacheRevalidateConfigType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	ageAttribute, ok := attributes["age"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`age is missing from object`)

		return nil, diags
	}

	ageVal, ok := ageAttribute.(basetypes.Int64Value)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`age expected to be basetypes.Int64Value, was: %T`, ageAttribute))
	}

	ageTypeAttribute, ok := attributes["age_type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`age_type is missing from object`)

		return nil, diags
	}

	ageTypeVal, ok := ageTypeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`age_type expected to be basetypes.StringValue, was: %T`, ageTypeAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return nil, diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return CacheRevalidateConfigValue{
		Age:                       ageVal,
		AgeType:                   ageTypeVal,
		CacheRevalidateConfigType: typeVal,
		state:                     attr.ValueStateKnown,
	}, diags
}

func (t CacheRevalidateConfigType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewCacheRevalidateConfigValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewCacheRevalidateConfigValueUnknown(), nil
	}

	if in.IsNull() {
		return NewCacheRevalidateConfigValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewCacheRevalidateConfigValueMust(CacheRevalidateConfigValue{}.AttributeTypes(ctx), attributes), nil
}

func (t CacheRevalidateConfigType) ValueType(ctx context.Context) attr.Value {
	return CacheRevalidateConfigValue{}
}

var _ basetypes.ObjectValuable = CacheRevalidateConfigValue{}

func (v CacheRevalidateConfigValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 3)

	var val tftypes.Value
	var err error

	attrTypes["age"] = basetypes.Int64Type{}.TerraformType(ctx)
	attrTypes["age_type"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["type"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 3)

		val, err = v.Age.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["age"] = val

		val, err = v.AgeType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["age_type"] = val

		val, err = v.CacheRevalidateConfigType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["type"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v CacheRevalidateConfigValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v CacheRevalidateConfigValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v CacheRevalidateConfigValue) String() string {
	return "CacheRevalidateConfigValue"
}

func (v CacheRevalidateConfigValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributeTypes := map[string]attr.Type{
		"age":      basetypes.Int64Type{},
		"age_type": basetypes.StringType{},
		"type":     basetypes.StringType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"age":      v.Age,
			"age_type": v.AgeType,
			"type":     v.CacheRevalidateConfigType,
		})

	return objVal, diags
}

func (v CacheRevalidateConfigValue) Equal(o attr.Value) bool {
	other, ok := o.(CacheRevalidateConfigValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Age.Equal(other.Age) {
		return false
	}

	if !v.AgeType.Equal(other.AgeType) {
		return false
	}

	if !v.CacheRevalidateConfigType.Equal(other.CacheRevalidateConfigType) {
		return false
	}

	return true
}

func (v CacheRevalidateConfigValue) Type(ctx context.Context) attr.Type {
	return CacheRevalidateConfigType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v CacheRevalidateConfigValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"age":      basetypes.Int64Type{},
		"age_type": basetypes.StringType{},
		"type":     basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = RuleBasedRoutingConfigType{}

type RuleBasedRoutingConfigType struct {
	basetypes.ObjectType
}

func (t RuleBasedRoutingConfigType) Equal(o attr.Type) bool {
	other, ok := o.(RuleBasedRoutingConfigType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t RuleBasedRoutingConfigType) String() string {
	return "RuleBasedRoutingConfigType"
}

func (t RuleBasedRoutingConfigType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return nil, diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	originalCopyLocationAttribute, ok := attributes["original_copy_location"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`original_copy_location is missing from object`)

		return nil, diags
	}

	originalCopyLocationVal, ok := originalCopyLocationAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`original_copy_location expected to be basetypes.ObjectValue, was: %T`, originalCopyLocationAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return RuleBasedRoutingConfigValue{
		Enabled:              enabledVal,
		OriginalCopyLocation: originalCopyLocationVal,
		state:                attr.ValueStateKnown,
	}, diags
}

func NewRuleBasedRoutingConfigValueNull() RuleBasedRoutingConfigValue {
	return RuleBasedRoutingConfigValue{
		state: attr.ValueStateNull,
	}
}

func NewRuleBasedRoutingConfigValueUnknown() RuleBasedRoutingConfigValue {
	return RuleBasedRoutingConfigValue{
		state: attr.ValueStateUnknown,
	}
}

func NewRuleBasedRoutingConfigValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (RuleBasedRoutingConfigValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing RuleBasedRoutingConfigValue Attribute Value",
				"While creating a RuleBasedRoutingConfigValue value, a missing attribute value was detected. "+
					"A RuleBasedRoutingConfigValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("RuleBasedRoutingConfigValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid RuleBasedRoutingConfigValue Attribute Type",
				"While creating a RuleBasedRoutingConfigValue value, an invalid attribute value was detected. "+
					"A RuleBasedRoutingConfigValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("RuleBasedRoutingConfigValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("RuleBasedRoutingConfigValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra RuleBasedRoutingConfigValue Attribute Value",
				"While creating a RuleBasedRoutingConfigValue value, an extra attribute value was detected. "+
					"A RuleBasedRoutingConfigValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra RuleBasedRoutingConfigValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewRuleBasedRoutingConfigValueUnknown(), diags
	}

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return NewRuleBasedRoutingConfigValueUnknown(), diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	originalCopyLocationAttribute, ok := attributes["original_copy_location"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`original_copy_location is missing from object`)

		return NewRuleBasedRoutingConfigValueUnknown(), diags
	}

	originalCopyLocationVal, ok := originalCopyLocationAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`original_copy_location expected to be basetypes.ObjectValue, was: %T`, originalCopyLocationAttribute))
	}

	if diags.HasError() {
		return NewRuleBasedRoutingConfigValueUnknown(), diags
	}

	return RuleBasedRoutingConfigValue{
		Enabled:              enabledVal,
		OriginalCopyLocation: originalCopyLocationVal,
		state:                attr.ValueStateKnown,
	}, diags
}

func NewRuleBasedRoutingConfigValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) RuleBasedRoutingConfigValue {
	object, diags := NewRuleBasedRoutingConfigValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewRuleBasedRoutingConfigValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t RuleBasedRoutingConfigType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewRuleBasedRoutingConfigValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewRuleBasedRoutingConfigValueUnknown(), nil
	}

	if in.IsNull() {
		return NewRuleBasedRoutingConfigValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewRuleBasedRoutingConfigValueMust(RuleBasedRoutingConfigValue{}.AttributeTypes(ctx), attributes), nil
}

func (t RuleBasedRoutingConfigType) ValueType(ctx context.Context) attr.Value {
	return RuleBasedRoutingConfigValue{}
}

var _ basetypes.ObjectValuable = RuleBasedRoutingConfigValue{}

type RuleBasedRoutingConfigValue struct {
	Enabled              basetypes.BoolValue   `tfsdk:"enabled"`
	OriginalCopyLocation basetypes.ObjectValue `tfsdk:"original_copy_location"`
	state                attr.ValueState
}

func (v RuleBasedRoutingConfigValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 2)

	var val tftypes.Value
	var err error

	attrTypes["enabled"] = basetypes.BoolType{}.TerraformType(ctx)
	attrTypes["original_copy_location"] = basetypes.ObjectType{
		AttrTypes: OriginalCopyLocationValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 2)

		val, err = v.Enabled.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["enabled"] = val

		val, err = v.OriginalCopyLocation.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["original_copy_location"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v RuleBasedRoutingConfigValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v RuleBasedRoutingConfigValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v RuleBasedRoutingConfigValue) String() string {
	return "RuleBasedRoutingConfigValue"
}

func (v RuleBasedRoutingConfigValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	var originalCopyLocation basetypes.ObjectValue

	if v.OriginalCopyLocation.IsNull() {
		originalCopyLocation = types.ObjectNull(
			OriginalCopyLocationValue{}.AttributeTypes(ctx),
		)
	}

	if v.OriginalCopyLocation.IsUnknown() {
		originalCopyLocation = types.ObjectUnknown(
			OriginalCopyLocationValue{}.AttributeTypes(ctx),
		)
	}

	if !v.OriginalCopyLocation.IsNull() && !v.OriginalCopyLocation.IsUnknown() {
		originalCopyLocation = types.ObjectValueMust(
			OriginalCopyLocationValue{}.AttributeTypes(ctx),
			v.OriginalCopyLocation.Attributes(),
		)
	}

	attributeTypes := map[string]attr.Type{
		"enabled": basetypes.BoolType{},
		"original_copy_location": basetypes.ObjectType{
			AttrTypes: OriginalCopyLocationValue{}.AttributeTypes(ctx),
		},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"enabled":                v.Enabled,
			"original_copy_location": originalCopyLocation,
		})

	return objVal, diags
}

func (v RuleBasedRoutingConfigValue) Equal(o attr.Value) bool {
	other, ok := o.(RuleBasedRoutingConfigValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Enabled.Equal(other.Enabled) {
		return false
	}

	if !v.OriginalCopyLocation.Equal(other.OriginalCopyLocation) {
		return false
	}

	return true
}

func (v RuleBasedRoutingConfigValue) Type(ctx context.Context) attr.Type {
	return RuleBasedRoutingConfigType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v RuleBasedRoutingConfigValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"enabled": basetypes.BoolType{},
		"original_copy_location": basetypes.ObjectType{
			AttrTypes: OriginalCopyLocationValue{}.AttributeTypes(ctx),
		},
	}
}

var _ basetypes.ObjectTypable = OriginalCopyLocationType{}

func (t OriginalCopyLocationType) Equal(o attr.Type) bool {
	other, ok := o.(OriginalCopyLocationType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t OriginalCopyLocationType) String() string {
	return "OriginalCopyLocationType"
}

func (t OriginalCopyLocationType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	bucketNameAttribute, ok := attributes["bucket_name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`bucket_name is missing from object`)

		return nil, diags
	}

	bucketNameVal, ok := bucketNameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`bucket_name expected to be basetypes.StringValue, was: %T`, bucketNameAttribute))
	}

	customLocationAttribute, ok := attributes["custom_location"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`custom_location is missing from object`)

		return nil, diags
	}

	customLocationVal, ok := customLocationAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`custom_location expected to be basetypes.StringValue, was: %T`, customLocationAttribute))
	}

	regionAttribute, ok := attributes["region"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`region is missing from object`)

		return nil, diags
	}

	regionVal, ok := regionAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`region expected to be basetypes.StringValue, was: %T`, regionAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return nil, diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return OriginalCopyLocationValue{
		BucketName:               bucketNameVal,
		CustomLocation:           customLocationVal,
		Region:                   regionVal,
		OriginalCopyLocationType: typeVal,
		state:                    attr.ValueStateKnown,
	}, diags
}

func (t OriginalCopyLocationType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewOriginalCopyLocationValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewOriginalCopyLocationValueUnknown(), nil
	}

	if in.IsNull() {
		return NewOriginalCopyLocationValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewOriginalCopyLocationValueMust(OriginalCopyLocationValue{}.AttributeTypes(ctx), attributes), nil
}

func (t OriginalCopyLocationType) ValueType(ctx context.Context) attr.Value {
	return OriginalCopyLocationValue{}
}

var _ basetypes.ObjectValuable = OriginalCopyLocationValue{}

func (v OriginalCopyLocationValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 4)

	var val tftypes.Value
	var err error

	attrTypes["bucket_name"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["custom_location"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["region"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["type"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 4)

		val, err = v.BucketName.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["bucket_name"] = val

		val, err = v.CustomLocation.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["custom_location"] = val

		val, err = v.Region.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["region"] = val

		val, err = v.OriginalCopyLocationType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["type"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v OriginalCopyLocationValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v OriginalCopyLocationValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v OriginalCopyLocationValue) String() string {
	return "OriginalCopyLocationValue"
}

func (v OriginalCopyLocationValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributeTypes := map[string]attr.Type{
		"bucket_name":     basetypes.StringType{},
		"custom_location": basetypes.StringType{},
		"region":          basetypes.StringType{},
		"type":            basetypes.StringType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"bucket_name":     v.BucketName,
			"custom_location": v.CustomLocation,
			"region":          v.Region,
			"type":            v.OriginalCopyLocationType,
		})

	return objVal, diags
}

func (v OriginalCopyLocationValue) Equal(o attr.Value) bool {
	other, ok := o.(OriginalCopyLocationValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.BucketName.Equal(other.BucketName) {
		return false
	}

	if !v.CustomLocation.Equal(other.CustomLocation) {
		return false
	}

	if !v.Region.Equal(other.Region) {
		return false
	}

	if !v.OriginalCopyLocationType.Equal(other.OriginalCopyLocationType) {
		return false
	}

	return true
}

func (v OriginalCopyLocationValue) Type(ctx context.Context) attr.Type {
	return OriginalCopyLocationType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v OriginalCopyLocationValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"bucket_name":     basetypes.StringType{},
		"custom_location": basetypes.StringType{},
		"region":          basetypes.StringType{},
		"type":            basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = UrlRedirectType{}

type UrlRedirectType struct {
	basetypes.ObjectType
}

func (t UrlRedirectType) Equal(o attr.Type) bool {
	other, ok := o.(UrlRedirectType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t UrlRedirectType) String() string {
	return "UrlRedirectType"
}

func (t UrlRedirectType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	destinationHostnameAttribute, ok := attributes["destination_hostname"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`destination_hostname is missing from object`)

		return nil, diags
	}

	destinationHostnameVal, ok := destinationHostnameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`destination_hostname expected to be basetypes.StringValue, was: %T`, destinationHostnameAttribute))
	}

	destinationPathAttribute, ok := attributes["destination_path"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`destination_path is missing from object`)

		return nil, diags
	}

	destinationPathVal, ok := destinationPathAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`destination_path expected to be basetypes.StringValue, was: %T`, destinationPathAttribute))
	}

	destinationProtocolAttribute, ok := attributes["destination_protocol"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`destination_protocol is missing from object`)

		return nil, diags
	}

	destinationProtocolVal, ok := destinationProtocolAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`destination_protocol expected to be basetypes.StringValue, was: %T`, destinationProtocolAttribute))
	}

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return nil, diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	responseCodeAttribute, ok := attributes["response_code"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`response_code is missing from object`)

		return nil, diags
	}

	responseCodeVal, ok := responseCodeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`response_code expected to be basetypes.StringValue, was: %T`, responseCodeAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return UrlRedirectValue{
		DestinationHostname: destinationHostnameVal,
		DestinationPath:     destinationPathVal,
		DestinationProtocol: destinationProtocolVal,
		Enabled:             enabledVal,
		ResponseCode:        responseCodeVal,
		state:               attr.ValueStateKnown,
	}, diags
}

func NewUrlRedirectValueNull() UrlRedirectValue {
	return UrlRedirectValue{
		state: attr.ValueStateNull,
	}
}

func NewUrlRedirectValueUnknown() UrlRedirectValue {
	return UrlRedirectValue{
		state: attr.ValueStateUnknown,
	}
}

func NewUrlRedirectValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (UrlRedirectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing UrlRedirectValue Attribute Value",
				"While creating a UrlRedirectValue value, a missing attribute value was detected. "+
					"A UrlRedirectValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("UrlRedirectValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid UrlRedirectValue Attribute Type",
				"While creating a UrlRedirectValue value, an invalid attribute value was detected. "+
					"A UrlRedirectValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("UrlRedirectValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("UrlRedirectValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra UrlRedirectValue Attribute Value",
				"While creating a UrlRedirectValue value, an extra attribute value was detected. "+
					"A UrlRedirectValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra UrlRedirectValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewUrlRedirectValueUnknown(), diags
	}

	destinationHostnameAttribute, ok := attributes["destination_hostname"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`destination_hostname is missing from object`)

		return NewUrlRedirectValueUnknown(), diags
	}

	destinationHostnameVal, ok := destinationHostnameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`destination_hostname expected to be basetypes.StringValue, was: %T`, destinationHostnameAttribute))
	}

	destinationPathAttribute, ok := attributes["destination_path"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`destination_path is missing from object`)

		return NewUrlRedirectValueUnknown(), diags
	}

	destinationPathVal, ok := destinationPathAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`destination_path expected to be basetypes.StringValue, was: %T`, destinationPathAttribute))
	}

	destinationProtocolAttribute, ok := attributes["destination_protocol"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`destination_protocol is missing from object`)

		return NewUrlRedirectValueUnknown(), diags
	}

	destinationProtocolVal, ok := destinationProtocolAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`destination_protocol expected to be basetypes.StringValue, was: %T`, destinationProtocolAttribute))
	}

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return NewUrlRedirectValueUnknown(), diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	responseCodeAttribute, ok := attributes["response_code"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`response_code is missing from object`)

		return NewUrlRedirectValueUnknown(), diags
	}

	responseCodeVal, ok := responseCodeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`response_code expected to be basetypes.StringValue, was: %T`, responseCodeAttribute))
	}

	if diags.HasError() {
		return NewUrlRedirectValueUnknown(), diags
	}

	return UrlRedirectValue{
		DestinationHostname: destinationHostnameVal,
		DestinationPath:     destinationPathVal,
		DestinationProtocol: destinationProtocolVal,
		Enabled:             enabledVal,
		ResponseCode:        responseCodeVal,
		state:               attr.ValueStateKnown,
	}, diags
}

func NewUrlRedirectValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) UrlRedirectValue {
	object, diags := NewUrlRedirectValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewUrlRedirectValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t UrlRedirectType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewUrlRedirectValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewUrlRedirectValueUnknown(), nil
	}

	if in.IsNull() {
		return NewUrlRedirectValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewUrlRedirectValueMust(UrlRedirectValue{}.AttributeTypes(ctx), attributes), nil
}

func (t UrlRedirectType) ValueType(ctx context.Context) attr.Value {
	return UrlRedirectValue{}
}

var _ basetypes.ObjectValuable = UrlRedirectValue{}

type UrlRedirectValue struct {
	DestinationHostname basetypes.StringValue `tfsdk:"destination_hostname"`
	DestinationPath     basetypes.StringValue `tfsdk:"destination_path"`
	DestinationProtocol basetypes.StringValue `tfsdk:"destination_protocol"`
	Enabled             basetypes.BoolValue   `tfsdk:"enabled"`
	ResponseCode        basetypes.StringValue `tfsdk:"response_code"`
	state               attr.ValueState
}

func (v UrlRedirectValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 5)

	var val tftypes.Value
	var err error

	attrTypes["destination_hostname"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["destination_path"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["destination_protocol"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["enabled"] = basetypes.BoolType{}.TerraformType(ctx)
	attrTypes["response_code"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 5)

		val, err = v.DestinationHostname.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["destination_hostname"] = val

		val, err = v.DestinationPath.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["destination_path"] = val

		val, err = v.DestinationProtocol.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["destination_protocol"] = val

		val, err = v.Enabled.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["enabled"] = val

		val, err = v.ResponseCode.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["response_code"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v UrlRedirectValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v UrlRedirectValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v UrlRedirectValue) String() string {
	return "UrlRedirectValue"
}

func (v UrlRedirectValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributeTypes := map[string]attr.Type{
		"destination_hostname": basetypes.StringType{},
		"destination_path":     basetypes.StringType{},
		"destination_protocol": basetypes.StringType{},
		"enabled":              basetypes.BoolType{},
		"response_code":        basetypes.StringType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"destination_hostname": v.DestinationHostname,
			"destination_path":     v.DestinationPath,
			"destination_protocol": v.DestinationProtocol,
			"enabled":              v.Enabled,
			"response_code":        v.ResponseCode,
		})

	return objVal, diags
}

func (v UrlRedirectValue) Equal(o attr.Value) bool {
	other, ok := o.(UrlRedirectValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.DestinationHostname.Equal(other.DestinationHostname) {
		return false
	}

	if !v.DestinationPath.Equal(other.DestinationPath) {
		return false
	}

	if !v.DestinationProtocol.Equal(other.DestinationProtocol) {
		return false
	}

	if !v.Enabled.Equal(other.Enabled) {
		return false
	}

	if !v.ResponseCode.Equal(other.ResponseCode) {
		return false
	}

	return true
}

func (v UrlRedirectValue) Type(ctx context.Context) attr.Type {
	return UrlRedirectType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v UrlRedirectValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"destination_hostname": basetypes.StringType{},
		"destination_path":     basetypes.StringType{},
		"destination_protocol": basetypes.StringType{},
		"enabled":              basetypes.BoolType{},
		"response_code":        basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = UrlRewriteType{}

type UrlRewriteType struct {
	basetypes.ObjectType
}

func (t UrlRewriteType) Equal(o attr.Type) bool {
	other, ok := o.(UrlRewriteType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t UrlRewriteType) String() string {
	return "UrlRewriteType"
}

func (t UrlRewriteType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return nil, diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	rewriteTargetAttribute, ok := attributes["rewrite_target"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`rewrite_target is missing from object`)

		return nil, diags
	}

	rewriteTargetVal, ok := rewriteTargetAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`rewrite_target expected to be basetypes.StringValue, was: %T`, rewriteTargetAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return UrlRewriteValue{
		Enabled:       enabledVal,
		RewriteTarget: rewriteTargetVal,
		state:         attr.ValueStateKnown,
	}, diags
}

func NewUrlRewriteValueNull() UrlRewriteValue {
	return UrlRewriteValue{
		state: attr.ValueStateNull,
	}
}

func NewUrlRewriteValueUnknown() UrlRewriteValue {
	return UrlRewriteValue{
		state: attr.ValueStateUnknown,
	}
}

func NewUrlRewriteValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (UrlRewriteValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing UrlRewriteValue Attribute Value",
				"While creating a UrlRewriteValue value, a missing attribute value was detected. "+
					"A UrlRewriteValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("UrlRewriteValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid UrlRewriteValue Attribute Type",
				"While creating a UrlRewriteValue value, an invalid attribute value was detected. "+
					"A UrlRewriteValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("UrlRewriteValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("UrlRewriteValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra UrlRewriteValue Attribute Value",
				"While creating a UrlRewriteValue value, an extra attribute value was detected. "+
					"A UrlRewriteValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra UrlRewriteValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewUrlRewriteValueUnknown(), diags
	}

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return NewUrlRewriteValueUnknown(), diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	rewriteTargetAttribute, ok := attributes["rewrite_target"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`rewrite_target is missing from object`)

		return NewUrlRewriteValueUnknown(), diags
	}

	rewriteTargetVal, ok := rewriteTargetAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`rewrite_target expected to be basetypes.StringValue, was: %T`, rewriteTargetAttribute))
	}

	if diags.HasError() {
		return NewUrlRewriteValueUnknown(), diags
	}

	return UrlRewriteValue{
		Enabled:       enabledVal,
		RewriteTarget: rewriteTargetVal,
		state:         attr.ValueStateKnown,
	}, diags
}

func NewUrlRewriteValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) UrlRewriteValue {
	object, diags := NewUrlRewriteValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewUrlRewriteValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t UrlRewriteType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewUrlRewriteValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewUrlRewriteValueUnknown(), nil
	}

	if in.IsNull() {
		return NewUrlRewriteValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewUrlRewriteValueMust(UrlRewriteValue{}.AttributeTypes(ctx), attributes), nil
}

func (t UrlRewriteType) ValueType(ctx context.Context) attr.Value {
	return UrlRewriteValue{}
}

var _ basetypes.ObjectValuable = UrlRewriteValue{}

type UrlRewriteValue struct {
	Enabled       basetypes.BoolValue   `tfsdk:"enabled"`
	RewriteTarget basetypes.StringValue `tfsdk:"rewrite_target"`
	state         attr.ValueState
}

func (v UrlRewriteValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 2)

	var val tftypes.Value
	var err error

	attrTypes["enabled"] = basetypes.BoolType{}.TerraformType(ctx)
	attrTypes["rewrite_target"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 2)

		val, err = v.Enabled.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["enabled"] = val

		val, err = v.RewriteTarget.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["rewrite_target"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v UrlRewriteValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v UrlRewriteValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v UrlRewriteValue) String() string {
	return "UrlRewriteValue"
}

func (v UrlRewriteValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributeTypes := map[string]attr.Type{
		"enabled":        basetypes.BoolType{},
		"rewrite_target": basetypes.StringType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"enabled":        v.Enabled,
			"rewrite_target": v.RewriteTarget,
		})

	return objVal, diags
}

func (v UrlRewriteValue) Equal(o attr.Value) bool {
	other, ok := o.(UrlRewriteValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Enabled.Equal(other.Enabled) {
		return false
	}

	if !v.RewriteTarget.Equal(other.RewriteTarget) {
		return false
	}

	return true
}

func (v UrlRewriteValue) Type(ctx context.Context) attr.Type {
	return UrlRewriteType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v UrlRewriteValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"enabled":        basetypes.BoolType{},
		"rewrite_target": basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = DefaultCachingType{}

type DefaultCachingType struct {
	basetypes.ObjectType
}

func (t DefaultCachingType) Equal(o attr.Type) bool {
	other, ok := o.(DefaultCachingType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t DefaultCachingType) String() string {
	return "DefaultCachingType"
}

func (t DefaultCachingType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	cacheRevalidateConfigAttribute, ok := attributes["cache_revalidate_config"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`cache_revalidate_config is missing from object`)

		return nil, diags
	}

	cacheRevalidateConfigVal, ok := cacheRevalidateConfigAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`cache_revalidate_config expected to be basetypes.ObjectValue, was: %T`, cacheRevalidateConfigAttribute))
	}

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return nil, diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	ruleDefinitionTypeAttribute, ok := attributes["rule_definition_type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`rule_definition_type is missing from object`)

		return nil, diags
	}

	ruleDefinitionTypeVal, ok := ruleDefinitionTypeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`rule_definition_type expected to be basetypes.StringValue, was: %T`, ruleDefinitionTypeAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return DefaultCachingValue{
		CacheRevalidateConfig: cacheRevalidateConfigVal,
		Enabled:               enabledVal,
		RuleDefinitionType:    ruleDefinitionTypeVal,
		state:                 attr.ValueStateKnown,
	}, diags
}

func NewDefaultCachingValueNull() DefaultCachingValue {
	return DefaultCachingValue{
		state: attr.ValueStateNull,
	}
}

func NewDefaultCachingValueUnknown() DefaultCachingValue {
	return DefaultCachingValue{
		state: attr.ValueStateUnknown,
	}
}

func NewDefaultCachingValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (DefaultCachingValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing DefaultCachingValue Attribute Value",
				"While creating a DefaultCachingValue value, a missing attribute value was detected. "+
					"A DefaultCachingValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("DefaultCachingValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid DefaultCachingValue Attribute Type",
				"While creating a DefaultCachingValue value, an invalid attribute value was detected. "+
					"A DefaultCachingValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("DefaultCachingValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("DefaultCachingValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra DefaultCachingValue Attribute Value",
				"While creating a DefaultCachingValue value, an extra attribute value was detected. "+
					"A DefaultCachingValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra DefaultCachingValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewDefaultCachingValueUnknown(), diags
	}

	cacheRevalidateConfigAttribute, ok := attributes["cache_revalidate_config"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`cache_revalidate_config is missing from object`)

		return NewDefaultCachingValueUnknown(), diags
	}

	cacheRevalidateConfigVal, ok := cacheRevalidateConfigAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`cache_revalidate_config expected to be basetypes.ObjectValue, was: %T`, cacheRevalidateConfigAttribute))
	}

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return NewDefaultCachingValueUnknown(), diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	ruleDefinitionTypeAttribute, ok := attributes["rule_definition_type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`rule_definition_type is missing from object`)

		return NewDefaultCachingValueUnknown(), diags
	}

	ruleDefinitionTypeVal, ok := ruleDefinitionTypeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`rule_definition_type expected to be basetypes.StringValue, was: %T`, ruleDefinitionTypeAttribute))
	}

	if diags.HasError() {
		return NewDefaultCachingValueUnknown(), diags
	}

	return DefaultCachingValue{
		CacheRevalidateConfig: cacheRevalidateConfigVal,
		Enabled:               enabledVal,
		RuleDefinitionType:    ruleDefinitionTypeVal,
		state:                 attr.ValueStateKnown,
	}, diags
}

func NewDefaultCachingValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) DefaultCachingValue {
	object, diags := NewDefaultCachingValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewDefaultCachingValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t DefaultCachingType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewDefaultCachingValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewDefaultCachingValueUnknown(), nil
	}

	if in.IsNull() {
		return NewDefaultCachingValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewDefaultCachingValueMust(DefaultCachingValue{}.AttributeTypes(ctx), attributes), nil
}

func (t DefaultCachingType) ValueType(ctx context.Context) attr.Value {
	return DefaultCachingValue{}
}

var _ basetypes.ObjectValuable = DefaultCachingValue{}

type DefaultCachingValue struct {
	CacheRevalidateConfig basetypes.ObjectValue `tfsdk:"cache_revalidate_config"`
	Enabled               basetypes.BoolValue   `tfsdk:"enabled"`
	RuleDefinitionType    basetypes.StringValue `tfsdk:"rule_definition_type"`
	state                 attr.ValueState
}

func (v DefaultCachingValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 3)

	var val tftypes.Value
	var err error

	attrTypes["cache_revalidate_config"] = basetypes.ObjectType{
		AttrTypes: CacheRevalidateConfigValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["enabled"] = basetypes.BoolType{}.TerraformType(ctx)
	attrTypes["rule_definition_type"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 3)

		val, err = v.CacheRevalidateConfig.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["cache_revalidate_config"] = val

		val, err = v.Enabled.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["enabled"] = val

		val, err = v.RuleDefinitionType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["rule_definition_type"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v DefaultCachingValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v DefaultCachingValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v DefaultCachingValue) String() string {
	return "DefaultCachingValue"
}

func (v DefaultCachingValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	var cacheRevalidateConfig basetypes.ObjectValue

	if v.CacheRevalidateConfig.IsNull() {
		cacheRevalidateConfig = types.ObjectNull(
			CacheRevalidateConfigValue{}.AttributeTypes(ctx),
		)
	}

	if v.CacheRevalidateConfig.IsUnknown() {
		cacheRevalidateConfig = types.ObjectUnknown(
			CacheRevalidateConfigValue{}.AttributeTypes(ctx),
		)
	}

	if !v.CacheRevalidateConfig.IsNull() && !v.CacheRevalidateConfig.IsUnknown() {
		cacheRevalidateConfig = types.ObjectValueMust(
			CacheRevalidateConfigValue{}.AttributeTypes(ctx),
			v.CacheRevalidateConfig.Attributes(),
		)
	}

	attributeTypes := map[string]attr.Type{
		"cache_revalidate_config": basetypes.ObjectType{
			AttrTypes: CacheRevalidateConfigValue{}.AttributeTypes(ctx),
		},
		"enabled":              basetypes.BoolType{},
		"rule_definition_type": basetypes.StringType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"cache_revalidate_config": cacheRevalidateConfig,
			"enabled":                 v.Enabled,
			"rule_definition_type":    v.RuleDefinitionType,
		})

	return objVal, diags
}

func (v DefaultCachingValue) Equal(o attr.Value) bool {
	other, ok := o.(DefaultCachingValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.CacheRevalidateConfig.Equal(other.CacheRevalidateConfig) {
		return false
	}

	if !v.Enabled.Equal(other.Enabled) {
		return false
	}

	if !v.RuleDefinitionType.Equal(other.RuleDefinitionType) {
		return false
	}

	return true
}

func (v DefaultCachingValue) Type(ctx context.Context) attr.Type {
	return DefaultCachingType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v DefaultCachingValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"cache_revalidate_config": basetypes.ObjectType{
			AttrTypes: CacheRevalidateConfigValue{}.AttributeTypes(ctx),
		},
		"enabled":              basetypes.BoolType{},
		"rule_definition_type": basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = CacheRevalidateConfigType{}

type CacheRevalidateConfigType struct {
	basetypes.ObjectType
}

func NewCacheRevalidateConfigValueNull() CacheRevalidateConfigValue {
	return CacheRevalidateConfigValue{
		state: attr.ValueStateNull,
	}
}

func NewCacheRevalidateConfigValueUnknown() CacheRevalidateConfigValue {
	return CacheRevalidateConfigValue{
		state: attr.ValueStateUnknown,
	}
}

func NewCacheRevalidateConfigValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (CacheRevalidateConfigValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing CacheRevalidateConfigValue Attribute Value",
				"While creating a CacheRevalidateConfigValue value, a missing attribute value was detected. "+
					"A CacheRevalidateConfigValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("CacheRevalidateConfigValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid CacheRevalidateConfigValue Attribute Type",
				"While creating a CacheRevalidateConfigValue value, an invalid attribute value was detected. "+
					"A CacheRevalidateConfigValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("CacheRevalidateConfigValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("CacheRevalidateConfigValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra CacheRevalidateConfigValue Attribute Value",
				"While creating a CacheRevalidateConfigValue value, an extra attribute value was detected. "+
					"A CacheRevalidateConfigValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra CacheRevalidateConfigValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewCacheRevalidateConfigValueUnknown(), diags
	}

	ageAttribute, ok := attributes["age"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`age is missing from object`)

		return NewCacheRevalidateConfigValueUnknown(), diags
	}

	ageVal, ok := ageAttribute.(basetypes.Int64Value)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`age expected to be basetypes.Int64Value, was: %T`, ageAttribute))
	}

	ageTypeAttribute, ok := attributes["age_type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`age_type is missing from object`)

		return NewCacheRevalidateConfigValueUnknown(), diags
	}

	ageTypeVal, ok := ageTypeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`age_type expected to be basetypes.StringValue, was: %T`, ageTypeAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return NewCacheRevalidateConfigValueUnknown(), diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return NewCacheRevalidateConfigValueUnknown(), diags
	}

	return CacheRevalidateConfigValue{
		Age:                       ageVal,
		AgeType:                   ageTypeVal,
		CacheRevalidateConfigType: typeVal,
		state:                     attr.ValueStateKnown,
	}, diags
}

func NewCacheRevalidateConfigValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) CacheRevalidateConfigValue {
	object, diags := NewCacheRevalidateConfigValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewCacheRevalidateConfigValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

type CacheRevalidateConfigValue struct {
	Age                       basetypes.Int64Value  `tfsdk:"age"`
	AgeType                   basetypes.StringValue `tfsdk:"age_type"`
	CacheRevalidateConfigType basetypes.StringValue `tfsdk:"type"`
	state                     attr.ValueState
}

var _ basetypes.ObjectTypable = EdgeAuthType{}

type EdgeAuthType struct {
	basetypes.ObjectType
}

func (t EdgeAuthType) Equal(o attr.Type) bool {
	other, ok := o.(EdgeAuthType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t EdgeAuthType) String() string {
	return "EdgeAuthType"
}

func (t EdgeAuthType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return nil, diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	tokenKeyAttribute, ok := attributes["token_key"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`token_key is missing from object`)

		return nil, diags
	}

	tokenKeyVal, ok := tokenKeyAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`token_key expected to be basetypes.StringValue, was: %T`, tokenKeyAttribute))
	}

	tokenNameAttribute, ok := attributes["token_name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`token_name is missing from object`)

		return nil, diags
	}

	tokenNameVal, ok := tokenNameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`token_name expected to be basetypes.StringValue, was: %T`, tokenNameAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return nil, diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return EdgeAuthValue{
		Enabled:      enabledVal,
		TokenKey:     tokenKeyVal,
		TokenName:    tokenNameVal,
		EdgeAuthType: typeVal,
		state:        attr.ValueStateKnown,
	}, diags
}

func NewEdgeAuthValueNull() EdgeAuthValue {
	return EdgeAuthValue{
		state: attr.ValueStateNull,
	}
}

func NewEdgeAuthValueUnknown() EdgeAuthValue {
	return EdgeAuthValue{
		state: attr.ValueStateUnknown,
	}
}

func NewEdgeAuthValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (EdgeAuthValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing EdgeAuthValue Attribute Value",
				"While creating a EdgeAuthValue value, a missing attribute value was detected. "+
					"A EdgeAuthValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("EdgeAuthValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid EdgeAuthValue Attribute Type",
				"While creating a EdgeAuthValue value, an invalid attribute value was detected. "+
					"A EdgeAuthValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("EdgeAuthValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("EdgeAuthValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra EdgeAuthValue Attribute Value",
				"While creating a EdgeAuthValue value, an extra attribute value was detected. "+
					"A EdgeAuthValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra EdgeAuthValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewEdgeAuthValueUnknown(), diags
	}

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return NewEdgeAuthValueUnknown(), diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	tokenKeyAttribute, ok := attributes["token_key"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`token_key is missing from object`)

		return NewEdgeAuthValueUnknown(), diags
	}

	tokenKeyVal, ok := tokenKeyAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`token_key expected to be basetypes.StringValue, was: %T`, tokenKeyAttribute))
	}

	tokenNameAttribute, ok := attributes["token_name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`token_name is missing from object`)

		return NewEdgeAuthValueUnknown(), diags
	}

	tokenNameVal, ok := tokenNameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`token_name expected to be basetypes.StringValue, was: %T`, tokenNameAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return NewEdgeAuthValueUnknown(), diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return NewEdgeAuthValueUnknown(), diags
	}

	return EdgeAuthValue{
		Enabled:      enabledVal,
		TokenKey:     tokenKeyVal,
		TokenName:    tokenNameVal,
		EdgeAuthType: typeVal,
		state:        attr.ValueStateKnown,
	}, diags
}

func NewEdgeAuthValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) EdgeAuthValue {
	object, diags := NewEdgeAuthValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewEdgeAuthValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t EdgeAuthType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewEdgeAuthValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewEdgeAuthValueUnknown(), nil
	}

	if in.IsNull() {
		return NewEdgeAuthValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewEdgeAuthValueMust(EdgeAuthValue{}.AttributeTypes(ctx), attributes), nil
}

func (t EdgeAuthType) ValueType(ctx context.Context) attr.Value {
	return EdgeAuthValue{}
}

var _ basetypes.ObjectValuable = EdgeAuthValue{}

type EdgeAuthValue struct {
	Enabled      basetypes.BoolValue   `tfsdk:"enabled"`
	TokenKey     basetypes.StringValue `tfsdk:"token_key"`
	TokenName    basetypes.StringValue `tfsdk:"token_name"`
	EdgeAuthType basetypes.StringValue `tfsdk:"type"`
	state        attr.ValueState
}

func (v EdgeAuthValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 4)

	var val tftypes.Value
	var err error

	attrTypes["enabled"] = basetypes.BoolType{}.TerraformType(ctx)
	attrTypes["token_key"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["token_name"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["type"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 4)

		val, err = v.Enabled.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["enabled"] = val

		val, err = v.TokenKey.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["token_key"] = val

		val, err = v.TokenName.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["token_name"] = val

		val, err = v.EdgeAuthType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["type"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v EdgeAuthValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v EdgeAuthValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v EdgeAuthValue) String() string {
	return "EdgeAuthValue"
}

func (v EdgeAuthValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributeTypes := map[string]attr.Type{
		"enabled":    basetypes.BoolType{},
		"token_key":  basetypes.StringType{},
		"token_name": basetypes.StringType{},
		"type":       basetypes.StringType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"enabled":    v.Enabled,
			"token_key":  v.TokenKey,
			"token_name": v.TokenName,
			"type":       v.EdgeAuthType,
		})

	return objVal, diags
}

func (v EdgeAuthValue) Equal(o attr.Value) bool {
	other, ok := o.(EdgeAuthValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Enabled.Equal(other.Enabled) {
		return false
	}

	if !v.TokenKey.Equal(other.TokenKey) {
		return false
	}

	if !v.TokenName.Equal(other.TokenName) {
		return false
	}

	if !v.EdgeAuthType.Equal(other.EdgeAuthType) {
		return false
	}

	return true
}

func (v EdgeAuthValue) Type(ctx context.Context) attr.Type {
	return EdgeAuthType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v EdgeAuthValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"enabled":    basetypes.BoolType{},
		"token_key":  basetypes.StringType{},
		"token_name": basetypes.StringType{},
		"type":       basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = DistributionConfigType{}

type DistributionConfigType struct {
	basetypes.ObjectType
}

func (t DistributionConfigType) Equal(o attr.Type) bool {
	other, ok := o.(DistributionConfigType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t DistributionConfigType) String() string {
	return "DistributionConfigType"
}

func (t DistributionConfigType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	edgeLoggingAttribute, ok := attributes["edge_logging"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`edge_logging is missing from object`)

		return nil, diags
	}

	edgeLoggingVal, ok := edgeLoggingAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`edge_logging expected to be basetypes.ObjectValue, was: %T`, edgeLoggingAttribute))
	}

	protocolTypeAttribute, ok := attributes["protocol_type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`protocol_type is missing from object`)

		return nil, diags
	}

	protocolTypeVal, ok := protocolTypeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`protocol_type expected to be basetypes.StringValue, was: %T`, protocolTypeAttribute))
	}

	regionTypeAttribute, ok := attributes["region_type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`region_type is missing from object`)

		return nil, diags
	}

	regionTypeVal, ok := regionTypeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`region_type expected to be basetypes.StringValue, was: %T`, regionTypeAttribute))
	}

	serviceDomainAttribute, ok := attributes["service_domain"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`service_domain is missing from object`)

		return nil, diags
	}

	serviceDomainVal, ok := serviceDomainAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`service_domain expected to be basetypes.ObjectValue, was: %T`, serviceDomainAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return DistributionConfigValue{
		EdgeLogging:   edgeLoggingVal,
		ProtocolType:  protocolTypeVal,
		RegionType:    regionTypeVal,
		ServiceDomain: serviceDomainVal,
		state:         attr.ValueStateKnown,
	}, diags
}

func NewDistributionConfigValueNull() DistributionConfigValue {
	return DistributionConfigValue{
		state: attr.ValueStateNull,
	}
}

func NewDistributionConfigValueUnknown() DistributionConfigValue {
	return DistributionConfigValue{
		state: attr.ValueStateUnknown,
	}
}

func NewDistributionConfigValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (DistributionConfigValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing DistributionConfigValue Attribute Value",
				"While creating a DistributionConfigValue value, a missing attribute value was detected. "+
					"A DistributionConfigValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("DistributionConfigValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid DistributionConfigValue Attribute Type",
				"While creating a DistributionConfigValue value, an invalid attribute value was detected. "+
					"A DistributionConfigValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("DistributionConfigValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("DistributionConfigValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra DistributionConfigValue Attribute Value",
				"While creating a DistributionConfigValue value, an extra attribute value was detected. "+
					"A DistributionConfigValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra DistributionConfigValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewDistributionConfigValueUnknown(), diags
	}

	edgeLoggingAttribute, ok := attributes["edge_logging"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`edge_logging is missing from object`)

		return NewDistributionConfigValueUnknown(), diags
	}

	edgeLoggingVal, ok := edgeLoggingAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`edge_logging expected to be basetypes.ObjectValue, was: %T`, edgeLoggingAttribute))
	}

	protocolTypeAttribute, ok := attributes["protocol_type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`protocol_type is missing from object`)

		return NewDistributionConfigValueUnknown(), diags
	}

	protocolTypeVal, ok := protocolTypeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`protocol_type expected to be basetypes.StringValue, was: %T`, protocolTypeAttribute))
	}

	regionTypeAttribute, ok := attributes["region_type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`region_type is missing from object`)

		return NewDistributionConfigValueUnknown(), diags
	}

	regionTypeVal, ok := regionTypeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`region_type expected to be basetypes.StringValue, was: %T`, regionTypeAttribute))
	}

	serviceDomainAttribute, ok := attributes["service_domain"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`service_domain is missing from object`)

		return NewDistributionConfigValueUnknown(), diags
	}

	serviceDomainVal, ok := serviceDomainAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`service_domain expected to be basetypes.ObjectValue, was: %T`, serviceDomainAttribute))
	}

	if diags.HasError() {
		return NewDistributionConfigValueUnknown(), diags
	}

	return DistributionConfigValue{
		EdgeLogging:   edgeLoggingVal,
		ProtocolType:  protocolTypeVal,
		RegionType:    regionTypeVal,
		ServiceDomain: serviceDomainVal,
		state:         attr.ValueStateKnown,
	}, diags
}

func NewDistributionConfigValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) DistributionConfigValue {
	object, diags := NewDistributionConfigValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewDistributionConfigValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t DistributionConfigType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewDistributionConfigValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewDistributionConfigValueUnknown(), nil
	}

	if in.IsNull() {
		return NewDistributionConfigValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewDistributionConfigValueMust(DistributionConfigValue{}.AttributeTypes(ctx), attributes), nil
}

func (t DistributionConfigType) ValueType(ctx context.Context) attr.Value {
	return DistributionConfigValue{}
}

var _ basetypes.ObjectValuable = DistributionConfigValue{}

type DistributionConfigValue struct {
	EdgeLogging   basetypes.ObjectValue `tfsdk:"edge_logging"`
	ProtocolType  basetypes.StringValue `tfsdk:"protocol_type"`
	RegionType    basetypes.StringValue `tfsdk:"region_type"`
	ServiceDomain basetypes.ObjectValue `tfsdk:"service_domain"`
	state         attr.ValueState
}

func (v DistributionConfigValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 4)

	var val tftypes.Value
	var err error

	attrTypes["edge_logging"] = basetypes.ObjectType{
		AttrTypes: EdgeLoggingValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["protocol_type"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["region_type"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["service_domain"] = basetypes.ObjectType{
		AttrTypes: ServiceDomainValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 4)

		val, err = v.EdgeLogging.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["edge_logging"] = val

		val, err = v.ProtocolType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["protocol_type"] = val

		val, err = v.RegionType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["region_type"] = val

		val, err = v.ServiceDomain.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["service_domain"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v DistributionConfigValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v DistributionConfigValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v DistributionConfigValue) String() string {
	return "DistributionConfigValue"
}

func (v DistributionConfigValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	var edgeLogging basetypes.ObjectValue

	if v.EdgeLogging.IsNull() {
		edgeLogging = types.ObjectNull(
			EdgeLoggingValue{}.AttributeTypes(ctx),
		)
	}

	if v.EdgeLogging.IsUnknown() {
		edgeLogging = types.ObjectUnknown(
			EdgeLoggingValue{}.AttributeTypes(ctx),
		)
	}

	if !v.EdgeLogging.IsNull() && !v.EdgeLogging.IsUnknown() {
		edgeLogging = types.ObjectValueMust(
			EdgeLoggingValue{}.AttributeTypes(ctx),
			v.EdgeLogging.Attributes(),
		)
	}

	var serviceDomain basetypes.ObjectValue

	if v.ServiceDomain.IsNull() {
		serviceDomain = types.ObjectNull(
			ServiceDomainValue{}.AttributeTypes(ctx),
		)
	}

	if v.ServiceDomain.IsUnknown() {
		serviceDomain = types.ObjectUnknown(
			ServiceDomainValue{}.AttributeTypes(ctx),
		)
	}

	if !v.ServiceDomain.IsNull() && !v.ServiceDomain.IsUnknown() {
		serviceDomain = types.ObjectValueMust(
			ServiceDomainValue{}.AttributeTypes(ctx),
			v.ServiceDomain.Attributes(),
		)
	}

	attributeTypes := map[string]attr.Type{
		"edge_logging": basetypes.ObjectType{
			AttrTypes: EdgeLoggingValue{}.AttributeTypes(ctx),
		},
		"protocol_type": basetypes.StringType{},
		"region_type":   basetypes.StringType{},
		"service_domain": basetypes.ObjectType{
			AttrTypes: ServiceDomainValue{}.AttributeTypes(ctx),
		},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"edge_logging":   edgeLogging,
			"protocol_type":  v.ProtocolType,
			"region_type":    v.RegionType,
			"service_domain": serviceDomain,
		})

	return objVal, diags
}

func (v DistributionConfigValue) Equal(o attr.Value) bool {
	other, ok := o.(DistributionConfigValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.EdgeLogging.Equal(other.EdgeLogging) {
		return false
	}

	if !v.ProtocolType.Equal(other.ProtocolType) {
		return false
	}

	if !v.RegionType.Equal(other.RegionType) {
		return false
	}

	if !v.ServiceDomain.Equal(other.ServiceDomain) {
		return false
	}

	return true
}

func (v DistributionConfigValue) Type(ctx context.Context) attr.Type {
	return DistributionConfigType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v DistributionConfigValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"edge_logging": basetypes.ObjectType{
			AttrTypes: EdgeLoggingValue{}.AttributeTypes(ctx),
		},
		"protocol_type": basetypes.StringType{},
		"region_type":   basetypes.StringType{},
		"service_domain": basetypes.ObjectType{
			AttrTypes: ServiceDomainValue{}.AttributeTypes(ctx),
		},
	}
}

var _ basetypes.ObjectTypable = EdgeLoggingType{}

type EdgeLoggingType struct {
	basetypes.ObjectType
}

func (t EdgeLoggingType) Equal(o attr.Type) bool {
	other, ok := o.(EdgeLoggingType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t EdgeLoggingType) String() string {
	return "EdgeLoggingType"
}

func (t EdgeLoggingType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	bucketPrefixAttribute, ok := attributes["bucket_prefix"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`bucket_prefix is missing from object`)

		return nil, diags
	}

	bucketPrefixVal, ok := bucketPrefixAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`bucket_prefix expected to be basetypes.StringValue, was: %T`, bucketPrefixAttribute))
	}

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return nil, diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	objectStorageAttribute, ok := attributes["object_storage"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`object_storage is missing from object`)

		return nil, diags
	}

	objectStorageVal, ok := objectStorageAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`object_storage expected to be basetypes.ObjectValue, was: %T`, objectStorageAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return EdgeLoggingValue{
		BucketPrefix:  bucketPrefixVal,
		Enabled:       enabledVal,
		ObjectStorage: objectStorageVal,
		state:         attr.ValueStateKnown,
	}, diags
}

func NewEdgeLoggingValueNull() EdgeLoggingValue {
	return EdgeLoggingValue{
		state: attr.ValueStateNull,
	}
}

func NewEdgeLoggingValueUnknown() EdgeLoggingValue {
	return EdgeLoggingValue{
		state: attr.ValueStateUnknown,
	}
}

func NewEdgeLoggingValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (EdgeLoggingValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing EdgeLoggingValue Attribute Value",
				"While creating a EdgeLoggingValue value, a missing attribute value was detected. "+
					"A EdgeLoggingValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("EdgeLoggingValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid EdgeLoggingValue Attribute Type",
				"While creating a EdgeLoggingValue value, an invalid attribute value was detected. "+
					"A EdgeLoggingValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("EdgeLoggingValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("EdgeLoggingValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra EdgeLoggingValue Attribute Value",
				"While creating a EdgeLoggingValue value, an extra attribute value was detected. "+
					"A EdgeLoggingValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra EdgeLoggingValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewEdgeLoggingValueUnknown(), diags
	}

	bucketPrefixAttribute, ok := attributes["bucket_prefix"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`bucket_prefix is missing from object`)

		return NewEdgeLoggingValueUnknown(), diags
	}

	bucketPrefixVal, ok := bucketPrefixAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`bucket_prefix expected to be basetypes.StringValue, was: %T`, bucketPrefixAttribute))
	}

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return NewEdgeLoggingValueUnknown(), diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	objectStorageAttribute, ok := attributes["object_storage"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`object_storage is missing from object`)

		return NewEdgeLoggingValueUnknown(), diags
	}

	objectStorageVal, ok := objectStorageAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`object_storage expected to be basetypes.ObjectValue, was: %T`, objectStorageAttribute))
	}

	if diags.HasError() {
		return NewEdgeLoggingValueUnknown(), diags
	}

	return EdgeLoggingValue{
		BucketPrefix:  bucketPrefixVal,
		Enabled:       enabledVal,
		ObjectStorage: objectStorageVal,
		state:         attr.ValueStateKnown,
	}, diags
}

func NewEdgeLoggingValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) EdgeLoggingValue {
	object, diags := NewEdgeLoggingValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewEdgeLoggingValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t EdgeLoggingType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewEdgeLoggingValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewEdgeLoggingValueUnknown(), nil
	}

	if in.IsNull() {
		return NewEdgeLoggingValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewEdgeLoggingValueMust(EdgeLoggingValue{}.AttributeTypes(ctx), attributes), nil
}

func (t EdgeLoggingType) ValueType(ctx context.Context) attr.Value {
	return EdgeLoggingValue{}
}

var _ basetypes.ObjectValuable = EdgeLoggingValue{}

type EdgeLoggingValue struct {
	BucketPrefix  basetypes.StringValue `tfsdk:"bucket_prefix"`
	Enabled       basetypes.BoolValue   `tfsdk:"enabled"`
	ObjectStorage basetypes.ObjectValue `tfsdk:"object_storage"`
	state         attr.ValueState
}

func (v EdgeLoggingValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 3)

	var val tftypes.Value
	var err error

	attrTypes["bucket_prefix"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["enabled"] = basetypes.BoolType{}.TerraformType(ctx)
	attrTypes["object_storage"] = basetypes.ObjectType{
		AttrTypes: ObjectStorageValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 3)

		val, err = v.BucketPrefix.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["bucket_prefix"] = val

		val, err = v.Enabled.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["enabled"] = val

		val, err = v.ObjectStorage.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["object_storage"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v EdgeLoggingValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v EdgeLoggingValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v EdgeLoggingValue) String() string {
	return "EdgeLoggingValue"
}

func (v EdgeLoggingValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	var objectStorage basetypes.ObjectValue

	if v.ObjectStorage.IsNull() {
		objectStorage = types.ObjectNull(
			ObjectStorageValue{}.AttributeTypes(ctx),
		)
	}

	if v.ObjectStorage.IsUnknown() {
		objectStorage = types.ObjectUnknown(
			ObjectStorageValue{}.AttributeTypes(ctx),
		)
	}

	if !v.ObjectStorage.IsNull() && !v.ObjectStorage.IsUnknown() {
		objectStorage = types.ObjectValueMust(
			ObjectStorageValue{}.AttributeTypes(ctx),
			v.ObjectStorage.Attributes(),
		)
	}

	attributeTypes := map[string]attr.Type{
		"bucket_prefix": basetypes.StringType{},
		"enabled":       basetypes.BoolType{},
		"object_storage": basetypes.ObjectType{
			AttrTypes: ObjectStorageValue{}.AttributeTypes(ctx),
		},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"bucket_prefix":  v.BucketPrefix,
			"enabled":        v.Enabled,
			"object_storage": objectStorage,
		})

	return objVal, diags
}

func (v EdgeLoggingValue) Equal(o attr.Value) bool {
	other, ok := o.(EdgeLoggingValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.BucketPrefix.Equal(other.BucketPrefix) {
		return false
	}

	if !v.Enabled.Equal(other.Enabled) {
		return false
	}

	if !v.ObjectStorage.Equal(other.ObjectStorage) {
		return false
	}

	return true
}

func (v EdgeLoggingValue) Type(ctx context.Context) attr.Type {
	return EdgeLoggingType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v EdgeLoggingValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"bucket_prefix": basetypes.StringType{},
		"enabled":       basetypes.BoolType{},
		"object_storage": basetypes.ObjectType{
			AttrTypes: ObjectStorageValue{}.AttributeTypes(ctx),
		},
	}
}

var _ basetypes.ObjectTypable = ObjectStorageType{}

type ObjectStorageType struct {
	basetypes.ObjectType
}

func (t ObjectStorageType) Equal(o attr.Type) bool {
	other, ok := o.(ObjectStorageType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t ObjectStorageType) String() string {
	return "ObjectStorageType"
}

func (t ObjectStorageType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	bucketNameAttribute, ok := attributes["bucket_name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`bucket_name is missing from object`)

		return nil, diags
	}

	bucketNameVal, ok := bucketNameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`bucket_name expected to be basetypes.StringValue, was: %T`, bucketNameAttribute))
	}

	regionAttribute, ok := attributes["region"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`region is missing from object`)

		return nil, diags
	}

	regionVal, ok := regionAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`region expected to be basetypes.StringValue, was: %T`, regionAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return ObjectStorageValue{
		BucketName: bucketNameVal,
		Region:     regionVal,
		state:      attr.ValueStateKnown,
	}, diags
}

func NewObjectStorageValueNull() ObjectStorageValue {
	return ObjectStorageValue{
		state: attr.ValueStateNull,
	}
}

func NewObjectStorageValueUnknown() ObjectStorageValue {
	return ObjectStorageValue{
		state: attr.ValueStateUnknown,
	}
}

func NewObjectStorageValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (ObjectStorageValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing ObjectStorageValue Attribute Value",
				"While creating a ObjectStorageValue value, a missing attribute value was detected. "+
					"A ObjectStorageValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("ObjectStorageValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid ObjectStorageValue Attribute Type",
				"While creating a ObjectStorageValue value, an invalid attribute value was detected. "+
					"A ObjectStorageValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("ObjectStorageValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("ObjectStorageValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra ObjectStorageValue Attribute Value",
				"While creating a ObjectStorageValue value, an extra attribute value was detected. "+
					"A ObjectStorageValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra ObjectStorageValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewObjectStorageValueUnknown(), diags
	}

	bucketNameAttribute, ok := attributes["bucket_name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`bucket_name is missing from object`)

		return NewObjectStorageValueUnknown(), diags
	}

	bucketNameVal, ok := bucketNameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`bucket_name expected to be basetypes.StringValue, was: %T`, bucketNameAttribute))
	}

	regionAttribute, ok := attributes["region"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`region is missing from object`)

		return NewObjectStorageValueUnknown(), diags
	}

	regionVal, ok := regionAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`region expected to be basetypes.StringValue, was: %T`, regionAttribute))
	}

	if diags.HasError() {
		return NewObjectStorageValueUnknown(), diags
	}

	return ObjectStorageValue{
		BucketName: bucketNameVal,
		Region:     regionVal,
		state:      attr.ValueStateKnown,
	}, diags
}

func NewObjectStorageValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) ObjectStorageValue {
	object, diags := NewObjectStorageValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewObjectStorageValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t ObjectStorageType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewObjectStorageValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewObjectStorageValueUnknown(), nil
	}

	if in.IsNull() {
		return NewObjectStorageValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewObjectStorageValueMust(ObjectStorageValue{}.AttributeTypes(ctx), attributes), nil
}

func (t ObjectStorageType) ValueType(ctx context.Context) attr.Value {
	return ObjectStorageValue{}
}

var _ basetypes.ObjectValuable = ObjectStorageValue{}

type ObjectStorageValue struct {
	BucketName basetypes.StringValue `tfsdk:"bucket_name"`
	Region     basetypes.StringValue `tfsdk:"region"`
	state      attr.ValueState
}

func (v ObjectStorageValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 2)

	var val tftypes.Value
	var err error

	attrTypes["bucket_name"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["region"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 2)

		val, err = v.BucketName.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["bucket_name"] = val

		val, err = v.Region.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["region"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v ObjectStorageValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v ObjectStorageValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v ObjectStorageValue) String() string {
	return "ObjectStorageValue"
}

func (v ObjectStorageValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributeTypes := map[string]attr.Type{
		"bucket_name": basetypes.StringType{},
		"region":      basetypes.StringType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"bucket_name": v.BucketName,
			"region":      v.Region,
		})

	return objVal, diags
}

func (v ObjectStorageValue) Equal(o attr.Value) bool {
	other, ok := o.(ObjectStorageValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.BucketName.Equal(other.BucketName) {
		return false
	}

	if !v.Region.Equal(other.Region) {
		return false
	}

	return true
}

func (v ObjectStorageValue) Type(ctx context.Context) attr.Type {
	return ObjectStorageType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v ObjectStorageValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"bucket_name": basetypes.StringType{},
		"region":      basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = ServiceDomainType{}

type ServiceDomainType struct {
	basetypes.ObjectType
}

func (t ServiceDomainType) Equal(o attr.Type) bool {
	other, ok := o.(ServiceDomainType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t ServiceDomainType) String() string {
	return "ServiceDomainType"
}

func (t ServiceDomainType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	certificateAttribute, ok := attributes["certificate"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`certificate is missing from object`)

		return nil, diags
	}

	certificateVal, ok := certificateAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`certificate expected to be basetypes.ObjectValue, was: %T`, certificateAttribute))
	}

	domainNameAttribute, ok := attributes["domain_name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`domain_name is missing from object`)

		return nil, diags
	}

	domainNameVal, ok := domainNameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`domain_name expected to be basetypes.StringValue, was: %T`, domainNameAttribute))
	}

	domainTypeAttribute, ok := attributes["domain_type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`domain_type is missing from object`)

		return nil, diags
	}

	domainTypeVal, ok := domainTypeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`domain_type expected to be basetypes.StringValue, was: %T`, domainTypeAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return ServiceDomainValue{
		Certificate: certificateVal,
		DomainName:  domainNameVal,
		DomainType:  domainTypeVal,
		state:       attr.ValueStateKnown,
	}, diags
}

func NewServiceDomainValueNull() ServiceDomainValue {
	return ServiceDomainValue{
		state: attr.ValueStateNull,
	}
}

func NewServiceDomainValueUnknown() ServiceDomainValue {
	return ServiceDomainValue{
		state: attr.ValueStateUnknown,
	}
}

func NewServiceDomainValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (ServiceDomainValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing ServiceDomainValue Attribute Value",
				"While creating a ServiceDomainValue value, a missing attribute value was detected. "+
					"A ServiceDomainValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("ServiceDomainValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid ServiceDomainValue Attribute Type",
				"While creating a ServiceDomainValue value, an invalid attribute value was detected. "+
					"A ServiceDomainValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("ServiceDomainValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("ServiceDomainValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra ServiceDomainValue Attribute Value",
				"While creating a ServiceDomainValue value, an extra attribute value was detected. "+
					"A ServiceDomainValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra ServiceDomainValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewServiceDomainValueUnknown(), diags
	}

	certificateAttribute, ok := attributes["certificate"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`certificate is missing from object`)

		return NewServiceDomainValueUnknown(), diags
	}

	certificateVal, ok := certificateAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`certificate expected to be basetypes.ObjectValue, was: %T`, certificateAttribute))
	}

	domainNameAttribute, ok := attributes["domain_name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`domain_name is missing from object`)

		return NewServiceDomainValueUnknown(), diags
	}

	domainNameVal, ok := domainNameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`domain_name expected to be basetypes.StringValue, was: %T`, domainNameAttribute))
	}

	domainTypeAttribute, ok := attributes["domain_type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`domain_type is missing from object`)

		return NewServiceDomainValueUnknown(), diags
	}

	domainTypeVal, ok := domainTypeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`domain_type expected to be basetypes.StringValue, was: %T`, domainTypeAttribute))
	}

	if diags.HasError() {
		return NewServiceDomainValueUnknown(), diags
	}

	return ServiceDomainValue{
		Certificate: certificateVal,
		DomainName:  domainNameVal,
		DomainType:  domainTypeVal,
		state:       attr.ValueStateKnown,
	}, diags
}

func NewServiceDomainValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) ServiceDomainValue {
	object, diags := NewServiceDomainValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewServiceDomainValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t ServiceDomainType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewServiceDomainValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewServiceDomainValueUnknown(), nil
	}

	if in.IsNull() {
		return NewServiceDomainValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewServiceDomainValueMust(ServiceDomainValue{}.AttributeTypes(ctx), attributes), nil
}

func (t ServiceDomainType) ValueType(ctx context.Context) attr.Value {
	return ServiceDomainValue{}
}

var _ basetypes.ObjectValuable = ServiceDomainValue{}

type ServiceDomainValue struct {
	Certificate basetypes.ObjectValue `tfsdk:"certificate"`
	DomainName  basetypes.StringValue `tfsdk:"domain_name"`
	DomainType  basetypes.StringValue `tfsdk:"domain_type"`
	state       attr.ValueState
}

func (v ServiceDomainValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 3)

	var val tftypes.Value
	var err error

	attrTypes["certificate"] = basetypes.ObjectType{
		AttrTypes: CertificateValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["domain_name"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["domain_type"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 3)

		val, err = v.Certificate.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["certificate"] = val

		val, err = v.DomainName.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["domain_name"] = val

		val, err = v.DomainType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["domain_type"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v ServiceDomainValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v ServiceDomainValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v ServiceDomainValue) String() string {
	return "ServiceDomainValue"
}

func (v ServiceDomainValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	var certificate basetypes.ObjectValue

	if v.Certificate.IsNull() {
		certificate = types.ObjectNull(
			CertificateValue{}.AttributeTypes(ctx),
		)
	}

	if v.Certificate.IsUnknown() {
		certificate = types.ObjectUnknown(
			CertificateValue{}.AttributeTypes(ctx),
		)
	}

	if !v.Certificate.IsNull() && !v.Certificate.IsUnknown() {
		certificate = types.ObjectValueMust(
			CertificateValue{}.AttributeTypes(ctx),
			v.Certificate.Attributes(),
		)
	}

	attributeTypes := map[string]attr.Type{
		"certificate": basetypes.ObjectType{
			AttrTypes: CertificateValue{}.AttributeTypes(ctx),
		},
		"domain_name": basetypes.StringType{},
		"domain_type": basetypes.StringType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"certificate": certificate,
			"domain_name": v.DomainName,
			"domain_type": v.DomainType,
		})

	return objVal, diags
}

func (v ServiceDomainValue) Equal(o attr.Value) bool {
	other, ok := o.(ServiceDomainValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Certificate.Equal(other.Certificate) {
		return false
	}

	if !v.DomainName.Equal(other.DomainName) {
		return false
	}

	if !v.DomainType.Equal(other.DomainType) {
		return false
	}

	return true
}

func (v ServiceDomainValue) Type(ctx context.Context) attr.Type {
	return ServiceDomainType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v ServiceDomainValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"certificate": basetypes.ObjectType{
			AttrTypes: CertificateValue{}.AttributeTypes(ctx),
		},
		"domain_name": basetypes.StringType{},
		"domain_type": basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = CertificateType{}

type CertificateType struct {
	basetypes.ObjectType
}

func (t CertificateType) Equal(o attr.Type) bool {
	other, ok := o.(CertificateType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t CertificateType) String() string {
	return "CertificateType"
}

func (t CertificateType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	domainAttribute, ok := attributes["domain"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`domain is missing from object`)

		return nil, diags
	}

	domainVal, ok := domainAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`domain expected to be basetypes.StringValue, was: %T`, domainAttribute))
	}

	expiryDateAttribute, ok := attributes["expiry_date"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`expiry_date is missing from object`)

		return nil, diags
	}

	expiryDateVal, ok := expiryDateAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`expiry_date expected to be basetypes.StringValue, was: %T`, expiryDateAttribute))
	}

	idAttribute, ok := attributes["id"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`id is missing from object`)

		return nil, diags
	}

	idVal, ok := idAttribute.(basetypes.Int64Value)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`id expected to be basetypes.Int64Value, was: %T`, idAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return CertificateValue{
		Domain:     domainVal,
		ExpiryDate: expiryDateVal,
		Id:         idVal,
		state:      attr.ValueStateKnown,
	}, diags
}

func NewCertificateValueNull() CertificateValue {
	return CertificateValue{
		state: attr.ValueStateNull,
	}
}

func NewCertificateValueUnknown() CertificateValue {
	return CertificateValue{
		state: attr.ValueStateUnknown,
	}
}

func NewCertificateValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (CertificateValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing CertificateValue Attribute Value",
				"While creating a CertificateValue value, a missing attribute value was detected. "+
					"A CertificateValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("CertificateValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid CertificateValue Attribute Type",
				"While creating a CertificateValue value, an invalid attribute value was detected. "+
					"A CertificateValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("CertificateValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("CertificateValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra CertificateValue Attribute Value",
				"While creating a CertificateValue value, an extra attribute value was detected. "+
					"A CertificateValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra CertificateValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewCertificateValueUnknown(), diags
	}

	domainAttribute, ok := attributes["domain"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`domain is missing from object`)

		return NewCertificateValueUnknown(), diags
	}

	domainVal, ok := domainAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`domain expected to be basetypes.StringValue, was: %T`, domainAttribute))
	}

	expiryDateAttribute, ok := attributes["expiry_date"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`expiry_date is missing from object`)

		return NewCertificateValueUnknown(), diags
	}

	expiryDateVal, ok := expiryDateAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`expiry_date expected to be basetypes.StringValue, was: %T`, expiryDateAttribute))
	}

	idAttribute, ok := attributes["id"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`id is missing from object`)

		return NewCertificateValueUnknown(), diags
	}

	idVal, ok := idAttribute.(basetypes.Int64Value)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`id expected to be basetypes.Int64Value, was: %T`, idAttribute))
	}

	if diags.HasError() {
		return NewCertificateValueUnknown(), diags
	}

	return CertificateValue{
		Domain:     domainVal,
		ExpiryDate: expiryDateVal,
		Id:         idVal,
		state:      attr.ValueStateKnown,
	}, diags
}

func NewCertificateValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) CertificateValue {
	object, diags := NewCertificateValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewCertificateValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t CertificateType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewCertificateValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewCertificateValueUnknown(), nil
	}

	if in.IsNull() {
		return NewCertificateValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewCertificateValueMust(CertificateValue{}.AttributeTypes(ctx), attributes), nil
}

func (t CertificateType) ValueType(ctx context.Context) attr.Value {
	return CertificateValue{}
}

var _ basetypes.ObjectValuable = CertificateValue{}

type CertificateValue struct {
	Domain     basetypes.StringValue `tfsdk:"domain"`
	ExpiryDate basetypes.StringValue `tfsdk:"expiry_date"`
	Id         basetypes.Int64Value  `tfsdk:"id"`
	state      attr.ValueState
}

func (v CertificateValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 3)

	var val tftypes.Value
	var err error

	attrTypes["domain"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["expiry_date"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["id"] = basetypes.Int64Type{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 3)

		val, err = v.Domain.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["domain"] = val

		val, err = v.ExpiryDate.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["expiry_date"] = val

		val, err = v.Id.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["id"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v CertificateValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v CertificateValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v CertificateValue) String() string {
	return "CertificateValue"
}

func (v CertificateValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributeTypes := map[string]attr.Type{
		"domain":      basetypes.StringType{},
		"expiry_date": basetypes.StringType{},
		"id":          basetypes.Int64Type{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"domain":      v.Domain,
			"expiry_date": v.ExpiryDate,
			"id":          v.Id,
		})

	return objVal, diags
}

func (v CertificateValue) Equal(o attr.Value) bool {
	other, ok := o.(CertificateValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Domain.Equal(other.Domain) {
		return false
	}

	if !v.ExpiryDate.Equal(other.ExpiryDate) {
		return false
	}

	if !v.Id.Equal(other.Id) {
		return false
	}

	return true
}

func (v CertificateValue) Type(ctx context.Context) attr.Type {
	return CertificateType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v CertificateValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"domain":      basetypes.StringType{},
		"expiry_date": basetypes.StringType{},
		"id":          basetypes.Int64Type{},
	}
}

var _ basetypes.ObjectTypable = HeaderPoliciesType{}

type HeaderPoliciesType struct {
	basetypes.ObjectType
}

func (t HeaderPoliciesType) Equal(o attr.Type) bool {
	other, ok := o.(HeaderPoliciesType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t HeaderPoliciesType) String() string {
	return "HeaderPoliciesType"
}

func (t HeaderPoliciesType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	headerAttribute, ok := attributes["header"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`header is missing from object`)

		return nil, diags
	}

	headerVal, ok := headerAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`header expected to be basetypes.ObjectValue, was: %T`, headerAttribute))
	}

	ruleNameAttribute, ok := attributes["rule_name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`rule_name is missing from object`)

		return nil, diags
	}

	ruleNameVal, ok := ruleNameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`rule_name expected to be basetypes.StringValue, was: %T`, ruleNameAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return nil, diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return HeaderPoliciesValue{
		Header:             headerVal,
		RuleName:           ruleNameVal,
		HeaderPoliciesType: typeVal,
		state:              attr.ValueStateKnown,
	}, diags
}

func NewHeaderPoliciesValueNull() HeaderPoliciesValue {
	return HeaderPoliciesValue{
		state: attr.ValueStateNull,
	}
}

func NewHeaderPoliciesValueUnknown() HeaderPoliciesValue {
	return HeaderPoliciesValue{
		state: attr.ValueStateUnknown,
	}
}

func NewHeaderPoliciesValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (HeaderPoliciesValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing HeaderPoliciesValue Attribute Value",
				"While creating a HeaderPoliciesValue value, a missing attribute value was detected. "+
					"A HeaderPoliciesValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("HeaderPoliciesValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid HeaderPoliciesValue Attribute Type",
				"While creating a HeaderPoliciesValue value, an invalid attribute value was detected. "+
					"A HeaderPoliciesValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("HeaderPoliciesValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("HeaderPoliciesValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra HeaderPoliciesValue Attribute Value",
				"While creating a HeaderPoliciesValue value, an extra attribute value was detected. "+
					"A HeaderPoliciesValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra HeaderPoliciesValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewHeaderPoliciesValueUnknown(), diags
	}

	headerAttribute, ok := attributes["header"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`header is missing from object`)

		return NewHeaderPoliciesValueUnknown(), diags
	}

	headerVal, ok := headerAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`header expected to be basetypes.ObjectValue, was: %T`, headerAttribute))
	}

	ruleNameAttribute, ok := attributes["rule_name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`rule_name is missing from object`)

		return NewHeaderPoliciesValueUnknown(), diags
	}

	ruleNameVal, ok := ruleNameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`rule_name expected to be basetypes.StringValue, was: %T`, ruleNameAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return NewHeaderPoliciesValueUnknown(), diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return NewHeaderPoliciesValueUnknown(), diags
	}

	return HeaderPoliciesValue{
		Header:             headerVal,
		RuleName:           ruleNameVal,
		HeaderPoliciesType: typeVal,
		state:              attr.ValueStateKnown,
	}, diags
}

func NewHeaderPoliciesValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) HeaderPoliciesValue {
	object, diags := NewHeaderPoliciesValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewHeaderPoliciesValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t HeaderPoliciesType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewHeaderPoliciesValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewHeaderPoliciesValueUnknown(), nil
	}

	if in.IsNull() {
		return NewHeaderPoliciesValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewHeaderPoliciesValueMust(HeaderPoliciesValue{}.AttributeTypes(ctx), attributes), nil
}

func (t HeaderPoliciesType) ValueType(ctx context.Context) attr.Value {
	return HeaderPoliciesValue{}
}

var _ basetypes.ObjectValuable = HeaderPoliciesValue{}

type HeaderPoliciesValue struct {
	Header             basetypes.ObjectValue `tfsdk:"header"`
	RuleName           basetypes.StringValue `tfsdk:"rule_name"`
	HeaderPoliciesType basetypes.StringValue `tfsdk:"type"`
	state              attr.ValueState
}

func (v HeaderPoliciesValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 3)

	var val tftypes.Value
	var err error

	attrTypes["header"] = basetypes.ObjectType{
		AttrTypes: HeaderValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["rule_name"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["type"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 3)

		val, err = v.Header.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["header"] = val

		val, err = v.RuleName.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["rule_name"] = val

		val, err = v.HeaderPoliciesType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["type"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v HeaderPoliciesValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v HeaderPoliciesValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v HeaderPoliciesValue) String() string {
	return "HeaderPoliciesValue"
}

func (v HeaderPoliciesValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	var header basetypes.ObjectValue

	if v.Header.IsNull() {
		header = types.ObjectNull(
			HeaderValue{}.AttributeTypes(ctx),
		)
	}

	if v.Header.IsUnknown() {
		header = types.ObjectUnknown(
			HeaderValue{}.AttributeTypes(ctx),
		)
	}

	if !v.Header.IsNull() && !v.Header.IsUnknown() {
		header = types.ObjectValueMust(
			HeaderValue{}.AttributeTypes(ctx),
			v.Header.Attributes(),
		)
	}

	attributeTypes := map[string]attr.Type{
		"header": basetypes.ObjectType{
			AttrTypes: HeaderValue{}.AttributeTypes(ctx),
		},
		"rule_name": basetypes.StringType{},
		"type":      basetypes.StringType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"header":    header,
			"rule_name": v.RuleName,
			"type":      v.HeaderPoliciesType,
		})

	return objVal, diags
}

func (v HeaderPoliciesValue) Equal(o attr.Value) bool {
	other, ok := o.(HeaderPoliciesValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Header.Equal(other.Header) {
		return false
	}

	if !v.RuleName.Equal(other.RuleName) {
		return false
	}

	if !v.HeaderPoliciesType.Equal(other.HeaderPoliciesType) {
		return false
	}

	return true
}

func (v HeaderPoliciesValue) Type(ctx context.Context) attr.Type {
	return HeaderPoliciesType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v HeaderPoliciesValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"header": basetypes.ObjectType{
			AttrTypes: HeaderValue{}.AttributeTypes(ctx),
		},
		"rule_name": basetypes.StringType{},
		"type":      basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = HeaderType{}

type HeaderType struct {
	basetypes.ObjectType
}

func (t HeaderType) Equal(o attr.Type) bool {
	other, ok := o.(HeaderType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t HeaderType) String() string {
	return "HeaderType"
}

func (t HeaderType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	nameAttribute, ok := attributes["name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`name is missing from object`)

		return nil, diags
	}

	nameVal, ok := nameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`name expected to be basetypes.StringValue, was: %T`, nameAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return nil, diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	valueAttribute, ok := attributes["value"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`value is missing from object`)

		return nil, diags
	}

	valueVal, ok := valueAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`value expected to be basetypes.StringValue, was: %T`, valueAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return HeaderValue{
		Name:       nameVal,
		HeaderType: typeVal,
		Value:      valueVal,
		state:      attr.ValueStateKnown,
	}, diags
}

func NewHeaderValueNull() HeaderValue {
	return HeaderValue{
		state: attr.ValueStateNull,
	}
}

func NewHeaderValueUnknown() HeaderValue {
	return HeaderValue{
		state: attr.ValueStateUnknown,
	}
}

func NewHeaderValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (HeaderValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing HeaderValue Attribute Value",
				"While creating a HeaderValue value, a missing attribute value was detected. "+
					"A HeaderValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("HeaderValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid HeaderValue Attribute Type",
				"While creating a HeaderValue value, an invalid attribute value was detected. "+
					"A HeaderValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("HeaderValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("HeaderValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra HeaderValue Attribute Value",
				"While creating a HeaderValue value, an extra attribute value was detected. "+
					"A HeaderValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra HeaderValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewHeaderValueUnknown(), diags
	}

	nameAttribute, ok := attributes["name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`name is missing from object`)

		return NewHeaderValueUnknown(), diags
	}

	nameVal, ok := nameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`name expected to be basetypes.StringValue, was: %T`, nameAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return NewHeaderValueUnknown(), diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	valueAttribute, ok := attributes["value"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`value is missing from object`)

		return NewHeaderValueUnknown(), diags
	}

	valueVal, ok := valueAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`value expected to be basetypes.StringValue, was: %T`, valueAttribute))
	}

	if diags.HasError() {
		return NewHeaderValueUnknown(), diags
	}

	return HeaderValue{
		Name:       nameVal,
		HeaderType: typeVal,
		Value:      valueVal,
		state:      attr.ValueStateKnown,
	}, diags
}

func NewHeaderValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) HeaderValue {
	object, diags := NewHeaderValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewHeaderValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t HeaderType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewHeaderValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewHeaderValueUnknown(), nil
	}

	if in.IsNull() {
		return NewHeaderValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewHeaderValueMust(HeaderValue{}.AttributeTypes(ctx), attributes), nil
}

func (t HeaderType) ValueType(ctx context.Context) attr.Value {
	return HeaderValue{}
}

var _ basetypes.ObjectValuable = HeaderValue{}

type HeaderValue struct {
	Name       basetypes.StringValue `tfsdk:"name"`
	HeaderType basetypes.StringValue `tfsdk:"type"`
	Value      basetypes.StringValue `tfsdk:"value"`
	state      attr.ValueState
}

func (v HeaderValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 3)

	var val tftypes.Value
	var err error

	attrTypes["name"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["type"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["value"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 3)

		val, err = v.Name.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["name"] = val

		val, err = v.HeaderType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["type"] = val

		val, err = v.Value.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["value"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v HeaderValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v HeaderValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v HeaderValue) String() string {
	return "HeaderValue"
}

func (v HeaderValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributeTypes := map[string]attr.Type{
		"name":  basetypes.StringType{},
		"type":  basetypes.StringType{},
		"value": basetypes.StringType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"name":  v.Name,
			"type":  v.HeaderType,
			"value": v.Value,
		})

	return objVal, diags
}

func (v HeaderValue) Equal(o attr.Value) bool {
	other, ok := o.(HeaderValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Name.Equal(other.Name) {
		return false
	}

	if !v.HeaderType.Equal(other.HeaderType) {
		return false
	}

	if !v.Value.Equal(other.Value) {
		return false
	}

	return true
}

func (v HeaderValue) Type(ctx context.Context) attr.Type {
	return HeaderType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v HeaderValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"name":  basetypes.StringType{},
		"type":  basetypes.StringType{},
		"value": basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = ManagedRuleType{}

type ManagedRuleType struct {
	basetypes.ObjectType
}

func (t ManagedRuleType) Equal(o attr.Type) bool {
	other, ok := o.(ManagedRuleType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t ManagedRuleType) String() string {
	return "ManagedRuleType"
}

func (t ManagedRuleType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	corsAttribute, ok := attributes["cors"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`cors is missing from object`)

		return nil, diags
	}

	corsVal, ok := corsAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`cors expected to be basetypes.BoolValue, was: %T`, corsAttribute))
	}

	hstsAttribute, ok := attributes["hsts"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`hsts is missing from object`)

		return nil, diags
	}

	hstsVal, ok := hstsAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`hsts expected to be basetypes.BoolValue, was: %T`, hstsAttribute))
	}

	http2Attribute, ok := attributes["http2"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`http2 is missing from object`)

		return nil, diags
	}

	http2Val, ok := http2Attribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`http2 expected to be basetypes.BoolValue, was: %T`, http2Attribute))
	}

	trueClientIpHeaderAttribute, ok := attributes["true_client_ip_header"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`true_client_ip_header is missing from object`)

		return nil, diags
	}

	trueClientIpHeaderVal, ok := trueClientIpHeaderAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`true_client_ip_header expected to be basetypes.BoolValue, was: %T`, trueClientIpHeaderAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return ManagedRuleValue{
		Cors:               corsVal,
		Hsts:               hstsVal,
		Http2:              http2Val,
		TrueClientIpHeader: trueClientIpHeaderVal,
		state:              attr.ValueStateKnown,
	}, diags
}

func NewManagedRuleValueNull() ManagedRuleValue {
	return ManagedRuleValue{
		state: attr.ValueStateNull,
	}
}

func NewManagedRuleValueUnknown() ManagedRuleValue {
	return ManagedRuleValue{
		state: attr.ValueStateUnknown,
	}
}

func NewManagedRuleValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (ManagedRuleValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing ManagedRuleValue Attribute Value",
				"While creating a ManagedRuleValue value, a missing attribute value was detected. "+
					"A ManagedRuleValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("ManagedRuleValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid ManagedRuleValue Attribute Type",
				"While creating a ManagedRuleValue value, an invalid attribute value was detected. "+
					"A ManagedRuleValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("ManagedRuleValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("ManagedRuleValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra ManagedRuleValue Attribute Value",
				"While creating a ManagedRuleValue value, an extra attribute value was detected. "+
					"A ManagedRuleValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra ManagedRuleValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewManagedRuleValueUnknown(), diags
	}

	corsAttribute, ok := attributes["cors"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`cors is missing from object`)

		return NewManagedRuleValueUnknown(), diags
	}

	corsVal, ok := corsAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`cors expected to be basetypes.BoolValue, was: %T`, corsAttribute))
	}

	hstsAttribute, ok := attributes["hsts"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`hsts is missing from object`)

		return NewManagedRuleValueUnknown(), diags
	}

	hstsVal, ok := hstsAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`hsts expected to be basetypes.BoolValue, was: %T`, hstsAttribute))
	}

	http2Attribute, ok := attributes["http2"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`http2 is missing from object`)

		return NewManagedRuleValueUnknown(), diags
	}

	http2Val, ok := http2Attribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`http2 expected to be basetypes.BoolValue, was: %T`, http2Attribute))
	}

	trueClientIpHeaderAttribute, ok := attributes["true_client_ip_header"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`true_client_ip_header is missing from object`)

		return NewManagedRuleValueUnknown(), diags
	}

	trueClientIpHeaderVal, ok := trueClientIpHeaderAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`true_client_ip_header expected to be basetypes.BoolValue, was: %T`, trueClientIpHeaderAttribute))
	}

	if diags.HasError() {
		return NewManagedRuleValueUnknown(), diags
	}

	return ManagedRuleValue{
		Cors:               corsVal,
		Hsts:               hstsVal,
		Http2:              http2Val,
		TrueClientIpHeader: trueClientIpHeaderVal,
		state:              attr.ValueStateKnown,
	}, diags
}

func NewManagedRuleValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) ManagedRuleValue {
	object, diags := NewManagedRuleValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewManagedRuleValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t ManagedRuleType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewManagedRuleValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewManagedRuleValueUnknown(), nil
	}

	if in.IsNull() {
		return NewManagedRuleValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewManagedRuleValueMust(ManagedRuleValue{}.AttributeTypes(ctx), attributes), nil
}

func (t ManagedRuleType) ValueType(ctx context.Context) attr.Value {
	return ManagedRuleValue{}
}

var _ basetypes.ObjectValuable = ManagedRuleValue{}

type ManagedRuleValue struct {
	Cors               basetypes.BoolValue `tfsdk:"cors"`
	Hsts               basetypes.BoolValue `tfsdk:"hsts"`
	Http2              basetypes.BoolValue `tfsdk:"http2"`
	TrueClientIpHeader basetypes.BoolValue `tfsdk:"true_client_ip_header"`
	state              attr.ValueState
}

func (v ManagedRuleValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 4)

	var val tftypes.Value
	var err error

	attrTypes["cors"] = basetypes.BoolType{}.TerraformType(ctx)
	attrTypes["hsts"] = basetypes.BoolType{}.TerraformType(ctx)
	attrTypes["http2"] = basetypes.BoolType{}.TerraformType(ctx)
	attrTypes["true_client_ip_header"] = basetypes.BoolType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 4)

		val, err = v.Cors.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["cors"] = val

		val, err = v.Hsts.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["hsts"] = val

		val, err = v.Http2.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["http2"] = val

		val, err = v.TrueClientIpHeader.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["true_client_ip_header"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v ManagedRuleValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v ManagedRuleValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v ManagedRuleValue) String() string {
	return "ManagedRuleValue"
}

func (v ManagedRuleValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributeTypes := map[string]attr.Type{
		"cors":                  basetypes.BoolType{},
		"hsts":                  basetypes.BoolType{},
		"http2":                 basetypes.BoolType{},
		"true_client_ip_header": basetypes.BoolType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"cors":                  v.Cors,
			"hsts":                  v.Hsts,
			"http2":                 v.Http2,
			"true_client_ip_header": v.TrueClientIpHeader,
		})

	return objVal, diags
}

func (v ManagedRuleValue) Equal(o attr.Value) bool {
	other, ok := o.(ManagedRuleValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Cors.Equal(other.Cors) {
		return false
	}

	if !v.Hsts.Equal(other.Hsts) {
		return false
	}

	if !v.Http2.Equal(other.Http2) {
		return false
	}

	if !v.TrueClientIpHeader.Equal(other.TrueClientIpHeader) {
		return false
	}

	return true
}

func (v ManagedRuleValue) Type(ctx context.Context) attr.Type {
	return ManagedRuleType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v ManagedRuleValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"cors":                  basetypes.BoolType{},
		"hsts":                  basetypes.BoolType{},
		"http2":                 basetypes.BoolType{},
		"true_client_ip_header": basetypes.BoolType{},
	}
}

var _ basetypes.ObjectTypable = OptimizationConfigType{}

type OptimizationConfigType struct {
	basetypes.ObjectType
}

func (t OptimizationConfigType) Equal(o attr.Type) bool {
	other, ok := o.(OptimizationConfigType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t OptimizationConfigType) String() string {
	return "OptimizationConfigType"
}

func (t OptimizationConfigType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	httpCompressionAttribute, ok := attributes["http_compression"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`http_compression is missing from object`)

		return nil, diags
	}

	httpCompressionVal, ok := httpCompressionAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`http_compression expected to be basetypes.BoolValue, was: %T`, httpCompressionAttribute))
	}

	largeFileOptimizationAttribute, ok := attributes["large_file_optimization"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`large_file_optimization is missing from object`)

		return nil, diags
	}

	largeFileOptimizationVal, ok := largeFileOptimizationAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`large_file_optimization expected to be basetypes.BoolValue, was: %T`, largeFileOptimizationAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return OptimizationConfigValue{
		HttpCompression:       httpCompressionVal,
		LargeFileOptimization: largeFileOptimizationVal,
		state:                 attr.ValueStateKnown,
	}, diags
}

func NewOptimizationConfigValueNull() OptimizationConfigValue {
	return OptimizationConfigValue{
		state: attr.ValueStateNull,
	}
}

func NewOptimizationConfigValueUnknown() OptimizationConfigValue {
	return OptimizationConfigValue{
		state: attr.ValueStateUnknown,
	}
}

func NewOptimizationConfigValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (OptimizationConfigValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing OptimizationConfigValue Attribute Value",
				"While creating a OptimizationConfigValue value, a missing attribute value was detected. "+
					"A OptimizationConfigValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("OptimizationConfigValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid OptimizationConfigValue Attribute Type",
				"While creating a OptimizationConfigValue value, an invalid attribute value was detected. "+
					"A OptimizationConfigValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("OptimizationConfigValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("OptimizationConfigValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra OptimizationConfigValue Attribute Value",
				"While creating a OptimizationConfigValue value, an extra attribute value was detected. "+
					"A OptimizationConfigValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra OptimizationConfigValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewOptimizationConfigValueUnknown(), diags
	}

	httpCompressionAttribute, ok := attributes["http_compression"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`http_compression is missing from object`)

		return NewOptimizationConfigValueUnknown(), diags
	}

	httpCompressionVal, ok := httpCompressionAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`http_compression expected to be basetypes.BoolValue, was: %T`, httpCompressionAttribute))
	}

	largeFileOptimizationAttribute, ok := attributes["large_file_optimization"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`large_file_optimization is missing from object`)

		return NewOptimizationConfigValueUnknown(), diags
	}

	largeFileOptimizationVal, ok := largeFileOptimizationAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`large_file_optimization expected to be basetypes.BoolValue, was: %T`, largeFileOptimizationAttribute))
	}

	if diags.HasError() {
		return NewOptimizationConfigValueUnknown(), diags
	}

	return OptimizationConfigValue{
		HttpCompression:       httpCompressionVal,
		LargeFileOptimization: largeFileOptimizationVal,
		state:                 attr.ValueStateKnown,
	}, diags
}

func NewOptimizationConfigValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) OptimizationConfigValue {
	object, diags := NewOptimizationConfigValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewOptimizationConfigValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t OptimizationConfigType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewOptimizationConfigValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewOptimizationConfigValueUnknown(), nil
	}

	if in.IsNull() {
		return NewOptimizationConfigValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewOptimizationConfigValueMust(OptimizationConfigValue{}.AttributeTypes(ctx), attributes), nil
}

func (t OptimizationConfigType) ValueType(ctx context.Context) attr.Value {
	return OptimizationConfigValue{}
}

var _ basetypes.ObjectValuable = OptimizationConfigValue{}

type OptimizationConfigValue struct {
	HttpCompression       basetypes.BoolValue `tfsdk:"http_compression"`
	LargeFileOptimization basetypes.BoolValue `tfsdk:"large_file_optimization"`
	state                 attr.ValueState
}

func (v OptimizationConfigValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 2)

	var val tftypes.Value
	var err error

	attrTypes["http_compression"] = basetypes.BoolType{}.TerraformType(ctx)
	attrTypes["large_file_optimization"] = basetypes.BoolType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 2)

		val, err = v.HttpCompression.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["http_compression"] = val

		val, err = v.LargeFileOptimization.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["large_file_optimization"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v OptimizationConfigValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v OptimizationConfigValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v OptimizationConfigValue) String() string {
	return "OptimizationConfigValue"
}

func (v OptimizationConfigValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributeTypes := map[string]attr.Type{
		"http_compression":        basetypes.BoolType{},
		"large_file_optimization": basetypes.BoolType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"http_compression":        v.HttpCompression,
			"large_file_optimization": v.LargeFileOptimization,
		})

	return objVal, diags
}

func (v OptimizationConfigValue) Equal(o attr.Value) bool {
	other, ok := o.(OptimizationConfigValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.HttpCompression.Equal(other.HttpCompression) {
		return false
	}

	if !v.LargeFileOptimization.Equal(other.LargeFileOptimization) {
		return false
	}

	return true
}

func (v OptimizationConfigValue) Type(ctx context.Context) attr.Type {
	return OptimizationConfigType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v OptimizationConfigValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"http_compression":        basetypes.BoolType{},
		"large_file_optimization": basetypes.BoolType{},
	}
}

var _ basetypes.ObjectTypable = OriginalCopyConfigType{}

type OriginalCopyConfigType struct {
	basetypes.ObjectType
}

func (t OriginalCopyConfigType) Equal(o attr.Type) bool {
	other, ok := o.(OriginalCopyConfigType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t OriginalCopyConfigType) String() string {
	return "OriginalCopyConfigType"
}

func (t OriginalCopyConfigType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	forwardHostHeaderAttribute, ok := attributes["forward_host_header"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`forward_host_header is missing from object`)

		return nil, diags
	}

	forwardHostHeaderVal, ok := forwardHostHeaderAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`forward_host_header expected to be basetypes.ObjectValue, was: %T`, forwardHostHeaderAttribute))
	}

	originFailoverConfigAttribute, ok := attributes["origin_failover_config"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`origin_failover_config is missing from object`)

		return nil, diags
	}

	originFailoverConfigVal, ok := originFailoverConfigAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`origin_failover_config expected to be basetypes.ObjectValue, was: %T`, originFailoverConfigAttribute))
	}

	originShieldAttribute, ok := attributes["origin_shield"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`origin_shield is missing from object`)

		return nil, diags
	}

	originShieldVal, ok := originShieldAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`origin_shield expected to be basetypes.ObjectValue, was: %T`, originShieldAttribute))
	}

	originalCopyLocationAttribute, ok := attributes["original_copy_location"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`original_copy_location is missing from object`)

		return nil, diags
	}

	originalCopyLocationVal, ok := originalCopyLocationAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`original_copy_location expected to be basetypes.ObjectValue, was: %T`, originalCopyLocationAttribute))
	}

	originalCopyPathAttribute, ok := attributes["original_copy_path"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`original_copy_path is missing from object`)

		return nil, diags
	}

	originalCopyPathVal, ok := originalCopyPathAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`original_copy_path expected to be basetypes.StringValue, was: %T`, originalCopyPathAttribute))
	}

	originalCopyProtocolAttribute, ok := attributes["original_copy_protocol"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`original_copy_protocol is missing from object`)

		return nil, diags
	}

	originalCopyProtocolVal, ok := originalCopyProtocolAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`original_copy_protocol expected to be basetypes.ObjectValue, was: %T`, originalCopyProtocolAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return OriginalCopyConfigValue{
		ForwardHostHeader:    forwardHostHeaderVal,
		OriginFailoverConfig: originFailoverConfigVal,
		OriginShield:         originShieldVal,
		OriginalCopyLocation: originalCopyLocationVal,
		OriginalCopyPath:     originalCopyPathVal,
		OriginalCopyProtocol: originalCopyProtocolVal,
		state:                attr.ValueStateKnown,
	}, diags
}

func NewOriginalCopyConfigValueNull() OriginalCopyConfigValue {
	return OriginalCopyConfigValue{
		state: attr.ValueStateNull,
	}
}

func NewOriginalCopyConfigValueUnknown() OriginalCopyConfigValue {
	return OriginalCopyConfigValue{
		state: attr.ValueStateUnknown,
	}
}

func NewOriginalCopyConfigValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (OriginalCopyConfigValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing OriginalCopyConfigValue Attribute Value",
				"While creating a OriginalCopyConfigValue value, a missing attribute value was detected. "+
					"A OriginalCopyConfigValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("OriginalCopyConfigValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid OriginalCopyConfigValue Attribute Type",
				"While creating a OriginalCopyConfigValue value, an invalid attribute value was detected. "+
					"A OriginalCopyConfigValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("OriginalCopyConfigValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("OriginalCopyConfigValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra OriginalCopyConfigValue Attribute Value",
				"While creating a OriginalCopyConfigValue value, an extra attribute value was detected. "+
					"A OriginalCopyConfigValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra OriginalCopyConfigValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewOriginalCopyConfigValueUnknown(), diags
	}

	forwardHostHeaderAttribute, ok := attributes["forward_host_header"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`forward_host_header is missing from object`)

		return NewOriginalCopyConfigValueUnknown(), diags
	}

	forwardHostHeaderVal, ok := forwardHostHeaderAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`forward_host_header expected to be basetypes.ObjectValue, was: %T`, forwardHostHeaderAttribute))
	}

	originFailoverConfigAttribute, ok := attributes["origin_failover_config"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`origin_failover_config is missing from object`)

		return NewOriginalCopyConfigValueUnknown(), diags
	}

	originFailoverConfigVal, ok := originFailoverConfigAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`origin_failover_config expected to be basetypes.ObjectValue, was: %T`, originFailoverConfigAttribute))
	}

	originShieldAttribute, ok := attributes["origin_shield"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`origin_shield is missing from object`)

		return NewOriginalCopyConfigValueUnknown(), diags
	}

	originShieldVal, ok := originShieldAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`origin_shield expected to be basetypes.ObjectValue, was: %T`, originShieldAttribute))
	}

	originalCopyLocationAttribute, ok := attributes["original_copy_location"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`original_copy_location is missing from object`)

		return NewOriginalCopyConfigValueUnknown(), diags
	}

	originalCopyLocationVal, ok := originalCopyLocationAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`original_copy_location expected to be basetypes.ObjectValue, was: %T`, originalCopyLocationAttribute))
	}

	originalCopyPathAttribute, ok := attributes["original_copy_path"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`original_copy_path is missing from object`)

		return NewOriginalCopyConfigValueUnknown(), diags
	}

	originalCopyPathVal, ok := originalCopyPathAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`original_copy_path expected to be basetypes.StringValue, was: %T`, originalCopyPathAttribute))
	}

	originalCopyProtocolAttribute, ok := attributes["original_copy_protocol"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`original_copy_protocol is missing from object`)

		return NewOriginalCopyConfigValueUnknown(), diags
	}

	originalCopyProtocolVal, ok := originalCopyProtocolAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`original_copy_protocol expected to be basetypes.ObjectValue, was: %T`, originalCopyProtocolAttribute))
	}

	if diags.HasError() {
		return NewOriginalCopyConfigValueUnknown(), diags
	}

	return OriginalCopyConfigValue{
		ForwardHostHeader:    forwardHostHeaderVal,
		OriginFailoverConfig: originFailoverConfigVal,
		OriginShield:         originShieldVal,
		OriginalCopyLocation: originalCopyLocationVal,
		OriginalCopyPath:     originalCopyPathVal,
		OriginalCopyProtocol: originalCopyProtocolVal,
		state:                attr.ValueStateKnown,
	}, diags
}

func NewOriginalCopyConfigValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) OriginalCopyConfigValue {
	object, diags := NewOriginalCopyConfigValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewOriginalCopyConfigValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t OriginalCopyConfigType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewOriginalCopyConfigValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewOriginalCopyConfigValueUnknown(), nil
	}

	if in.IsNull() {
		return NewOriginalCopyConfigValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewOriginalCopyConfigValueMust(OriginalCopyConfigValue{}.AttributeTypes(ctx), attributes), nil
}

func (t OriginalCopyConfigType) ValueType(ctx context.Context) attr.Value {
	return OriginalCopyConfigValue{}
}

var _ basetypes.ObjectValuable = OriginalCopyConfigValue{}

type OriginalCopyConfigValue struct {
	ForwardHostHeader    basetypes.ObjectValue `tfsdk:"forward_host_header"`
	OriginFailoverConfig basetypes.ObjectValue `tfsdk:"origin_failover_config"`
	OriginShield         basetypes.ObjectValue `tfsdk:"origin_shield"`
	OriginalCopyLocation basetypes.ObjectValue `tfsdk:"original_copy_location"`
	OriginalCopyPath     basetypes.StringValue `tfsdk:"original_copy_path"`
	OriginalCopyProtocol basetypes.ObjectValue `tfsdk:"original_copy_protocol"`
	state                attr.ValueState
}

func (v OriginalCopyConfigValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 6)

	var val tftypes.Value
	var err error

	attrTypes["forward_host_header"] = basetypes.ObjectType{
		AttrTypes: ForwardHostHeaderValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["origin_failover_config"] = basetypes.ObjectType{
		AttrTypes: OriginFailoverConfigValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["origin_shield"] = basetypes.ObjectType{
		AttrTypes: OriginShieldValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["original_copy_location"] = basetypes.ObjectType{
		AttrTypes: OriginalCopyLocationValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["original_copy_path"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["original_copy_protocol"] = basetypes.ObjectType{
		AttrTypes: OriginalCopyProtocolValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 6)

		val, err = v.ForwardHostHeader.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["forward_host_header"] = val

		val, err = v.OriginFailoverConfig.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["origin_failover_config"] = val

		val, err = v.OriginShield.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["origin_shield"] = val

		val, err = v.OriginalCopyLocation.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["original_copy_location"] = val

		val, err = v.OriginalCopyPath.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["original_copy_path"] = val

		val, err = v.OriginalCopyProtocol.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["original_copy_protocol"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v OriginalCopyConfigValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v OriginalCopyConfigValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v OriginalCopyConfigValue) String() string {
	return "OriginalCopyConfigValue"
}

func (v OriginalCopyConfigValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	var forwardHostHeader basetypes.ObjectValue

	if v.ForwardHostHeader.IsNull() {
		forwardHostHeader = types.ObjectNull(
			ForwardHostHeaderValue{}.AttributeTypes(ctx),
		)
	}

	if v.ForwardHostHeader.IsUnknown() {
		forwardHostHeader = types.ObjectUnknown(
			ForwardHostHeaderValue{}.AttributeTypes(ctx),
		)
	}

	if !v.ForwardHostHeader.IsNull() && !v.ForwardHostHeader.IsUnknown() {
		forwardHostHeader = types.ObjectValueMust(
			ForwardHostHeaderValue{}.AttributeTypes(ctx),
			v.ForwardHostHeader.Attributes(),
		)
	}

	var originFailoverConfig basetypes.ObjectValue

	if v.OriginFailoverConfig.IsNull() {
		originFailoverConfig = types.ObjectNull(
			OriginFailoverConfigValue{}.AttributeTypes(ctx),
		)
	}

	if v.OriginFailoverConfig.IsUnknown() {
		originFailoverConfig = types.ObjectUnknown(
			OriginFailoverConfigValue{}.AttributeTypes(ctx),
		)
	}

	if !v.OriginFailoverConfig.IsNull() && !v.OriginFailoverConfig.IsUnknown() {
		originFailoverConfig = types.ObjectValueMust(
			OriginFailoverConfigValue{}.AttributeTypes(ctx),
			v.OriginFailoverConfig.Attributes(),
		)
	}

	var originShield basetypes.ObjectValue

	if v.OriginShield.IsNull() {
		originShield = types.ObjectNull(
			OriginShieldValue{}.AttributeTypes(ctx),
		)
	}

	if v.OriginShield.IsUnknown() {
		originShield = types.ObjectUnknown(
			OriginShieldValue{}.AttributeTypes(ctx),
		)
	}

	if !v.OriginShield.IsNull() && !v.OriginShield.IsUnknown() {
		originShield = types.ObjectValueMust(
			OriginShieldValue{}.AttributeTypes(ctx),
			v.OriginShield.Attributes(),
		)
	}

	var originalCopyLocation basetypes.ObjectValue

	if v.OriginalCopyLocation.IsNull() {
		originalCopyLocation = types.ObjectNull(
			OriginalCopyLocationValue{}.AttributeTypes(ctx),
		)
	}

	if v.OriginalCopyLocation.IsUnknown() {
		originalCopyLocation = types.ObjectUnknown(
			OriginalCopyLocationValue{}.AttributeTypes(ctx),
		)
	}

	if !v.OriginalCopyLocation.IsNull() && !v.OriginalCopyLocation.IsUnknown() {
		originalCopyLocation = types.ObjectValueMust(
			OriginalCopyLocationValue{}.AttributeTypes(ctx),
			v.OriginalCopyLocation.Attributes(),
		)
	}

	var originalCopyProtocol basetypes.ObjectValue

	if v.OriginalCopyProtocol.IsNull() {
		originalCopyProtocol = types.ObjectNull(
			OriginalCopyProtocolValue{}.AttributeTypes(ctx),
		)
	}

	if v.OriginalCopyProtocol.IsUnknown() {
		originalCopyProtocol = types.ObjectUnknown(
			OriginalCopyProtocolValue{}.AttributeTypes(ctx),
		)
	}

	if !v.OriginalCopyProtocol.IsNull() && !v.OriginalCopyProtocol.IsUnknown() {
		originalCopyProtocol = types.ObjectValueMust(
			OriginalCopyProtocolValue{}.AttributeTypes(ctx),
			v.OriginalCopyProtocol.Attributes(),
		)
	}

	attributeTypes := map[string]attr.Type{
		"forward_host_header": basetypes.ObjectType{
			AttrTypes: ForwardHostHeaderValue{}.AttributeTypes(ctx),
		},
		"origin_failover_config": basetypes.ObjectType{
			AttrTypes: OriginFailoverConfigValue{}.AttributeTypes(ctx),
		},
		"origin_shield": basetypes.ObjectType{
			AttrTypes: OriginShieldValue{}.AttributeTypes(ctx),
		},
		"original_copy_location": basetypes.ObjectType{
			AttrTypes: OriginalCopyLocationValue{}.AttributeTypes(ctx),
		},
		"original_copy_path": basetypes.StringType{},
		"original_copy_protocol": basetypes.ObjectType{
			AttrTypes: OriginalCopyProtocolValue{}.AttributeTypes(ctx),
		},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"forward_host_header":    forwardHostHeader,
			"origin_failover_config": originFailoverConfig,
			"origin_shield":          originShield,
			"original_copy_location": originalCopyLocation,
			"original_copy_path":     v.OriginalCopyPath,
			"original_copy_protocol": originalCopyProtocol,
		})

	return objVal, diags
}

func (v OriginalCopyConfigValue) Equal(o attr.Value) bool {
	other, ok := o.(OriginalCopyConfigValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.ForwardHostHeader.Equal(other.ForwardHostHeader) {
		return false
	}

	if !v.OriginFailoverConfig.Equal(other.OriginFailoverConfig) {
		return false
	}

	if !v.OriginShield.Equal(other.OriginShield) {
		return false
	}

	if !v.OriginalCopyLocation.Equal(other.OriginalCopyLocation) {
		return false
	}

	if !v.OriginalCopyPath.Equal(other.OriginalCopyPath) {
		return false
	}

	if !v.OriginalCopyProtocol.Equal(other.OriginalCopyProtocol) {
		return false
	}

	return true
}

func (v OriginalCopyConfigValue) Type(ctx context.Context) attr.Type {
	return OriginalCopyConfigType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v OriginalCopyConfigValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"forward_host_header": basetypes.ObjectType{
			AttrTypes: ForwardHostHeaderValue{}.AttributeTypes(ctx),
		},
		"origin_failover_config": basetypes.ObjectType{
			AttrTypes: OriginFailoverConfigValue{}.AttributeTypes(ctx),
		},
		"origin_shield": basetypes.ObjectType{
			AttrTypes: OriginShieldValue{}.AttributeTypes(ctx),
		},
		"original_copy_location": basetypes.ObjectType{
			AttrTypes: OriginalCopyLocationValue{}.AttributeTypes(ctx),
		},
		"original_copy_path": basetypes.StringType{},
		"original_copy_protocol": basetypes.ObjectType{
			AttrTypes: OriginalCopyProtocolValue{}.AttributeTypes(ctx),
		},
	}
}

var _ basetypes.ObjectTypable = ForwardHostHeaderType{}

type ForwardHostHeaderType struct {
	basetypes.ObjectType
}

func (t ForwardHostHeaderType) Equal(o attr.Type) bool {
	other, ok := o.(ForwardHostHeaderType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t ForwardHostHeaderType) String() string {
	return "ForwardHostHeaderType"
}

func (t ForwardHostHeaderType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	customHostHeaderAttribute, ok := attributes["custom_host_header"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`custom_host_header is missing from object`)

		return nil, diags
	}

	customHostHeaderVal, ok := customHostHeaderAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`custom_host_header expected to be basetypes.StringValue, was: %T`, customHostHeaderAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return nil, diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return ForwardHostHeaderValue{
		CustomHostHeader:      customHostHeaderVal,
		ForwardHostHeaderType: typeVal,
		state:                 attr.ValueStateKnown,
	}, diags
}

func NewForwardHostHeaderValueNull() ForwardHostHeaderValue {
	return ForwardHostHeaderValue{
		state: attr.ValueStateNull,
	}
}

func NewForwardHostHeaderValueUnknown() ForwardHostHeaderValue {
	return ForwardHostHeaderValue{
		state: attr.ValueStateUnknown,
	}
}

func NewForwardHostHeaderValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (ForwardHostHeaderValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing ForwardHostHeaderValue Attribute Value",
				"While creating a ForwardHostHeaderValue value, a missing attribute value was detected. "+
					"A ForwardHostHeaderValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("ForwardHostHeaderValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid ForwardHostHeaderValue Attribute Type",
				"While creating a ForwardHostHeaderValue value, an invalid attribute value was detected. "+
					"A ForwardHostHeaderValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("ForwardHostHeaderValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("ForwardHostHeaderValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra ForwardHostHeaderValue Attribute Value",
				"While creating a ForwardHostHeaderValue value, an extra attribute value was detected. "+
					"A ForwardHostHeaderValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra ForwardHostHeaderValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewForwardHostHeaderValueUnknown(), diags
	}

	customHostHeaderAttribute, ok := attributes["custom_host_header"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`custom_host_header is missing from object`)

		return NewForwardHostHeaderValueUnknown(), diags
	}

	customHostHeaderVal, ok := customHostHeaderAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`custom_host_header expected to be basetypes.StringValue, was: %T`, customHostHeaderAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return NewForwardHostHeaderValueUnknown(), diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return NewForwardHostHeaderValueUnknown(), diags
	}

	return ForwardHostHeaderValue{
		CustomHostHeader:      customHostHeaderVal,
		ForwardHostHeaderType: typeVal,
		state:                 attr.ValueStateKnown,
	}, diags
}

func NewForwardHostHeaderValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) ForwardHostHeaderValue {
	object, diags := NewForwardHostHeaderValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewForwardHostHeaderValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t ForwardHostHeaderType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewForwardHostHeaderValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewForwardHostHeaderValueUnknown(), nil
	}

	if in.IsNull() {
		return NewForwardHostHeaderValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewForwardHostHeaderValueMust(ForwardHostHeaderValue{}.AttributeTypes(ctx), attributes), nil
}

func (t ForwardHostHeaderType) ValueType(ctx context.Context) attr.Value {
	return ForwardHostHeaderValue{}
}

var _ basetypes.ObjectValuable = ForwardHostHeaderValue{}

type ForwardHostHeaderValue struct {
	CustomHostHeader      basetypes.StringValue `tfsdk:"custom_host_header"`
	ForwardHostHeaderType basetypes.StringValue `tfsdk:"type"`
	state                 attr.ValueState
}

func (v ForwardHostHeaderValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 2)

	var val tftypes.Value
	var err error

	attrTypes["custom_host_header"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["type"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 2)

		val, err = v.CustomHostHeader.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["custom_host_header"] = val

		val, err = v.ForwardHostHeaderType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["type"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v ForwardHostHeaderValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v ForwardHostHeaderValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v ForwardHostHeaderValue) String() string {
	return "ForwardHostHeaderValue"
}

func (v ForwardHostHeaderValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributeTypes := map[string]attr.Type{
		"custom_host_header": basetypes.StringType{},
		"type":               basetypes.StringType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"custom_host_header": v.CustomHostHeader,
			"type":               v.ForwardHostHeaderType,
		})

	return objVal, diags
}

func (v ForwardHostHeaderValue) Equal(o attr.Value) bool {
	other, ok := o.(ForwardHostHeaderValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.CustomHostHeader.Equal(other.CustomHostHeader) {
		return false
	}

	if !v.ForwardHostHeaderType.Equal(other.ForwardHostHeaderType) {
		return false
	}

	return true
}

func (v ForwardHostHeaderValue) Type(ctx context.Context) attr.Type {
	return ForwardHostHeaderType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v ForwardHostHeaderValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"custom_host_header": basetypes.StringType{},
		"type":               basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = OriginFailoverConfigType{}

type OriginFailoverConfigType struct {
	basetypes.ObjectType
}

func (t OriginFailoverConfigType) Equal(o attr.Type) bool {
	other, ok := o.(OriginFailoverConfigType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t OriginFailoverConfigType) String() string {
	return "OriginFailoverConfigType"
}

func (t OriginFailoverConfigType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	originalCopyLocationAttribute, ok := attributes["original_copy_location"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`original_copy_location is missing from object`)

		return nil, diags
	}

	originalCopyLocationVal, ok := originalCopyLocationAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`original_copy_location expected to be basetypes.ObjectValue, was: %T`, originalCopyLocationAttribute))
	}

	ruleNameAttribute, ok := attributes["rule_name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`rule_name is missing from object`)

		return nil, diags
	}

	ruleNameVal, ok := ruleNameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`rule_name expected to be basetypes.StringValue, was: %T`, ruleNameAttribute))
	}

	statusCodesAttribute, ok := attributes["status_codes"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`status_codes is missing from object`)

		return nil, diags
	}

	statusCodesVal, ok := statusCodesAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`status_codes expected to be basetypes.ListValue, was: %T`, statusCodesAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return OriginFailoverConfigValue{
		OriginalCopyLocation: originalCopyLocationVal,
		RuleName:             ruleNameVal,
		StatusCodes:          statusCodesVal,
		state:                attr.ValueStateKnown,
	}, diags
}

func NewOriginFailoverConfigValueNull() OriginFailoverConfigValue {
	return OriginFailoverConfigValue{
		state: attr.ValueStateNull,
	}
}

func NewOriginFailoverConfigValueUnknown() OriginFailoverConfigValue {
	return OriginFailoverConfigValue{
		state: attr.ValueStateUnknown,
	}
}

func NewOriginFailoverConfigValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (OriginFailoverConfigValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing OriginFailoverConfigValue Attribute Value",
				"While creating a OriginFailoverConfigValue value, a missing attribute value was detected. "+
					"A OriginFailoverConfigValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("OriginFailoverConfigValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid OriginFailoverConfigValue Attribute Type",
				"While creating a OriginFailoverConfigValue value, an invalid attribute value was detected. "+
					"A OriginFailoverConfigValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("OriginFailoverConfigValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("OriginFailoverConfigValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra OriginFailoverConfigValue Attribute Value",
				"While creating a OriginFailoverConfigValue value, an extra attribute value was detected. "+
					"A OriginFailoverConfigValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra OriginFailoverConfigValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewOriginFailoverConfigValueUnknown(), diags
	}

	originalCopyLocationAttribute, ok := attributes["original_copy_location"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`original_copy_location is missing from object`)

		return NewOriginFailoverConfigValueUnknown(), diags
	}

	originalCopyLocationVal, ok := originalCopyLocationAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`original_copy_location expected to be basetypes.ObjectValue, was: %T`, originalCopyLocationAttribute))
	}

	ruleNameAttribute, ok := attributes["rule_name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`rule_name is missing from object`)

		return NewOriginFailoverConfigValueUnknown(), diags
	}

	ruleNameVal, ok := ruleNameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`rule_name expected to be basetypes.StringValue, was: %T`, ruleNameAttribute))
	}

	statusCodesAttribute, ok := attributes["status_codes"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`status_codes is missing from object`)

		return NewOriginFailoverConfigValueUnknown(), diags
	}

	statusCodesVal, ok := statusCodesAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`status_codes expected to be basetypes.ListValue, was: %T`, statusCodesAttribute))
	}

	if diags.HasError() {
		return NewOriginFailoverConfigValueUnknown(), diags
	}

	return OriginFailoverConfigValue{
		OriginalCopyLocation: originalCopyLocationVal,
		RuleName:             ruleNameVal,
		StatusCodes:          statusCodesVal,
		state:                attr.ValueStateKnown,
	}, diags
}

func NewOriginFailoverConfigValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) OriginFailoverConfigValue {
	object, diags := NewOriginFailoverConfigValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewOriginFailoverConfigValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t OriginFailoverConfigType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewOriginFailoverConfigValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewOriginFailoverConfigValueUnknown(), nil
	}

	if in.IsNull() {
		return NewOriginFailoverConfigValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewOriginFailoverConfigValueMust(OriginFailoverConfigValue{}.AttributeTypes(ctx), attributes), nil
}

func (t OriginFailoverConfigType) ValueType(ctx context.Context) attr.Value {
	return OriginFailoverConfigValue{}
}

var _ basetypes.ObjectValuable = OriginFailoverConfigValue{}

type OriginFailoverConfigValue struct {
	OriginalCopyLocation basetypes.ObjectValue `tfsdk:"original_copy_location"`
	RuleName             basetypes.StringValue `tfsdk:"rule_name"`
	StatusCodes          basetypes.ListValue   `tfsdk:"status_codes"`
	state                attr.ValueState
}

func (v OriginFailoverConfigValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 3)

	var val tftypes.Value
	var err error

	attrTypes["original_copy_location"] = basetypes.ObjectType{
		AttrTypes: OriginalCopyLocationValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["rule_name"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["status_codes"] = basetypes.ListType{
		ElemType: types.Int64Type,
	}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 3)

		val, err = v.OriginalCopyLocation.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["original_copy_location"] = val

		val, err = v.RuleName.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["rule_name"] = val

		val, err = v.StatusCodes.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["status_codes"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v OriginFailoverConfigValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v OriginFailoverConfigValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v OriginFailoverConfigValue) String() string {
	return "OriginFailoverConfigValue"
}

func (v OriginFailoverConfigValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	var originalCopyLocation basetypes.ObjectValue

	if v.OriginalCopyLocation.IsNull() {
		originalCopyLocation = types.ObjectNull(
			OriginalCopyLocationValue{}.AttributeTypes(ctx),
		)
	}

	if v.OriginalCopyLocation.IsUnknown() {
		originalCopyLocation = types.ObjectUnknown(
			OriginalCopyLocationValue{}.AttributeTypes(ctx),
		)
	}

	if !v.OriginalCopyLocation.IsNull() && !v.OriginalCopyLocation.IsUnknown() {
		originalCopyLocation = types.ObjectValueMust(
			OriginalCopyLocationValue{}.AttributeTypes(ctx),
			v.OriginalCopyLocation.Attributes(),
		)
	}

	statusCodesVal, d := types.ListValue(types.Int64Type, v.StatusCodes.Elements())

	diags.Append(d...)

	if d.HasError() {
		return types.ObjectUnknown(map[string]attr.Type{
			"original_copy_location": basetypes.ObjectType{
				AttrTypes: OriginalCopyLocationValue{}.AttributeTypes(ctx),
			},
			"rule_name": basetypes.StringType{},
			"status_codes": basetypes.ListType{
				ElemType: types.Int64Type,
			},
		}), diags
	}

	attributeTypes := map[string]attr.Type{
		"original_copy_location": basetypes.ObjectType{
			AttrTypes: OriginalCopyLocationValue{}.AttributeTypes(ctx),
		},
		"rule_name": basetypes.StringType{},
		"status_codes": basetypes.ListType{
			ElemType: types.Int64Type,
		},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"original_copy_location": originalCopyLocation,
			"rule_name":              v.RuleName,
			"status_codes":           statusCodesVal,
		})

	return objVal, diags
}

func (v OriginFailoverConfigValue) Equal(o attr.Value) bool {
	other, ok := o.(OriginFailoverConfigValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.OriginalCopyLocation.Equal(other.OriginalCopyLocation) {
		return false
	}

	if !v.RuleName.Equal(other.RuleName) {
		return false
	}

	if !v.StatusCodes.Equal(other.StatusCodes) {
		return false
	}

	return true
}

func (v OriginFailoverConfigValue) Type(ctx context.Context) attr.Type {
	return OriginFailoverConfigType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v OriginFailoverConfigValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"original_copy_location": basetypes.ObjectType{
			AttrTypes: OriginalCopyLocationValue{}.AttributeTypes(ctx),
		},
		"rule_name": basetypes.StringType{},
		"status_codes": basetypes.ListType{
			ElemType: types.Int64Type,
		},
	}
}

var _ basetypes.ObjectTypable = OriginalCopyLocationType{}

var _ basetypes.ObjectValuable = OriginalCopyLocationValue{}

var _ basetypes.ObjectTypable = OriginShieldType{}

type OriginShieldType struct {
	basetypes.ObjectType
}

func (t OriginShieldType) Equal(o attr.Type) bool {
	other, ok := o.(OriginShieldType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t OriginShieldType) String() string {
	return "OriginShieldType"
}

func (t OriginShieldType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return nil, diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	regionAttribute, ok := attributes["region"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`region is missing from object`)

		return nil, diags
	}

	regionVal, ok := regionAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`region expected to be basetypes.StringValue, was: %T`, regionAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return OriginShieldValue{
		Enabled: enabledVal,
		Region:  regionVal,
		state:   attr.ValueStateKnown,
	}, diags
}

func NewOriginShieldValueNull() OriginShieldValue {
	return OriginShieldValue{
		state: attr.ValueStateNull,
	}
}

func NewOriginShieldValueUnknown() OriginShieldValue {
	return OriginShieldValue{
		state: attr.ValueStateUnknown,
	}
}

func NewOriginShieldValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (OriginShieldValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing OriginShieldValue Attribute Value",
				"While creating a OriginShieldValue value, a missing attribute value was detected. "+
					"A OriginShieldValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("OriginShieldValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid OriginShieldValue Attribute Type",
				"While creating a OriginShieldValue value, an invalid attribute value was detected. "+
					"A OriginShieldValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("OriginShieldValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("OriginShieldValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra OriginShieldValue Attribute Value",
				"While creating a OriginShieldValue value, an extra attribute value was detected. "+
					"A OriginShieldValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra OriginShieldValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewOriginShieldValueUnknown(), diags
	}

	enabledAttribute, ok := attributes["enabled"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`enabled is missing from object`)

		return NewOriginShieldValueUnknown(), diags
	}

	enabledVal, ok := enabledAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`enabled expected to be basetypes.BoolValue, was: %T`, enabledAttribute))
	}

	regionAttribute, ok := attributes["region"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`region is missing from object`)

		return NewOriginShieldValueUnknown(), diags
	}

	regionVal, ok := regionAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`region expected to be basetypes.StringValue, was: %T`, regionAttribute))
	}

	if diags.HasError() {
		return NewOriginShieldValueUnknown(), diags
	}

	return OriginShieldValue{
		Enabled: enabledVal,
		Region:  regionVal,
		state:   attr.ValueStateKnown,
	}, diags
}

func NewOriginShieldValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) OriginShieldValue {
	object, diags := NewOriginShieldValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewOriginShieldValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t OriginShieldType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewOriginShieldValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewOriginShieldValueUnknown(), nil
	}

	if in.IsNull() {
		return NewOriginShieldValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewOriginShieldValueMust(OriginShieldValue{}.AttributeTypes(ctx), attributes), nil
}

func (t OriginShieldType) ValueType(ctx context.Context) attr.Value {
	return OriginShieldValue{}
}

var _ basetypes.ObjectValuable = OriginShieldValue{}

type OriginShieldValue struct {
	Enabled basetypes.BoolValue   `tfsdk:"enabled"`
	Region  basetypes.StringValue `tfsdk:"region"`
	state   attr.ValueState
}

func (v OriginShieldValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 2)

	var val tftypes.Value
	var err error

	attrTypes["enabled"] = basetypes.BoolType{}.TerraformType(ctx)
	attrTypes["region"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 2)

		val, err = v.Enabled.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["enabled"] = val

		val, err = v.Region.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["region"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v OriginShieldValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v OriginShieldValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v OriginShieldValue) String() string {
	return "OriginShieldValue"
}

func (v OriginShieldValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributeTypes := map[string]attr.Type{
		"enabled": basetypes.BoolType{},
		"region":  basetypes.StringType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"enabled": v.Enabled,
			"region":  v.Region,
		})

	return objVal, diags
}

func (v OriginShieldValue) Equal(o attr.Value) bool {
	other, ok := o.(OriginShieldValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Enabled.Equal(other.Enabled) {
		return false
	}

	if !v.Region.Equal(other.Region) {
		return false
	}

	return true
}

func (v OriginShieldValue) Type(ctx context.Context) attr.Type {
	return OriginShieldType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v OriginShieldValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"enabled": basetypes.BoolType{},
		"region":  basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = OriginalCopyLocationType{}

type OriginalCopyLocationType struct {
	basetypes.ObjectType
}

func NewOriginalCopyLocationValueNull() OriginalCopyLocationValue {
	return OriginalCopyLocationValue{
		state: attr.ValueStateNull,
	}
}

func NewOriginalCopyLocationValueUnknown() OriginalCopyLocationValue {
	return OriginalCopyLocationValue{
		state: attr.ValueStateUnknown,
	}
}

func NewOriginalCopyLocationValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (OriginalCopyLocationValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing OriginalCopyLocationValue Attribute Value",
				"While creating a OriginalCopyLocationValue value, a missing attribute value was detected. "+
					"A OriginalCopyLocationValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("OriginalCopyLocationValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid OriginalCopyLocationValue Attribute Type",
				"While creating a OriginalCopyLocationValue value, an invalid attribute value was detected. "+
					"A OriginalCopyLocationValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("OriginalCopyLocationValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("OriginalCopyLocationValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra OriginalCopyLocationValue Attribute Value",
				"While creating a OriginalCopyLocationValue value, an extra attribute value was detected. "+
					"A OriginalCopyLocationValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra OriginalCopyLocationValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewOriginalCopyLocationValueUnknown(), diags
	}

	bucketNameAttribute, ok := attributes["bucket_name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`bucket_name is missing from object`)

		return NewOriginalCopyLocationValueUnknown(), diags
	}

	bucketNameVal, ok := bucketNameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`bucket_name expected to be basetypes.StringValue, was: %T`, bucketNameAttribute))
	}

	customLocationAttribute, ok := attributes["custom_location"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`custom_location is missing from object`)

		return NewOriginalCopyLocationValueUnknown(), diags
	}

	customLocationVal, ok := customLocationAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`custom_location expected to be basetypes.StringValue, was: %T`, customLocationAttribute))
	}

	regionAttribute, ok := attributes["region"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`region is missing from object`)

		return NewOriginalCopyLocationValueUnknown(), diags
	}

	regionVal, ok := regionAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`region expected to be basetypes.StringValue, was: %T`, regionAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return NewOriginalCopyLocationValueUnknown(), diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return NewOriginalCopyLocationValueUnknown(), diags
	}

	return OriginalCopyLocationValue{
		BucketName:               bucketNameVal,
		CustomLocation:           customLocationVal,
		Region:                   regionVal,
		OriginalCopyLocationType: typeVal,
		state:                    attr.ValueStateKnown,
	}, diags
}

func NewOriginalCopyLocationValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) OriginalCopyLocationValue {
	object, diags := NewOriginalCopyLocationValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewOriginalCopyLocationValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

var _ basetypes.ObjectValuable = OriginalCopyLocationValue{}

type OriginalCopyLocationValue struct {
	BucketName               basetypes.StringValue `tfsdk:"bucket_name"`
	CustomLocation           basetypes.StringValue `tfsdk:"custom_location"`
	Region                   basetypes.StringValue `tfsdk:"region"`
	OriginalCopyLocationType basetypes.StringValue `tfsdk:"type"`
	state                    attr.ValueState
}

var _ basetypes.ObjectTypable = OriginalCopyProtocolType{}

type OriginalCopyProtocolType struct {
	basetypes.ObjectType
}

func (t OriginalCopyProtocolType) Equal(o attr.Type) bool {
	other, ok := o.(OriginalCopyProtocolType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t OriginalCopyProtocolType) String() string {
	return "OriginalCopyProtocolType"
}

func (t OriginalCopyProtocolType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	portAttribute, ok := attributes["port"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`port is missing from object`)

		return nil, diags
	}

	portVal, ok := portAttribute.(basetypes.Int64Value)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`port expected to be basetypes.Int64Value, was: %T`, portAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return nil, diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return OriginalCopyProtocolValue{
		Port:                     portVal,
		OriginalCopyProtocolType: typeVal,
		state:                    attr.ValueStateKnown,
	}, diags
}

func NewOriginalCopyProtocolValueNull() OriginalCopyProtocolValue {
	return OriginalCopyProtocolValue{
		state: attr.ValueStateNull,
	}
}

func NewOriginalCopyProtocolValueUnknown() OriginalCopyProtocolValue {
	return OriginalCopyProtocolValue{
		state: attr.ValueStateUnknown,
	}
}

func NewOriginalCopyProtocolValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (OriginalCopyProtocolValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing OriginalCopyProtocolValue Attribute Value",
				"While creating a OriginalCopyProtocolValue value, a missing attribute value was detected. "+
					"A OriginalCopyProtocolValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("OriginalCopyProtocolValue Attribute Name (%s) Expected Type: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid OriginalCopyProtocolValue Attribute Type",
				"While creating a OriginalCopyProtocolValue value, an invalid attribute value was detected. "+
					"A OriginalCopyProtocolValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("OriginalCopyProtocolValue Attribute Name (%s) Expected Type: %s\n", name, attributeType.String())+
					fmt.Sprintf("OriginalCopyProtocolValue Attribute Name (%s) Given Type: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra OriginalCopyProtocolValue Attribute Value",
				"While creating a OriginalCopyProtocolValue value, an extra attribute value was detected. "+
					"A OriginalCopyProtocolValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra OriginalCopyProtocolValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewOriginalCopyProtocolValueUnknown(), diags
	}

	portAttribute, ok := attributes["port"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`port is missing from object`)

		return NewOriginalCopyProtocolValueUnknown(), diags
	}

	portVal, ok := portAttribute.(basetypes.Int64Value)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`port expected to be basetypes.Int64Value, was: %T`, portAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return NewOriginalCopyProtocolValueUnknown(), diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong Type",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return NewOriginalCopyProtocolValueUnknown(), diags
	}

	return OriginalCopyProtocolValue{
		Port:                     portVal,
		OriginalCopyProtocolType: typeVal,
		state:                    attr.ValueStateKnown,
	}, diags
}

func NewOriginalCopyProtocolValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) OriginalCopyProtocolValue {
	object, diags := NewOriginalCopyProtocolValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewOriginalCopyProtocolValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t OriginalCopyProtocolType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewOriginalCopyProtocolValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewOriginalCopyProtocolValueUnknown(), nil
	}

	if in.IsNull() {
		return NewOriginalCopyProtocolValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewOriginalCopyProtocolValueMust(OriginalCopyProtocolValue{}.AttributeTypes(ctx), attributes), nil
}

func (t OriginalCopyProtocolType) ValueType(ctx context.Context) attr.Value {
	return OriginalCopyProtocolValue{}
}

var _ basetypes.ObjectValuable = OriginalCopyProtocolValue{}

type OriginalCopyProtocolValue struct {
	Port                     basetypes.Int64Value  `tfsdk:"port"`
	OriginalCopyProtocolType basetypes.StringValue `tfsdk:"type"`
	state                    attr.ValueState
}

func (v OriginalCopyProtocolValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 2)

	var val tftypes.Value
	var err error

	attrTypes["port"] = basetypes.Int64Type{}.TerraformType(ctx)
	attrTypes["type"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 2)

		val, err = v.Port.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["port"] = val

		val, err = v.OriginalCopyProtocolType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["type"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v OriginalCopyProtocolValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v OriginalCopyProtocolValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v OriginalCopyProtocolValue) String() string {
	return "OriginalCopyProtocolValue"
}

func (v OriginalCopyProtocolValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributeTypes := map[string]attr.Type{
		"port": basetypes.Int64Type{},
		"type": basetypes.StringType{},
	}

	if v.IsNull() {
		return types.ObjectNull(attributeTypes), diags
	}

	if v.IsUnknown() {
		return types.ObjectUnknown(attributeTypes), diags
	}

	objVal, diags := types.ObjectValue(
		attributeTypes,
		map[string]attr.Value{
			"port": v.Port,
			"type": v.OriginalCopyProtocolType,
		})

	return objVal, diags
}

func (v OriginalCopyProtocolValue) Equal(o attr.Value) bool {
	other, ok := o.(OriginalCopyProtocolValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Port.Equal(other.Port) {
		return false
	}

	if !v.OriginalCopyProtocolType.Equal(other.OriginalCopyProtocolType) {
		return false
	}

	return true
}

func (v OriginalCopyProtocolValue) Type(ctx context.Context) attr.Type {
	return OriginalCopyProtocolType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v OriginalCopyProtocolValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"port": basetypes.Int64Type{},
		"type": basetypes.StringType{},
	}
}
