package utils

import (
	"fmt"
	"reflect"
	"strings"
)

func GenerateConverter_core(sdkStruct, tfStruct interface{}) {
	var template string

	sdkElem := reflect.TypeOf(sdkStruct).Elem()
	tfElem := reflect.TypeOf(tfStruct).Elem()
	fieldNum := sdkElem.NumField()

	for i := 0; i < fieldNum; i++ {
		v := sdkElem.Field(i).Type
		if t, ok := tfElem.FieldByName(sdkElem.Field(i).Name); ok {
			var innerTemplate string
			if v.Kind() == reflect.Struct {
				for j := 0; j < v.NumField(); j++ {
					structInnerTemplate := recursiveTypeChecker(v.Field(j).Type, "input."+t.Name+v.Name(), strings.Split(v.Field(j).Tag.Get("json"), ",")[0])
					innerTemplate = innerTemplate + fmt.Sprintf(`
					%[1]s: diagOff(types.ObjectValueFrom, ctx, types.ObjectType{AttrTypes: map[string]attr.Type{
						%[3]s			
					}}.AttributeTypes(), %[2]s.%[1]s),`, v.Elem().Field(j).Name, "input."+t.Name+v.Elem().Name(), structInnerTemplate) + "\n"
				}
			} else if v.Kind() == reflect.Ptr {
				for j := 0; j < v.Elem().NumField(); j++ {
					switch v.Elem().Field(j).Type.String() {
					case "string":
						innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: types.StringValue(%[2]s),`, v.Elem().Field(j).Name, "input."+t.Name+"."+v.Elem().Field(j).Name) + "\n"
					case "[]string":
						innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: diagOff(types.ListValueFrom, ctx, types.ListType{ElemType: types.StringType}.ElementType(), %[2]s),`, v.Elem().Field(j).Name, "input."+t.Name+"."+v.Elem().Field(j).Name) + "\n"
					case "bool":
						innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: types.BoolValue(%[2]s),`, v.Elem().Field(j).Name, "input."+t.Name+"."+v.Elem().Field(j).Name) + "\n"
					case "[]bool":
						innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: diagOff(types.ListValueFrom, ctx, types.ListType{ElemType: types.BoolType}.ElementType(), %[2]s),`, v.Elem().Field(j).Name, "input."+t.Name+"."+v.Elem().Field(j).Name) + "\n"
					case "int32":
						innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: types.Int32Value(%[2]s),`, v.Elem().Field(j).Name, "input."+t.Name+"."+v.Elem().Field(j).Name) + "\n"
					case "[]int32":
						innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: diagOff(types.ListValueFrom, ctx, types.ListType{ElemType: types.Int32Type}.ElementType(), %[2]s),`, v.Elem().Field(j).Name, "input."+t.Name+"."+v.Elem().Field(j).Name) + "\n"
					case "int64":
						innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: types.Int64Value(%[2]s),`, v.Elem().Field(j).Name, "input."+t.Name+"."+v.Elem().Field(j).Name) + "\n"
					case "[]int64":
						innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: diagOff(types.ListValueFrom, ctx, types.ListType{ElemType: types.Int64Type}.ElementType(), %[2]s),`, v.Elem().Field(j).Name, "input."+t.Name+"."+v.Elem().Field(j).Name) + "\n"
					default:
						structInnerTemplate := recursiveTypeChecker(v.Elem().Field(j).Type, "input."+t.Name+v.Name(), strings.Split(v.Elem().Field(j).Tag.Get("json"), ",")[0])
						innerTemplate = innerTemplate + fmt.Sprintf(`
						%[1]s: diagOff(types.ObjectValueFrom, ctx, types.ObjectType{AttrTypes: map[string]attr.Type{
							%[3]s			
						}}.AttributeTypes(), %[2]s.%[1]s),`, v.Elem().Field(j).Name, "input."+t.Name, structInnerTemplate) + "\n"
					}
				}
			} else if v.Kind() == reflect.Array || v.Kind() == reflect.Slice {
				var structInnerTemplate string
				for j := 0; j < v.Elem().NumField(); j++ {
					switch v.Elem().Field(j).Type.String() {
					case "string":
						innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: types.StringValue(%[2]s),`, v.Elem().Field(j).Name, "input."+t.Name+"."+v.Elem().Field(j).Name) + "\n"
					case "[]string":
						innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: diagOff(types.ListValueFrom, ctx, types.ListType{ElemType: types.StringType}.ElementType(), %[2]s),`, v.Elem().Field(j).Name, "input."+t.Name+"."+v.Elem().Field(j).Name) + "\n"
					case "bool":
						innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: types.BoolValue(%[2]s),`, v.Elem().Field(j).Name, "input."+t.Name+"."+v.Elem().Field(j).Name) + "\n"
					case "[]bool":
						innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: diagOff(types.ListValueFrom, ctx, types.ListType{ElemType: types.BoolType}.ElementType(), %[2]s),`, v.Elem().Field(j).Name, "input."+t.Name+"."+v.Elem().Field(j).Name) + "\n"
					case "int32":
						innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: types.Int32Value(%[2]s),`, v.Elem().Field(j).Name, "input."+t.Name+"."+v.Elem().Field(j).Name) + "\n"
					case "[]int32":
						innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: diagOff(types.ListValueFrom, ctx, types.ListType{ElemType: types.Int32Type}.ElementType(), %[2]s),`, v.Elem().Field(j).Name, "input."+t.Name+"."+v.Elem().Field(j).Name) + "\n"
					case "int64":
						innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: types.Int64Value(%[2]s),`, v.Elem().Field(j).Name, "input."+t.Name+"."+v.Elem().Field(j).Name) + "\n"
					case "[]int64":
						innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: diagOff(types.ListValueFrom, ctx, types.ListType{ElemType: types.Int64Type}.ElementType(), %[2]s),`, v.Elem().Field(j).Name, "input."+t.Name+"."+v.Elem().Field(j).Name) + "\n"
					default:
						structInnerTemplate = structInnerTemplate + recursiveTypeChecker(v.Elem().Field(j).Type, "input."+t.Name+v.Name(), strings.Split(v.Elem().Field(j).Tag.Get("json"), ",")[0])
						innerTemplate = innerTemplate + fmt.Sprintf(`
						%[1]s: diagOff(types.ListValueFrom, ctx, types.ObjectType{AttrTypes: map[string]attr.Type{
							%[3]s			
						}}.AttributeTypes(), %[2]s.%[1]s),`, v.Elem().Field(j).Name, "input."+t.Name, structInnerTemplate) + "\n"
					}
				}
			} else if v.Kind() == reflect.String {
				innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: types.StringValue(%[2]s),`, v.Name(), "input."+t.Name+v.Name()) + "\n"
			} else if v.Kind() == reflect.Bool {
				innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: types.BoolValue(%[2]s),`, v.Name(), "input."+t.Name+v.Name()) + "\n"
			} else if v.Kind() == reflect.Int64 {
				innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: types.Int64Value(%[2]s),`, v.Name(), "input."+t.Name+v.Name()) + "\n"
			} else if v.Kind() == reflect.Int32 {
				innerTemplate = innerTemplate + fmt.Sprintf(`%[1]s: types.Int32Value(%[2]s),`, v.Name(), "input."+t.Name+v.Name()) + "\n"
			}

			template = template + fmt.Sprintf(`
				target.%[1]s = %[2]s{
					%[3]s
				}`, t.Name, strings.Split(t.Type.String(), ".")[1], innerTemplate)
		}
	}

	fmt.Println(template)

	// data := struct {
	// 	ResourceName string
	// 	DtoName      string
	// 	Inner        string
	// }{
	// 	ResourceName: resourceName,
	// 	DtoName:      dtoName,
	// 	Inner:        template,
	// }
}

func recursiveTypeChecker(r reflect.Type, latestName string, jsonTag string) string {

	switch r.String() {
	case "string":
		return fmt.Sprintf(`"%[1]s": types.StringType,`, jsonTag) + "\n"
	case "[]string":
		return fmt.Sprintf(`"%[1]s": types.ListType{ElemType: types.StringType1},`, jsonTag) + "\n"
	case "int64":
		return fmt.Sprintf(`"%[1]s": types.Int64Type,`, jsonTag) + "\n"
	case "[]int64":
		return fmt.Sprintf(`"%[1]s": types.ListType{ElemType: types.Int64Type},`, jsonTag) + "\n"
	case "int32":
		return fmt.Sprintf(`"%[1]s": types.Int32Type,`, jsonTag) + "\n"
	case "[]int32":
		return fmt.Sprintf(`"%[1]s": types.ListType{ElemType: types.Int32Type},`, jsonTag) + "\n"
	case "bool":
		return fmt.Sprintf(`"%[1]s": types.BoolType1,`, jsonTag) + "\n"
	case "[]bool":
		return fmt.Sprintf(`"%[1]s": types.ListType{ElemType: types.BoolType},`, jsonTag) + "\n"
	case "time.Time":
		return fmt.Sprintf(`"%[1]s": types.StringType,`, jsonTag) + "\n"
	}

	var baseTemplate string

	for i := 0; i < r.Elem().NumField(); i++ {
		var t reflect.StructField
		if r.Kind() == reflect.Ptr {
			t = r.Elem().Field(i)
		} else if r.Kind() == reflect.Slice {
			t = r.Elem().Field(i)
		} else {
			t = r.Field(i)
		}

		tag := strings.Split(t.Tag.Get("json"), ",")[0] // bypassQueryString

		// case like []HeaderPolicy
		if r.Kind() == reflect.Slice || r.Kind() == reflect.Array {
			innerTemplate := recursiveTypeChecker(t.Type, latestName+"."+t.Name, tag)
			baseTemplate = baseTemplate + fmt.Sprintf(`
						%[1]s: diagOff(types.ListValueFrom, ctx, types.ListType{ElemType: types.ObjectType{AttrTypes: map[string]attr.Type{
							%[3]s
						}}}.ElementType(), %[2]s.%[1]s)`, t.Name, latestName, innerTemplate) + "\n"
		} else if r.Kind() == reflect.Struct || r.Kind() == reflect.Ptr {
			switch t.Type.String() {
			case "string":
				baseTemplate = baseTemplate + fmt.Sprintf(`"%[1]s": types.StringType,`, tag) + "\n"
			case "[]string":
				baseTemplate = baseTemplate + fmt.Sprintf(`"%[1]s": types.ListType{ElemType: types.StringType},`, tag) + "\n"
			case "int64":
				baseTemplate = baseTemplate + fmt.Sprintf(`"%[1]s": types.Int64Type,`, tag) + "\n"
			case "[]int64":
				baseTemplate = baseTemplate + fmt.Sprintf(`"%[1]s": types.ListType{ElemType: types.Int64Type},`, tag) + "\n"
			case "int32":
				baseTemplate = baseTemplate + fmt.Sprintf(`"%[1]s": types.Int32Type,`, tag) + "\n"
			case "[]int32":
				baseTemplate = baseTemplate + fmt.Sprintf(`"%[1]s": types.ListType{ElemType: types.Int32Type},`, tag) + "\n"
			case "bool":
				baseTemplate = baseTemplate + fmt.Sprintf(`"%[1]s": types.BoolType222,`, tag) + "\n"
			case "[]bool":
				baseTemplate = baseTemplate + fmt.Sprintf(`"%[1]s": types.ListType{ElemType: types.BoolType},`, tag) + "\n"
			case "time.Time":
				baseTemplate = baseTemplate + fmt.Sprintf(`"%[1]s": types.StringType,`, tag) + "\n"
			default:
				// check whether the type is object
				innerTemplate := recursiveTypeChecker(t.Type, latestName+"."+t.Name, tag)
				baseTemplate = baseTemplate + fmt.Sprintf(`
				%[1]s: diagOff(types.ObjectValueFrom, ctx, types.ObjectType{AttrTypes: map[string]attr.Type{
					%[3]s			
				}}.AttributeTypes(), %[2]s.%[1]s),`, t.Name, latestName, innerTemplate) + "\n"
			}

		}
	}
	return baseTemplate
}
