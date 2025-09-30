package compartment

import (
	"reflect"
	"testing"

	domain "github.com/cnopslabs/ocloud/internal/domain/identity"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

func strId(s string) *string { return &s }

func TestToDomainModel_Compartment(t *testing.T) {
	ad := &Adapter{}
	oci := identity.Compartment{
		Id:             strId("ocid1.compartment.oc1..abc"),
		Name:           strId("dev"),
		Description:    strId("development"),
		LifecycleState: identity.CompartmentLifecycleStateActive,
		FreeformTags:   map[string]string{"env": "dev"},
		DefinedTags:    map[string]map[string]interface{}{"ns": {"k": "v"}},
	}
	d := ad.toDomainModel(oci)
	expect := domain.Compartment{
		OCID:           "ocid1.compartment.oc1..abc",
		DisplayName:    "dev",
		Description:    "development",
		LifecycleState: string(identity.CompartmentLifecycleStateActive),
		FreeformTags:   map[string]string{"env": "dev"},
		DefinedTags:    map[string]map[string]interface{}{"ns": {"k": "v"}},
	}
	if !reflect.DeepEqual(d, expect) {
		t.Fatalf("toDomainModel(compartment) mismatch: got %#v want %#v", d, expect)
	}
}
