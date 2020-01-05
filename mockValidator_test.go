//Package validator ...
package validator

import (
	"fmt"
	"net/http"
	"testing"
)

func TestMockOauthClient_Authorize(t *testing.T) {
	var oc MockOauthClient
	oc.MockValidate = true

	c := oc.GetNewClient()

	r, _ := http.NewRequest("GET", "/testurl", nil)

	var cl Claim
	cl.Role = "superAdmin"
	cl.URL = "/ulbora/rs/client/update"

	var vurl = "http://localhost:3000/rs/token/validate"

	suc := c.Authorize(r, &cl, vurl)
	fmt.Println("suc", suc)
	if !suc {
		t.Fail()
	}
}
