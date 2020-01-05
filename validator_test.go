//Package validator ...
package validator

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	//m "github.com/Ulbora/GoAuth2/managers"
	gp "github.com/Ulbora/GoProxy"
	cp "github.com/Ulbora/JwtCompression"
)

func TestOauthClient_Validate(t *testing.T) {
	var vurl = "http://localhost:3000/rs/token/validate"
	var o OauthClient
	var proxy gp.MockGoProxy
	proxy.MockDoSuccess1 = true
	proxy.MockRespCode = 200
	var res http.Response
	res.Body = ioutil.NopCloser(bytes.NewBufferString(`{"valid":true}`))
	proxy.MockResp = &res
	o.Proxy = proxy.GetNewProxy()

	var vr TokenRequest
	vr.AccessToken = "eNrEmN9vozgQx/+jFYFkKx6bHzj2gXNAMOC3YNoEMGm0bADz15+c0lN0ukrF0brvgz3zmfnOjHkR6JQBVuwKBKMBznABG3gOFmwFf8LqkpAVsn+8COSnCW8y06lgeXmCNR+YkAZ56yfEOKxh4a7QkMdQHlRmgPPsHLymFuIUkGsO+CnbetLmlMe+tNlmhjPLwVG4NW6zEDawJnN5qbePrN0amnjv91h0xSF2DFi+9XjP5l6Z9rv1xnoNuyIH9i8aL6KXZMlh+VakMS5pggdYdEVq9hcaL4xQ3lVuOneFzqx2rrkMqsbNISbX3LFLVpNK2h1ip2FCBo7aDBASVXyA5SV7EWg9xhJmZs/D6Hae2K26IqrthobwJzzjGQNE+HHw+xDPZYwf3ywz0Le5SSpCEBq/NXbrqIHV6MPGaTJgWzQOSFRVxa6AbR73RWahk2uhwTVHu5U9YyA45SC6Px8FN15L2902hT/GfPMr4hvJzCuPDeQypkgyH/JkyVnlVFnMr5LTxzd+3DeZlXPqkDAcv8VrZn0Wi+TtWqRJa1ukoS2YsGfMJMK1ME8TVB5W8C7G0Zet0fwZnqkKz4HGjkjNo06e8wk8Rw35LQWkoUnA788fY+9ew/7p39idW+2OMUB5142xPJtZpKMJWlIwu2QF/IQXH7/151J3/xuLzE9hzzKAWlZvWnb22g+tuaZTUY15x0P19bxbZKAJbKlJDJ0cvZUKx/7CLF9jXR7n03VOOgocg4Y6db6Znu9v0I5XTM/5jQl556FbR7u1N5lrGgeVRqYWVtDRnZ04fLD9lrr1p8+nOztW8/1Nz4V9okBnX2AzpXk1vccu7msj/SrXPZzO9f1ewupKtTeo+Drz1kyhBnKRxguDbHlHQ7s5JFgT10qRa9RmgA/51N4V3mmr/mptVsP02gy2tzeAEywYiFR6mGLun9X2fVNxFqjw3D8r7KZBSOPgwmpS5rLHaq1RX6VGOQVc0BgbJEEXjWx7lT6aJ1j2fMV3SnXf909fm7NRJ+N7aM6GdkXjnk9/pyr526vs1++71s1XhXmqxlVlJ/wPV23awsOE97Slue/vNwpaurPTq/vhAd0r/u9RqU9/gRV0H1jolJ2D2/831wx4Bsj0vVpp9h8XE7gKeZ/am1qxJym9/0h1SBBPreAbdlNfed/T6Kex26cP7FE517SXdg9oXufs7FQ0fzc7Ne56TCXvIwf7TBNfSw/1VHlq3EPw43uI1rm0Wz3s76f5TxLjBxLJ32+46dwALP4SmIT+s4fn7fHp9xXsr/WxCUmf/poVLvD/CQAA//873Vmo"
	//vr.UserID = "userID"
	vr.ClientID = 10
	vr.Role = "superAdmin"
	vr.URI = "/ulbora/rs/client/update"
	//vr.Scope = "read"

	valid := o.validateAccessToken(&vr, vurl)
	if !valid {
		t.Fail()
	}
}

func TestOauthClient_Authorize(t *testing.T) {

	var oc OauthClient
	var vurl = "http://localhost:3000/rs/token/validate"

	var proxy gp.MockGoProxy
	proxy.MockDoSuccess1 = true
	proxy.MockRespCode = 200
	var res http.Response
	res.Body = ioutil.NopCloser(bytes.NewBufferString(`{"valid":true}`))
	proxy.MockResp = &res
	oc.Proxy = proxy.GetNewProxy()
	c := oc.GetNewClient()

	var cl Claim
	cl.Role = "superAdmin"
	cl.URL = "/ulbora/rs/client/update"
	//cl.Scope = "web"
	var token = "eNrEmN9vozgQx/+jFYFkKx6bHzj2gXNAMOC3YNoEMGm0bADz15+c0lN0ukrF0brvgz3zmfnOjHkR6JQBVuwKBKMBznABG3gOFmwFf8LqkpAVsn+8COSnCW8y06lgeXmCNR+YkAZ56yfEOKxh4a7QkMdQHlRmgPPsHLymFuIUkGsO+CnbetLmlMe+tNlmhjPLwVG4NW6zEDawJnN5qbePrN0amnjv91h0xSF2DFi+9XjP5l6Z9rv1xnoNuyIH9i8aL6KXZMlh+VakMS5pggdYdEVq9hcaL4xQ3lVuOneFzqx2rrkMqsbNISbX3LFLVpNK2h1ip2FCBo7aDBASVXyA5SV7EWg9xhJmZs/D6Hae2K26IqrthobwJzzjGQNE+HHw+xDPZYwf3ywz0Le5SSpCEBq/NXbrqIHV6MPGaTJgWzQOSFRVxa6AbR73RWahk2uhwTVHu5U9YyA45SC6Px8FN15L2902hT/GfPMr4hvJzCuPDeQypkgyH/JkyVnlVFnMr5LTxzd+3DeZlXPqkDAcv8VrZn0Wi+TtWqRJa1ukoS2YsGfMJMK1ME8TVB5W8C7G0Zet0fwZnqkKz4HGjkjNo06e8wk8Rw35LQWkoUnA788fY+9ew/7p39idW+2OMUB5142xPJtZpKMJWlIwu2QF/IQXH7/151J3/xuLzE9hzzKAWlZvWnb22g+tuaZTUY15x0P19bxbZKAJbKlJDJ0cvZUKx/7CLF9jXR7n03VOOgocg4Y6db6Znu9v0I5XTM/5jQl556FbR7u1N5lrGgeVRqYWVtDRnZ04fLD9lrr1p8+nOztW8/1Nz4V9okBnX2AzpXk1vccu7msj/SrXPZzO9f1ewupKtTeo+Drz1kyhBnKRxguDbHlHQ7s5JFgT10qRa9RmgA/51N4V3mmr/mptVsP02gy2tzeAEywYiFR6mGLun9X2fVNxFqjw3D8r7KZBSOPgwmpS5rLHaq1RX6VGOQVc0BgbJEEXjWx7lT6aJ1j2fMV3SnXf909fm7NRJ+N7aM6GdkXjnk9/pyr526vs1++71s1XhXmqxlVlJ/wPV23awsOE97Slue/vNwpaurPTq/vhAd0r/u9RqU9/gRV0H1jolJ2D2/831wx4Bsj0vVpp9h8XE7gKeZ/am1qxJym9/0h1SBBPreAbdlNfed/T6Kex26cP7FE517SXdg9oXufs7FQ0fzc7Ne56TCXvIwf7TBNfSw/1VHlq3EPw43uI1rm0Wz3s76f5TxLjBxLJ32+46dwALP4SmIT+s4fn7fHp9xXsr/WxCUmf/poVLvD/CQAA//873Vmo"
	fmt.Println("len of token: ", len(token))
	var jc cp.JwtCompress
	tkn := jc.CompressJwt(token)
	fmt.Println("tkn", tkn)
	fmt.Println("len of compressed token: ", len(tkn))
	r, _ := http.NewRequest("GET", "/testurl", nil)
	r.Header.Set("Authorization", "Bearer "+tkn)
	r.Header.Set("clientId", "10")
	//r.Header.Set("userId", "lfo")

	suc := c.Authorize(r, &cl, vurl)
	fmt.Println("suc", suc)
	if !suc {
		t.Fail()
	}
}
