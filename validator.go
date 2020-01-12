//Package validator ...
package validator

/*
   Copyright (C) 2019 Ulbora Labs LLC. (www.ulboralabs.com)
   All rights reserved.

   Copyright (C) 2019 Ken Williamson
   All rights reserved.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	gp "github.com/Ulbora/GoProxy"
)

const (
	tokenValidationServiceLocal = "http://localhost:3000/rs/token/validate"
)

//Claim Claim
type Claim struct {
	Role  string
	URL   string
	Scope string
}

//Client Client
type Client interface {
	Authorize(r *http.Request, c *Claim, vURL string) bool
}

//OauthClient OauthClient
type OauthClient struct {
	Proxy gp.Proxy
	//TokenCompressed bool
	//JwtCompress cp.JwtCompress
}

//TokenRequest TokenRequest
type TokenRequest struct {
	AccessToken string `json:"accessToken"`
	UserID      string `json:"userId"`
	ClientID    int64  `json:"clientId"`
	Role        string `json:"role"`
	URI         string `json:"url"`
	Scope       string `json:"scope"`
}

//TokenResponse TokenResponse
type TokenResponse struct {
	Valid bool `json:"valid"`
}

//Authorize Authorize
func (o *OauthClient) Authorize(r *http.Request, c *Claim, vURL string) bool {
	var rtn bool
	tokenHeader := r.Header.Get("Authorization")
	clientIDStr := r.Header.Get("clientId")
	clientID, _ := strconv.ParseInt(clientIDStr, 10, 64)
	userID := r.Header.Get("userId")
	// fmt.Println("clientIDStr", clientIDStr)
	// fmt.Println("clientID", clientID)
	// fmt.Println("userID", userID)
	if tokenHeader != "" {
		tokenArray := strings.Split(tokenHeader, " ")
		//fmt.Println("tokenArray", tokenArray)
		if len(tokenArray) == 2 {
			var token string
			token = tokenArray[1]
			//fmt.Println("token:", token)
			var vr TokenRequest
			vr.AccessToken = token
			vr.UserID = userID
			vr.ClientID = clientID
			vr.Role = c.Role
			vr.URI = c.URL
			vr.Scope = c.Scope
			rtn = o.validateAccessToken(&vr, vURL)
			//fmt.Println("valid: ", rtn)
		}
	}
	return rtn
}

func (o *OauthClient) validateAccessToken(vr *TokenRequest, vURL string) bool {
	var rtn bool
	aJSON, err := json.Marshal(vr)
	if err == nil {
		req, rErr := http.NewRequest("POST", vURL, bytes.NewBuffer(aJSON))
		if rErr == nil {
			req.Header.Set("Content-Type", "application/json")
			var res TokenResponse
			suc, stat := o.Proxy.Do(req, &res)
			// fmt.Println("suc: ", suc)
			// fmt.Println("stat: ", stat)
			// fmt.Println("uRes: ", res)
			if suc && stat == 200 && res.Valid {
				rtn = true
			}
		}
	}
	return rtn
}

//GetNewClient GetNewClient
func (o *OauthClient) GetNewClient() Client {
	var proxy gp.GoProxy
	o.Proxy = &proxy
	var c Client
	c = o
	return c
}

//go mod init github.com/Ulbora/GoAuth2JwtValidator
