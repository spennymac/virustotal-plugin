package policy

import (
	"errors"
	"path/filepath"
	"strings"
)

// Permission is a Type to describe a operation that is allowed by a authentication token
type Permission string

func (p Permission) String() string {
	s := string(p)
	return s
}

//Grant returns whether the given url path is granted permission
func (p Permission) Grant(urlpath string) bool {

	urlpath = strings.TrimSuffix(urlpath, "/")
	match, err := filepath.Match(p.String(), urlpath)
	if err != nil {
		return false
	}
	if !match {
		return false
	}
	return true
}

//NormalizePermissionPolicyFromMap normalizes and checks to make sure the given map contains a valid permission policy
func NormalizePermissionPolicyFromMap(json map[string]interface{}) error {

	v, ok := json["permissions"]
	if !ok {
		return ErrFailedToValidate
	}

	p, ok := v.([]interface{})
	if !ok {
		return ErrFailedToValidate
	}

	for i := 0; i < len(p); i++ {
		st, ok := p[i].(string)
		if !ok {
			return ErrFailedToValidate
		}

		//Place prefix for them if they forgot
		if !strings.HasPrefix(st, "/") {
			st = "/" + st
		}
		//remove trailing slash if needed
		st = strings.TrimSuffix(st, "/")
		norm := Permission(strings.ToLower(st))
		if !IsValidPermission(norm) {
			return ErrFailedToValidate
		}

		// Save normalized value
		p[i] = norm
	}

	return nil

}

var (
	//ErrNoPermission error used when the token is unauthorized due to missing permission
	ErrNoPermission = errors.New("no permission")
	//PermFileAll allow all file operations
	PermFileAll = Permission("/file/*")
	//PermFileScan allow file scan operation
	PermFileScan = Permission("/file/scan")
	//PermFileDownload allow file download operation
	PermFileDownload = Permission("/file/download")
	//PermTokenAll allow all token operations
	PermTokenAll = Permission("/token/*")
	//PermTokenCreate allow token create operation
	PermTokenCreate = Permission("/token/create")
	//PermTokenDelete allow token delete operation
	PermTokenDelete = Permission("/token/delete")
)

var (
	validPermissions = map[Permission]struct{}{
		PermFileAll:      {},
		PermFileScan:     {},
		PermFileDownload: {},
		PermTokenAll:     {},
		PermTokenCreate:  {},
		PermTokenDelete:  {},
	}
)

//IsValidPermission returns whether the given permission is valid
func IsValidPermission(p Permission) bool {
	_, ok := validPermissions[p]
	return ok
}

func normalizeAndValidatePermission(r *Rule) error {
	if r.Type != PermissionRuleType {
		return ErrFailedToValidate
	}

	if r.Configuration == nil || len(r.Configuration) == 0 {
		return ErrFailedToValidate
	}

	err := NormalizePermissionPolicyFromMap(r.Configuration)
	if err != nil {
		return ErrFailedToValidate
	}

	return nil
}
