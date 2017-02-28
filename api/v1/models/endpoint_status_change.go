package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"

	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// EndpointStatusChange Indication of a change of status
// swagger:model EndpointStatusChange
type EndpointStatusChange struct {

	// Code indicate type of status change
	Code string `json:"code,omitempty"`

	// Status message
	Message string `json:"message,omitempty"`

	// Timestamp when status change occured
	Timestamp string `json:"timestamp,omitempty"`
}

// Validate validates this endpoint status change
func (m *EndpointStatusChange) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCode(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var endpointStatusChangeTypeCodePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["ok","failed"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		endpointStatusChangeTypeCodePropEnum = append(endpointStatusChangeTypeCodePropEnum, v)
	}
}

const (
	// EndpointStatusChangeCodeOk captures enum value "ok"
	EndpointStatusChangeCodeOk string = "ok"
	// EndpointStatusChangeCodeFailed captures enum value "failed"
	EndpointStatusChangeCodeFailed string = "failed"
)

// prop value enum
func (m *EndpointStatusChange) validateCodeEnum(path, location string, value string) error {
	if err := validate.Enum(path, location, value, endpointStatusChangeTypeCodePropEnum); err != nil {
		return err
	}
	return nil
}

func (m *EndpointStatusChange) validateCode(formats strfmt.Registry) error {

	if swag.IsZero(m.Code) { // not required
		return nil
	}

	// value enum
	if err := m.validateCodeEnum("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}